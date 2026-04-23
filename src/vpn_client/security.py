from __future__ import annotations

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SignatureVerificationError(Exception):
    """Raised when a signed manifest fails verification."""


@dataclass(slots=True)
class Ed25519Verifier:
    public_key: Ed25519PublicKey

    @classmethod
    def from_public_key_pem(cls, pem_data: bytes) -> "Ed25519Verifier":
        key = serialization.load_pem_public_key(pem_data)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("expected Ed25519 public key")
        return cls(public_key=key)

    def verify(self, payload: bytes, signature_b64: str) -> None:
        try:
            signature = base64.b64decode(signature_b64)
            self.public_key.verify(signature, payload)
        except (InvalidSignature, ValueError) as exc:
            raise SignatureVerificationError("manifest signature is invalid") from exc


def generate_keypair() -> tuple[bytes, bytes]:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def sign_payload(private_pem: bytes, payload: bytes) -> str:
    key = serialization.load_pem_private_key(private_pem, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected Ed25519 private key")
    signature = key.sign(payload)
    return base64.b64encode(signature).decode("ascii")
