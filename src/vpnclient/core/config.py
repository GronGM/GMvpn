from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vpnclient.core.models import Endpoint, Manifest


class ManifestError(Exception):
    pass


class ManifestSigner:
    def __init__(self, secret: bytes) -> None:
        self._secret = secret

    def sign_payload(self, payload: dict[str, Any]) -> str:
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._secret, raw, hashlib.sha256).hexdigest()

    def build_signed_document(self, manifest: Manifest) -> dict[str, Any]:
        payload = {
            "version": manifest.version,
            "expires_at": manifest.expires_at,
            "network": manifest.network,
            "features": manifest.features,
            "endpoints": [asdict(x) for x in manifest.endpoints],
        }
        return {"payload": payload, "signature": self.sign_payload(payload)}

    def verify(self, document: dict[str, Any]) -> Manifest:
        payload = document["payload"]
        signature = document["signature"]
        if not hmac.compare_digest(signature, self.sign_payload(payload)):
            raise ManifestError("invalid signature")
        endpoints = [Endpoint(**ep) for ep in payload["endpoints"]]
        manifest = Manifest(
            version=payload["version"],
            expires_at=payload["expires_at"],
            endpoints=endpoints,
            network=payload["network"],
            features=payload.get("features", {}),
        )
        if manifest.is_expired():
            raise ManifestError("manifest expired")
        return manifest


class ManifestStore:
    def __init__(self, root: Path, signer: ManifestSigner) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        self.current_file = self.root / "current.json"
        self.lkg_file = self.root / "last_known_good.json"
        self.signer = signer

    def write_current(self, document: dict[str, Any]) -> None:
        self.current_file.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def commit_last_known_good(self, document: dict[str, Any]) -> None:
        self.lkg_file.write_text(json.dumps(document, indent=2), encoding="utf-8")

    def load_verified(self) -> Manifest:
        for candidate in (self.current_file, self.lkg_file):
            if candidate.exists():
                document = json.loads(candidate.read_text(encoding="utf-8"))
                try:
                    manifest = self.signer.verify(document)
                except ManifestError:
                    continue
                if candidate == self.current_file:
                    self.commit_last_known_good(document)
                return manifest
        raise ManifestError("no valid manifest available")
