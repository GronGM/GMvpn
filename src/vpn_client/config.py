from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from vpn_client.models import DnsMode, Endpoint, Manifest, NetworkPolicy, TransportPolicy, TunnelMode
from vpn_client.policy import validate_incident_guidance_overrides
from vpn_client.security import Ed25519Verifier


class ManifestError(Exception):
    """Raised when manifest loading fails."""


def canonical_manifest_bytes(data: dict) -> bytes:
    payload = {key: value for key, value in data.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_from_dict(data: dict) -> Manifest:
    endpoints = [Endpoint(**endpoint) for endpoint in data["endpoints"]]
    policy = TransportPolicy(**data["transport_policy"])
    network_policy_raw = data.get("network_policy", {})
    network_policy = NetworkPolicy(
        tunnel_mode=TunnelMode(network_policy_raw.get("tunnel_mode", TunnelMode.FULL)),
        dns_mode=DnsMode(network_policy_raw.get("dns_mode", DnsMode.VPN_ONLY)),
        kill_switch_enabled=network_policy_raw.get("kill_switch_enabled", True),
        ipv6_enabled=network_policy_raw.get("ipv6_enabled", False),
        allow_lan_while_connected=network_policy_raw.get("allow_lan_while_connected", False),
    )
    return Manifest(
        version=data["version"],
        generated_at=data["generated_at"],
        expires_at=data["expires_at"],
        endpoints=endpoints,
        transport_policy=policy,
        network_policy=network_policy,
        features=data.get("features", {}),
    )


def _parse_utc_timestamp(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_manifest(manifest: Manifest) -> None:
    if manifest.version < 1:
        raise ManifestError("manifest version must be positive")
    if not manifest.endpoints:
        raise ManifestError("manifest must contain at least one endpoint")
    if _parse_utc_timestamp(manifest.expires_at) <= datetime.now(timezone.utc):
        raise ManifestError("manifest is expired")
    overrides = manifest.features.get("incident_guidance_overrides")
    if overrides is not None:
        try:
            validate_incident_guidance_overrides(overrides)
        except ValueError as exc:
            raise ManifestError(str(exc)) from exc


class ManifestStore:
    def __init__(self, cache_dir: Path):
        self.cache_dir = cache_dir
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def last_known_good_path(self) -> Path:
        return self.cache_dir / "last_known_good.json"

    def save_last_known_good(self, data: dict) -> None:
        self.last_known_good_path.write_text(
            json.dumps(data, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def load_last_known_good(self) -> dict | None:
        if not self.last_known_good_path.exists():
            return None
        return json.loads(self.last_known_good_path.read_text(encoding="utf-8"))


class SignedManifestLoader:
    def __init__(self, verifier: Ed25519Verifier, store: ManifestStore):
        self.verifier = verifier
        self.store = store

    def load_file(self, path: Path) -> Manifest:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return self.load_dict(raw)

    def load_dict(self, raw: dict) -> Manifest:
        signature = raw.get("signature")
        if not signature:
            raise ManifestError("manifest has no signature")

        payload = canonical_manifest_bytes(raw)
        self.verifier.verify(payload, signature)
        manifest = manifest_from_dict(raw)
        validate_manifest(manifest)
        self.store.save_last_known_good(raw)
        return manifest

    def load_with_fallback(self, path: Path) -> Manifest:
        try:
            return self.load_file(path)
        except Exception as primary_error:
            cached = self.store.load_last_known_good()
            if not cached:
                raise ManifestError(f"manifest load failed and no cached copy exists: {primary_error}") from primary_error
            return manifest_from_dict(cached)


def manifest_to_dict(manifest: Manifest) -> dict:
    data = asdict(manifest)
    return {
        "version": data["version"],
        "generated_at": data["generated_at"],
        "expires_at": data["expires_at"],
        "endpoints": data["endpoints"],
        "transport_policy": data["transport_policy"],
        "network_policy": data["network_policy"],
        "features": data["features"],
    }
