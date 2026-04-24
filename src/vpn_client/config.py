from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from vpn_client.client_platform import ClientPlatform
from vpn_client.android_runtime import (
    AndroidRuntimeConfigError,
    endpoint_declares_android_runtime,
    validate_android_runtime_endpoint_metadata,
)
from vpn_client.desktop_policy import (
    DesktopPolicyError,
    endpoint_declares_desktop_policy,
    validate_desktop_policy_endpoint_metadata,
)
from vpn_client.models import DnsMode, Endpoint, Manifest, NetworkPolicy, PlatformCapability, TransportPolicy, TunnelMode
from vpn_client.policy import validate_incident_guidance_overrides
from vpn_client.security import Ed25519Verifier
from vpn_client.ios_bridge import (
    IOSBridgeConfigError,
    endpoint_declares_ios_bridge,
    validate_ios_bridge_endpoint_metadata,
)
from vpn_client.xray import XrayConfigError, endpoint_declares_xray, validate_xray_endpoint_metadata


class ManifestError(Exception):
    """Raised when manifest loading fails."""


MANIFEST_SCHEMA_VERSION = 1
PROVIDER_PROFILE_SCHEMA_VERSION = 1


def canonical_manifest_bytes(data: dict) -> bytes:
    payload = {key: value for key, value in data.items() if key != "signature"}
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_from_dict(data: dict) -> Manifest:
    endpoints = [Endpoint(**endpoint) for endpoint in data["endpoints"]]
    policy = TransportPolicy(**data["transport_policy"])
    platform_capabilities = {
        platform: PlatformCapability(**capability)
        for platform, capability in data.get("platform_capabilities", {}).items()
    }
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
        platform_capabilities=platform_capabilities,
        features=data.get("features", {}),
        schema_version=int(data.get("schema_version", MANIFEST_SCHEMA_VERSION)),
        provider_profile_schema_version=(
            int(data["provider_profile_schema_version"])
            if data.get("provider_profile_schema_version") is not None
            else None
        ),
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
    _validate_manifest_schema_version(manifest)
    if not manifest.endpoints:
        raise ManifestError("manifest must contain at least one endpoint")
    if _parse_utc_timestamp(manifest.expires_at) <= datetime.now(timezone.utc):
        raise ManifestError("manifest is expired")
    _validate_platform_capabilities(manifest.platform_capabilities)
    overrides = manifest.features.get("incident_guidance_overrides")
    if overrides is not None:
        try:
            validate_incident_guidance_overrides(overrides)
        except ValueError as exc:
            raise ManifestError(str(exc)) from exc
    _validate_provider_profile_contract(manifest)
    for endpoint in manifest.endpoints:
        _validate_endpoint_platform_targeting(endpoint)
        if endpoint_declares_xray(endpoint):
            try:
                validate_xray_endpoint_metadata(endpoint)
            except XrayConfigError as exc:
                raise ManifestError(str(exc)) from exc
        if endpoint_declares_android_runtime(endpoint):
            try:
                validate_android_runtime_endpoint_metadata(endpoint)
            except AndroidRuntimeConfigError as exc:
                raise ManifestError(str(exc)) from exc
        if endpoint_declares_desktop_policy(endpoint):
            try:
                validate_desktop_policy_endpoint_metadata(endpoint)
            except DesktopPolicyError as exc:
                raise ManifestError(str(exc)) from exc
        if endpoint_declares_ios_bridge(endpoint):
            try:
                validate_ios_bridge_endpoint_metadata(endpoint)
            except IOSBridgeConfigError as exc:
                raise ManifestError(str(exc)) from exc


def _validate_manifest_schema_version(manifest: Manifest) -> None:
    if manifest.schema_version < 1:
        raise ManifestError("manifest schema_version must be positive")
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION:
        raise ManifestError(
            f"unsupported manifest schema_version '{manifest.schema_version}'; supported version is '{MANIFEST_SCHEMA_VERSION}'"
        )

    profile_kind = manifest.features.get("profile_kind")
    if profile_kind == "provider-profile":
        provider_schema_version = manifest.provider_profile_schema_version or PROVIDER_PROFILE_SCHEMA_VERSION
        if provider_schema_version < 1:
            raise ManifestError("provider_profile_schema_version must be positive")
        if provider_schema_version != PROVIDER_PROFILE_SCHEMA_VERSION:
            raise ManifestError(
                "unsupported provider_profile_schema_version "
                f"'{provider_schema_version}'; supported version is '{PROVIDER_PROFILE_SCHEMA_VERSION}'"
            )
    elif manifest.provider_profile_schema_version is not None:
        raise ManifestError("provider_profile_schema_version requires features.profile_kind='provider-profile'")


def _validate_provider_profile_contract(manifest: Manifest) -> None:
    if manifest.features.get("profile_kind") != "provider-profile":
        return

    provider_schema_version = manifest.provider_profile_schema_version or PROVIDER_PROFILE_SCHEMA_VERSION
    for endpoint in manifest.endpoints:
        logical_server = endpoint.metadata.get("logical_server")
        if not isinstance(logical_server, str) or not logical_server:
            raise ManifestError(
                f"provider-profile endpoint '{endpoint.id}' is missing logical_server metadata"
            )
        endpoint_schema_version = endpoint.metadata.get("provider_profile_schema_version", provider_schema_version)
        if endpoint_schema_version != provider_schema_version:
            raise ManifestError(
                f"provider-profile endpoint '{endpoint.id}' has provider_profile_schema_version "
                f"'{endpoint_schema_version}', expected '{provider_schema_version}'"
            )


def _validate_endpoint_platform_targeting(endpoint: Endpoint) -> None:
    supported = endpoint.metadata.get("supported_client_platforms")
    if supported is None:
        return
    if not isinstance(supported, Sequence) or isinstance(supported, (str, bytes)):
        raise ManifestError(
            f"endpoint '{endpoint.id}' has invalid supported_client_platforms; expected a list of platform names"
        )
    valid_platforms = {platform.value for platform in ClientPlatform}
    for item in supported:
        if not isinstance(item, str) or item not in valid_platforms:
            raise ManifestError(
                f"endpoint '{endpoint.id}' references unsupported client platform '{item}'"
            )


def _validate_platform_capabilities(capabilities: dict[str, PlatformCapability]) -> None:
    valid_platforms = {platform.value for platform in ClientPlatform}
    valid_dataplanes = {"null", "linux-userspace", "xray-core", "ios-bridge", "routed"}
    valid_adapters = {"simulated", "linux", "windows", "macos", "android", "ios"}
    for platform_name, capability in capabilities.items():
        if platform_name not in valid_platforms:
            raise ManifestError(f"unknown platform capability '{platform_name}'")
        if capability.platform != platform_name:
            raise ManifestError(f"platform capability '{platform_name}' has mismatched platform field '{capability.platform}'")
        if not capability.supported_dataplanes:
            raise ManifestError(f"platform capability '{platform_name}' must declare at least one dataplane")
        for dataplane in capability.supported_dataplanes:
            if dataplane not in valid_dataplanes:
                raise ManifestError(
                    f"platform capability '{platform_name}' references unsupported dataplane '{dataplane}'"
                )
        if capability.network_adapter not in valid_adapters:
            raise ManifestError(
                f"platform capability '{platform_name}' references unsupported network adapter '{capability.network_adapter}'"
            )


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
        "schema_version": data["schema_version"],
        "generated_at": data["generated_at"],
        "expires_at": data["expires_at"],
        "endpoints": data["endpoints"],
        "transport_policy": data["transport_policy"],
        "network_policy": data["network_policy"],
        "platform_capabilities": data["platform_capabilities"],
        "features": data["features"],
        "provider_profile_schema_version": data["provider_profile_schema_version"],
    }
