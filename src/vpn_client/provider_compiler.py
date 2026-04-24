from __future__ import annotations

from copy import deepcopy

PROVIDER_PROFILE_SCHEMA_VERSION = 1


class ProviderCompileError(Exception):
    """Raised when logical server variants cannot be compiled safely."""


def compile_logical_server_variants(
    server: dict[str, object],
    provider_profile_schema_version: int = PROVIDER_PROFILE_SCHEMA_VERSION,
) -> list[dict[str, object]]:
    _validate_provider_profile_schema_version(provider_profile_schema_version)
    logical_server = str(server["logical_server"])
    base_host = str(server["host"])
    base_port = int(server["port"])
    region = str(server["region"])
    transport = str(server.get("transport", "https"))
    variants = server.get("variants", [])
    compiled: list[dict[str, object]] = []

    for variant in variants:
        variant_name = str(variant["name"])
        metadata = deepcopy(variant.get("metadata", {}))
        metadata["logical_server"] = logical_server
        metadata["provider_profile_schema_version"] = provider_profile_schema_version
        compiled.append(
            {
                "id": f"{logical_server}-{variant_name}",
                "host": str(variant.get("host", base_host)),
                "port": int(variant.get("port", base_port)),
                "transport": str(variant.get("transport", transport)),
                "region": str(variant.get("region", region)),
                "tags": list(variant.get("tags", [])),
                "metadata": metadata,
            }
        )
    validate_compiled_variants(compiled)
    return compiled


def build_provider_profile_manifest(
    *,
    version: int,
    generated_at: str,
    expires_at: str,
    platform_capabilities: dict[str, object],
    network_policy: dict[str, object],
    transport_policy: dict[str, object],
    logical_servers: list[dict[str, object]],
    features: dict[str, object] | None = None,
    schema_version: int = 1,
    provider_profile_schema_version: int = PROVIDER_PROFILE_SCHEMA_VERSION,
) -> dict[str, object]:
    _validate_provider_profile_schema_version(provider_profile_schema_version)
    manifest_features = dict(features or {})
    manifest_features["profile_kind"] = "provider-profile"
    _validate_unique_logical_servers(logical_servers)

    endpoints: list[dict[str, object]] = []
    for server in logical_servers:
        server_schema_version = int(server.get("provider_profile_schema_version", provider_profile_schema_version))
        if server_schema_version != provider_profile_schema_version:
            raise ProviderCompileError(
                "logical server provider_profile_schema_version "
                f"'{server_schema_version}' does not match manifest provider_profile_schema_version "
                f"'{provider_profile_schema_version}'"
            )
        endpoints.extend(
            compile_logical_server_variants(
                server,
                provider_profile_schema_version=provider_profile_schema_version,
            )
        )

    return {
        "version": version,
        "schema_version": schema_version,
        "provider_profile_schema_version": provider_profile_schema_version,
        "generated_at": generated_at,
        "expires_at": expires_at,
        "platform_capabilities": platform_capabilities,
        "features": manifest_features,
        "network_policy": network_policy,
        "transport_policy": transport_policy,
        "endpoints": endpoints,
    }


def validate_compiled_variants(endpoints: list[dict[str, object]]) -> None:
    seen_ids: set[str] = set()
    for endpoint in endpoints:
        endpoint_id = str(endpoint.get("id", ""))
        if not endpoint_id:
            raise ProviderCompileError("compiled endpoint is missing id")
        if endpoint_id in seen_ids:
            raise ProviderCompileError(f"duplicate compiled endpoint id '{endpoint_id}'")
        seen_ids.add(endpoint_id)

        metadata = endpoint.get("metadata")
        if not isinstance(metadata, dict):
            raise ProviderCompileError(f"compiled endpoint '{endpoint_id}' is missing metadata")
        logical_server = metadata.get("logical_server")
        if not isinstance(logical_server, str) or not logical_server:
            raise ProviderCompileError(f"compiled endpoint '{endpoint_id}' is missing logical_server metadata")
        schema_version = metadata.get("provider_profile_schema_version")
        if not isinstance(schema_version, int) or schema_version < 1:
            raise ProviderCompileError(
                f"compiled endpoint '{endpoint_id}' has invalid provider_profile_schema_version"
            )
        supported = metadata.get("supported_client_platforms")
        if supported is not None:
            if not isinstance(supported, list) or not supported:
                raise ProviderCompileError(
                    f"compiled endpoint '{endpoint_id}' has invalid supported_client_platforms"
                )


def _validate_provider_profile_schema_version(schema_version: int) -> None:
    if schema_version < 1:
        raise ProviderCompileError("provider_profile_schema_version must be positive")
    if schema_version != PROVIDER_PROFILE_SCHEMA_VERSION:
        raise ProviderCompileError(
            "unsupported provider_profile_schema_version "
            f"'{schema_version}'; supported version is '{PROVIDER_PROFILE_SCHEMA_VERSION}'"
        )


def _validate_unique_logical_servers(logical_servers: list[dict[str, object]]) -> None:
    seen: set[str] = set()
    for server in logical_servers:
        logical_server = str(server.get("logical_server", ""))
        if not logical_server:
            raise ProviderCompileError("logical server entry is missing logical_server")
        if logical_server in seen:
            raise ProviderCompileError(f"duplicate logical_server '{logical_server}'")
        seen.add(logical_server)
