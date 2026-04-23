from __future__ import annotations

from copy import deepcopy


class ProviderCompileError(Exception):
    """Raised when logical server variants cannot be compiled safely."""


def compile_logical_server_variants(server: dict[str, object]) -> list[dict[str, object]]:
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
        supported = metadata.get("supported_client_platforms")
        if supported is not None:
            if not isinstance(supported, list) or not supported:
                raise ProviderCompileError(
                    f"compiled endpoint '{endpoint_id}' has invalid supported_client_platforms"
                )
