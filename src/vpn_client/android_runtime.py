from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import json

from vpn_client.models import DnsMode, Endpoint, NetworkPolicy, TunnelMode


class AndroidRuntimeConfigError(Exception):
    """Raised when Android runtime metadata is incomplete or inconsistent."""


class AndroidRuntimeState(str, Enum):
    PERMISSION_REQUIRED = "permission_required"
    SERVICE_BOUND = "service_bound"
    VPN_ESTABLISHED = "vpn_established"
    BACKEND_STARTED = "backend_started"
    RUNNING = "running"
    STOP_REQUESTED = "stop_requested"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(slots=True)
class AndroidVpnServiceConfig:
    endpoint_id: str
    session_name: str
    dataplane_backend: str
    protect_socket_api: bool
    meter_handling: str
    allow_lan: bool
    allow_bypass: bool
    dns_mode: str


@dataclass(slots=True)
class AndroidRuntimeRequest:
    schema_version: int
    request_kind: str
    session_id: str
    config: AndroidVpnServiceConfig
    remote: dict[str, object]
    routes: dict[str, object]
    dns: dict[str, object]
    lifecycle: dict[str, object]


@dataclass(slots=True)
class AndroidRuntimeStatus:
    schema_version: int
    session_id: str
    state: str
    detail: str
    vpn_prepared: bool
    backend_started: bool
    last_error: str | None = None


def android_policy(metadata: dict[str, object]) -> dict[str, object]:
    policy = metadata.get("android_policy")
    if isinstance(policy, dict):
        return policy
    return {}


def endpoint_declares_android_runtime(endpoint: Endpoint) -> bool:
    metadata = endpoint.metadata
    return "android_policy" in metadata or any(str(key).startswith("android_") for key in metadata)


def validate_android_runtime_endpoint_metadata(endpoint: Endpoint) -> None:
    metadata = endpoint.metadata
    policy = android_policy(metadata)
    dataplane = str(metadata.get("dataplane", ""))
    if dataplane and dataplane != "xray-core":
        raise AndroidRuntimeConfigError(
            f"endpoint '{endpoint.id}' uses android runtime metadata but dataplane '{dataplane}' is not supported"
        )

    session_name = policy.get("session_name", metadata.get("android_session_name"))
    if not session_name:
        raise AndroidRuntimeConfigError(f"endpoint '{endpoint.id}' is missing android_session_name")

    meter_handling = str(policy.get("meter_handling", metadata.get("android_meter_handling", "allow_metered")))
    if meter_handling not in {"allow_metered", "prefer_unmetered", "block_metered"}:
        raise AndroidRuntimeConfigError(
            f"endpoint '{endpoint.id}' uses unsupported android_meter_handling '{meter_handling}'"
        )
    rank_priority = policy.get("rank_priority", metadata.get("android_rank_priority", 100))
    if not isinstance(rank_priority, int):
        raise AndroidRuntimeConfigError(f"endpoint '{endpoint.id}' has non-integer android rank_priority")

    supported = metadata.get("supported_client_platforms")
    if supported is not None and "android" not in supported:
        raise AndroidRuntimeConfigError(
            f"endpoint '{endpoint.id}' declares android runtime metadata without android in supported_client_platforms"
        )


def build_android_runtime_request(
    endpoint: Endpoint,
    network_policy: NetworkPolicy | None = None,
) -> AndroidRuntimeRequest:
    validate_android_runtime_endpoint_metadata(endpoint)
    policy = network_policy or NetworkPolicy()
    metadata = endpoint.metadata
    runtime_policy = android_policy(metadata)
    session_name = runtime_policy.get("session_name") or metadata.get("android_session_name")
    session_id = f"android-{endpoint.id}-{endpoint.transport}"
    config = AndroidVpnServiceConfig(
        endpoint_id=endpoint.id,
        session_name=str(session_name),
        dataplane_backend=str(metadata.get("dataplane", "xray-core") or "xray-core"),
        protect_socket_api=bool(runtime_policy.get("protect_socket_api", metadata.get("android_protect_socket_api", True))),
        meter_handling=str(runtime_policy.get("meter_handling", metadata.get("android_meter_handling", "allow_metered"))),
        allow_lan=policy.allow_lan_while_connected,
        allow_bypass=bool(runtime_policy.get("allow_bypass", metadata.get("android_allow_bypass", False))),
        dns_mode=policy.dns_mode.value,
    )
    return AndroidRuntimeRequest(
        schema_version=1,
        request_kind="start_vpn_service",
        session_id=session_id,
        config=config,
        remote={
            "host": endpoint.host,
            "port": endpoint.port,
            "transport": endpoint.transport,
            "logical_server": metadata.get("logical_server"),
        },
        routes={
            "tunnel_mode": policy.tunnel_mode.value,
            "ipv6_enabled": policy.ipv6_enabled,
            "included_routes": ["0.0.0.0/0"] if policy.tunnel_mode is TunnelMode.FULL else [],
            "excluded_routes": runtime_policy.get("excluded_routes", metadata.get("android_excluded_routes", [])),
        },
        dns={
            "mode": policy.dns_mode.value,
            "servers": runtime_policy.get("dns_servers", metadata.get("android_dns_servers", [])),
            "block_system_fallback": policy.dns_mode is DnsMode.VPN_ONLY,
        },
        lifecycle={
            "on_boot_reconnect": bool(runtime_policy.get("on_boot_reconnect", metadata.get("android_on_boot_reconnect", False))),
            "respect_doze": bool(runtime_policy.get("respect_doze", metadata.get("android_respect_doze", True))),
            "reassert_on_network_change": bool(
                runtime_policy.get("reassert_on_network_change", metadata.get("android_reassert_on_network_change", True))
            ),
        },
    )


def build_initial_android_runtime_status(request: AndroidRuntimeRequest) -> AndroidRuntimeStatus:
    return AndroidRuntimeStatus(
        schema_version=request.schema_version,
        session_id=request.session_id,
        state=AndroidRuntimeState.PERMISSION_REQUIRED.value,
        detail="VpnService permission and service bind are required before startup",
        vpn_prepared=False,
        backend_started=False,
    )


def render_android_runtime_request_json(endpoint: Endpoint, network_policy: NetworkPolicy | None = None) -> str:
    request = build_android_runtime_request(endpoint, network_policy=network_policy)
    return json.dumps(asdict(request), indent=2, sort_keys=True)
