from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SessionState(str, Enum):
    IDLE = "idle"
    LOADING = "loading"
    PROBING = "probing"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DEGRADED = "degraded"
    FAILED = "failed"


class FailureClass(str, Enum):
    NONE = "none"
    DNS_INTERFERENCE = "dns_interference"
    TLS_INTERFERENCE = "tls_interference"
    UDP_BLOCKED = "udp_blocked"
    TCP_BLOCKED = "tcp_blocked"
    NETWORK_DOWN = "network_down"
    ENDPOINT_DOWN = "endpoint_down"
    UNKNOWN = "unknown"


class FailureReasonCode(str, Enum):
    NONE = "none"
    DNS_LOOKUP_FAILED = "dns_lookup_failed"
    TLS_HANDSHAKE_FAILED = "tls_handshake_failed"
    UDP_FILTERED = "udp_filtered"
    TCP_CONNECT_FAILED = "tcp_connect_failed"
    ENDPOINT_UNREACHABLE = "endpoint_unreachable"
    NETWORK_STACK_NOT_APPLIED = "network_stack_not_applied"
    ROUTE_PROGRAMMING_FAILED = "route_programming_failed"
    SECURE_DNS_POLICY_FAILED = "secure_dns_policy_failed"
    DATAPLANE_BACKEND_UNSUPPORTED = "dataplane_backend_unsupported"
    DATAPLANE_BACKEND_UNREGISTERED = "dataplane_backend_unregistered"
    DATAPLANE_BACKEND_START_FAILED = "dataplane_backend_start_failed"
    DATAPLANE_BACKEND_CRASHED = "dataplane_backend_crashed"
    DATAPLANE_HEALTHCHECK_FAILED = "dataplane_healthcheck_failed"
    DATAPLANE_SESSION_INACTIVE = "dataplane_session_inactive"
    DATAPLANE_PID_MISSING = "dataplane_pid_missing"
    TRANSPORT_NOT_REGISTERED = "transport_not_registered"
    UNKNOWN = "unknown"


def default_reason_code_for_failure(failure_class: FailureClass) -> FailureReasonCode:
    if failure_class is FailureClass.NONE:
        return FailureReasonCode.NONE
    if failure_class is FailureClass.DNS_INTERFERENCE:
        return FailureReasonCode.DNS_LOOKUP_FAILED
    if failure_class is FailureClass.TLS_INTERFERENCE:
        return FailureReasonCode.TLS_HANDSHAKE_FAILED
    if failure_class is FailureClass.UDP_BLOCKED:
        return FailureReasonCode.UDP_FILTERED
    if failure_class is FailureClass.TCP_BLOCKED:
        return FailureReasonCode.TCP_CONNECT_FAILED
    if failure_class is FailureClass.NETWORK_DOWN:
        return FailureReasonCode.DATAPLANE_BACKEND_CRASHED
    if failure_class is FailureClass.ENDPOINT_DOWN:
        return FailureReasonCode.ENDPOINT_UNREACHABLE
    return FailureReasonCode.UNKNOWN


class TunnelMode(str, Enum):
    FULL = "full"
    SPLIT = "split"


class DnsMode(str, Enum):
    VPN_ONLY = "vpn_only"
    SYSTEM_FALLBACK = "system_fallback"


class PlatformSupportStatus(str, Enum):
    MVP_SUPPORTED = "mvp-supported"
    PROTOTYPE = "prototype"
    PLANNED = "planned"
    BRIDGE_ONLY = "bridge-only"
    DEVELOPMENT_ONLY = "development-only"


@dataclass(slots=True)
class PlatformCapability:
    platform: str
    supported_dataplanes: list[str]
    network_adapter: str
    startup_reconciliation: bool = False
    status: str = "planned"
    notes: str = ""


@dataclass(slots=True)
class Endpoint:
    id: str
    host: str
    port: int
    transport: str
    region: str
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class TransportPolicy:
    preferred_order: list[str]
    connect_timeout_ms: int = 2_500
    retry_budget: int = 3
    probe_timeout_ms: int = 1_000


@dataclass(slots=True)
class NetworkPolicy:
    tunnel_mode: TunnelMode = TunnelMode.FULL
    dns_mode: DnsMode = DnsMode.VPN_ONLY
    kill_switch_enabled: bool = True
    ipv6_enabled: bool = False
    allow_lan_while_connected: bool = False


@dataclass(slots=True)
class Manifest:
    version: int
    generated_at: str
    expires_at: str
    endpoints: list[Endpoint]
    transport_policy: TransportPolicy
    network_policy: NetworkPolicy = field(default_factory=NetworkPolicy)
    platform_capabilities: dict[str, PlatformCapability] = field(default_factory=dict)
    features: dict[str, object] = field(default_factory=dict)
    schema_version: int = 1
    provider_profile_schema_version: int | None = None


@dataclass(slots=True)
class ProbeResult:
    endpoint_id: str
    reachable: bool
    failure_class: FailureClass = FailureClass.NONE
    reason_code: FailureReasonCode = FailureReasonCode.NONE
    detail: str = ""
    latency_ms: int | None = None


@dataclass(slots=True)
class ConnectionAttempt:
    endpoint_id: str
    transport: str
    success: bool
    failure_class: FailureClass
    reason_code: FailureReasonCode = FailureReasonCode.NONE
    detail: str = ""
