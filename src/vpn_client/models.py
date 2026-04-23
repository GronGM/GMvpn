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


class TunnelMode(str, Enum):
    FULL = "full"
    SPLIT = "split"


class DnsMode(str, Enum):
    VPN_ONLY = "vpn_only"
    SYSTEM_FALLBACK = "system_fallback"


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


@dataclass(slots=True)
class ProbeResult:
    endpoint_id: str
    reachable: bool
    failure_class: FailureClass = FailureClass.NONE
    detail: str = ""
    latency_ms: int | None = None


@dataclass(slots=True)
class ConnectionAttempt:
    endpoint_id: str
    transport: str
    success: bool
    failure_class: FailureClass
    detail: str = ""
