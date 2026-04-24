from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path

from vpn_client.backend_state import BackendStateStore, now_utc_iso
from vpn_client.dataplane import DataPlaneBackend, DataPlaneError, DataPlaneSession
from vpn_client.models import DnsMode, Endpoint, FailureClass, FailureReasonCode, NetworkPolicy, TunnelMode


class IOSBridgeConfigError(Exception):
    """Raised when an endpoint cannot be translated into the iOS bridge contract."""


class IOSBridgeState(str, Enum):
    AWAITING_EXTENSION = "awaiting_extension"
    EXTENSION_ACKNOWLEDGED = "extension_acknowledged"
    NETWORK_READY = "network_ready"
    TUNNEL_FD_READY = "tunnel_fd_ready"
    RUNNING = "running"
    STOP_REQUESTED = "stop_requested"
    STOPPED = "stopped"
    FAILED = "failed"


@dataclass(slots=True)
class IOSBridgeConfig:
    endpoint_id: str
    provider_kind: str
    remote_host: str
    remote_port: int
    transport: str
    tunnel_mode: str
    security: str
    server_name: str | None
    auth: dict[str, object]
    extras: dict[str, object]


@dataclass(slots=True)
class IOSBridgeRequest:
    schema_version: int
    request_kind: str
    session_id: str
    config: IOSBridgeConfig
    dns: dict[str, object]
    routing: dict[str, object]
    telemetry: dict[str, object]


@dataclass(slots=True)
class IOSBridgeStatus:
    schema_version: int
    session_id: str
    state: str
    detail: str
    network_ready: bool
    tunnel_file_descriptor_ready: bool
    last_error: str | None = None


def initial_ios_bridge_status(request: IOSBridgeRequest) -> IOSBridgeStatus:
    return IOSBridgeStatus(
        schema_version=request.schema_version,
        session_id=request.session_id,
        state=IOSBridgeState.AWAITING_EXTENSION.value,
        detail="contract rendered and waiting for Network Extension pickup",
        network_ready=False,
        tunnel_file_descriptor_ready=False,
    )


def advance_ios_bridge_status(
    status: IOSBridgeStatus,
    *,
    state: IOSBridgeState,
    detail: str,
    network_ready: bool | None = None,
    tunnel_file_descriptor_ready: bool | None = None,
    last_error: str | None = None,
) -> IOSBridgeStatus:
    return IOSBridgeStatus(
        schema_version=status.schema_version,
        session_id=status.session_id,
        state=state.value,
        detail=detail,
        network_ready=status.network_ready if network_ready is None else network_ready,
        tunnel_file_descriptor_ready=(
            status.tunnel_file_descriptor_ready
            if tunnel_file_descriptor_ready is None
            else tunnel_file_descriptor_ready
        ),
        last_error=last_error,
    )


def build_ios_bridge_request(
    endpoint: Endpoint,
    config: IOSBridgeConfig,
    network_policy: NetworkPolicy | None = None,
) -> IOSBridgeRequest:
    policy = network_policy or NetworkPolicy()
    session_id = f"{endpoint.id}-{endpoint.transport}"
    return IOSBridgeRequest(
        schema_version=1,
        request_kind="start_tunnel",
        session_id=session_id,
        config=config,
        dns={
            "mode": policy.dns_mode.value,
            "match_domains": [""] if policy.dns_mode is DnsMode.VPN_ONLY else [],
            "allow_system_fallback": policy.dns_mode is DnsMode.SYSTEM_FALLBACK,
        },
        routing={
            "tunnel_mode": policy.tunnel_mode.value,
            "ipv6_enabled": policy.ipv6_enabled,
            "allow_lan": policy.allow_lan_while_connected,
            "kill_switch_enabled": policy.kill_switch_enabled,
            "included_routes": ["0.0.0.0/0"] if policy.tunnel_mode is TunnelMode.FULL else [],
        },
        telemetry={
            "redact_remote_host": bool(endpoint.metadata.get("ios_redact_remote_host", False)),
            "session_label": endpoint.id,
            "transport": endpoint.transport,
        },
    )


class IOSBridgeConfigRenderer:
    def render(self, endpoint: Endpoint) -> IOSBridgeConfig:
        metadata = endpoint.metadata
        provider_kind = str(metadata.get("ios_provider_kind", "packet-tunnel"))
        transport = str(metadata.get("xray_stream_network", "tcp"))
        security = str(metadata.get("xray_security", "none"))
        server_name = metadata.get("xray_server_name")
        protocol = str(metadata.get("xray_protocol", "vless"))

        if provider_kind != "packet-tunnel":
            raise IOSBridgeConfigError(
                f"endpoint '{endpoint.id}' uses unsupported ios_provider_kind '{provider_kind}'"
            )

        auth = self._build_auth(endpoint, protocol)
        extras: dict[str, object] = {
            "protocol": protocol,
            "fingerprint": metadata.get("xray_fingerprint"),
            "reality_public_key": metadata.get("xray_reality_public_key"),
            "reality_short_id": metadata.get("xray_reality_short_id"),
            "ws_path": metadata.get("xray_ws_path"),
            "ws_host": metadata.get("xray_ws_host"),
            "grpc_service_name": metadata.get("xray_grpc_service_name"),
            "allow_lan": bool(metadata.get("ios_allow_lan", False)),
        }
        extras = {key: value for key, value in extras.items() if value not in (None, "", [])}

        if transport not in {"tcp", "ws", "grpc"}:
            raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' uses unsupported iOS transport '{transport}'")
        if security not in {"none", "tls", "reality"}:
            raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' uses unsupported iOS security '{security}'")

        if security in {"tls", "reality"} and not server_name:
            raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' is missing xray_server_name for iOS bridge")
        if security == "reality" and (
            not metadata.get("xray_reality_public_key") or not metadata.get("xray_reality_short_id")
        ):
            raise IOSBridgeConfigError(
                f"endpoint '{endpoint.id}' needs xray_reality_public_key and xray_reality_short_id for iOS bridge"
            )
        if transport == "grpc" and not metadata.get("xray_grpc_service_name"):
            raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' is missing xray_grpc_service_name for iOS bridge")

        return IOSBridgeConfig(
            endpoint_id=endpoint.id,
            provider_kind=provider_kind,
            remote_host=endpoint.host,
            remote_port=endpoint.port,
            transport=transport,
            tunnel_mode=str(metadata.get("ios_tunnel_mode", "full")),
            security=security,
            server_name=str(server_name) if server_name else None,
            auth=auth,
            extras=extras,
        )

    def render_json(self, endpoint: Endpoint) -> str:
        payload = asdict(self.render(endpoint))
        return json.dumps(payload, indent=2, sort_keys=True)

    def _build_auth(self, endpoint: Endpoint, protocol: str) -> dict[str, object]:
        metadata = endpoint.metadata
        if protocol in {"vless", "vmess"}:
            user_id = metadata.get("xray_user_id")
            if not user_id:
                raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' is missing xray_user_id for iOS bridge")
            auth = {"id": str(user_id)}
            if protocol == "vless":
                auth["encryption"] = str(metadata.get("xray_encryption", "none"))
            return auth
        if protocol == "trojan":
            password = metadata.get("xray_password")
            if not password:
                raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' is missing xray_password for iOS bridge")
            return {"password": str(password)}
        raise IOSBridgeConfigError(f"endpoint '{endpoint.id}' uses unsupported iOS protocol '{protocol}'")


def endpoint_declares_ios_bridge(endpoint: Endpoint) -> bool:
    metadata = endpoint.metadata
    return metadata.get("dataplane") == "ios-bridge" or any(str(key).startswith("ios_") for key in metadata)


def validate_ios_bridge_endpoint_metadata(endpoint: Endpoint) -> None:
    IOSBridgeConfigRenderer().render(endpoint)


class IOSBridgeDataPlane(DataPlaneBackend):
    name = "ios-bridge"

    def __init__(
        self,
        contract_dir: Path | None = None,
        state_store: BackendStateStore | None = None,
        renderer: IOSBridgeConfigRenderer | None = None,
        network_policy: NetworkPolicy | None = None,
    ) -> None:
        self.contract_dir = contract_dir or Path(".cache/resilient-vpn/ios-bridge")
        self.contract_dir.mkdir(parents=True, exist_ok=True)
        self.state_store = state_store
        self.renderer = renderer or IOSBridgeConfigRenderer()
        self.network_policy = network_policy or NetworkPolicy()
        self.session: DataPlaneSession | None = None
        self.active_contract_path: Path | None = None
        self.active_status_path: Path | None = None

    def connect(self, endpoint: Endpoint) -> DataPlaneSession:
        contract_path = self.contract_dir / f"{endpoint.id}.json"
        config = self.renderer.render(endpoint)
        request = build_ios_bridge_request(endpoint, config, network_policy=self.network_policy)
        self._write_json(contract_path, asdict(request))
        self.active_contract_path = contract_path
        status_path = self.contract_dir / f"{endpoint.id}.status.json"
        status = initial_ios_bridge_status(request)
        self._write_json(status_path, asdict(status))
        self.active_status_path = status_path
        self.session = DataPlaneSession(
            backend_name=self.name,
            endpoint_id=endpoint.id,
            active=False,
            dry_run=True,
            command=["ios-bridge", "load-contract", str(contract_path)],
            pid=None,
            restart_count=0,
            started_at=now_utc_iso(),
        )
        self._persist_state(active=False)
        raise DataPlaneError(
            FailureClass.UNKNOWN,
            "ios-bridge contract rendered, but the Apple Network Extension runtime is not wired yet",
            reason_code=FailureReasonCode.DATAPLANE_BACKEND_UNSUPPORTED,
        )

    def disconnect(self) -> None:
        self._cleanup_contract()
        self.session = None
        self._persist_state(active=False)

    def health_check(self, endpoint: Endpoint) -> None:
        raise DataPlaneError(
            FailureClass.UNKNOWN,
            "ios-bridge health checks are unavailable until the Apple runtime is implemented",
            reason_code=FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
        )

    def runtime_snapshot(self) -> dict:
        return {
            "backend": self.name,
            "active": False,
            "endpoint_id": self.session.endpoint_id if self.session else None,
            "pid": None,
            "restart_count": 0,
            "crashed": False,
            "crash_reason": None,
            "last_exit_code": None,
            "stdout_tail": "",
            "stderr_tail": "",
            "command": self.session.command if self.session else None,
            "contract_path": str(self.active_contract_path) if self.active_contract_path else None,
            "status_path": str(self.active_status_path) if self.active_status_path else None,
            "status": asdict(self.load_status()) if self.active_status_path else None,
        }

    def load_status(self) -> IOSBridgeStatus | None:
        if not self.active_status_path or not self.active_status_path.exists():
            return None
        return IOSBridgeStatus(**json.loads(self.active_status_path.read_text(encoding="utf-8")))

    def mark_extension_acknowledged(self) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.EXTENSION_ACKNOWLEDGED,
            detail="Network Extension acknowledged the request payload",
        )

    def mark_network_ready(self) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.NETWORK_READY,
            detail="Network settings have been prepared inside the extension",
            network_ready=True,
        )

    def mark_tunnel_fd_ready(self) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.TUNNEL_FD_READY,
            detail="Tunnel file descriptor is attached and ready for traffic",
            network_ready=True,
            tunnel_file_descriptor_ready=True,
        )

    def mark_running(self) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.RUNNING,
            detail="Tunnel is running inside the Network Extension",
            network_ready=True,
            tunnel_file_descriptor_ready=True,
        )

    def mark_stop_requested(self) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.STOP_REQUESTED,
            detail="App requested tunnel shutdown",
        )

    def mark_stopped(self) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.STOPPED,
            detail="Tunnel stopped cleanly",
        )

    def mark_failed(self, detail: str, *, last_error: str | None = None) -> IOSBridgeStatus:
        return self._advance_status(
            state=IOSBridgeState.FAILED,
            detail=detail,
            last_error=last_error or detail,
        )

    def _cleanup_contract(self) -> None:
        if self.active_contract_path and self.active_contract_path.exists():
            self.active_contract_path.unlink()
        self.active_contract_path = None
        if self.active_status_path and self.active_status_path.exists():
            self.active_status_path.unlink()
        self.active_status_path = None

    def _advance_status(
        self,
        *,
        state: IOSBridgeState,
        detail: str,
        network_ready: bool | None = None,
        tunnel_file_descriptor_ready: bool | None = None,
        last_error: str | None = None,
    ) -> IOSBridgeStatus:
        status = self.load_status()
        if status is None or self.active_status_path is None:
            raise DataPlaneError(
                FailureClass.UNKNOWN,
                "ios-bridge status file is not available",
                reason_code=FailureReasonCode.DATAPLANE_SESSION_INACTIVE,
            )
        updated = advance_ios_bridge_status(
            status,
            state=state,
            detail=detail,
            network_ready=network_ready,
            tunnel_file_descriptor_ready=tunnel_file_descriptor_ready,
            last_error=last_error,
        )
        self._write_json(self.active_status_path, asdict(updated))
        return updated

    def _write_json(self, path: Path, payload: dict[str, object]) -> None:
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    def _persist_state(self, active: bool) -> None:
        if self.state_store is None:
            return
        from vpn_client.backend_state import BackendStateRecord

        snapshot = self.runtime_snapshot()
        record = BackendStateRecord(
            backend=self.name,
            endpoint_id=self.session.endpoint_id if self.session else None,
            pid=None,
            active=active and self.session is not None,
            started_at=self.session.started_at if self.session else None,
            stopped_at=None if active and self.session is not None else now_utc_iso(),
            command=snapshot["command"] or [],
            restart_count=0,
            crashed=False,
            crash_reason=None,
            last_exit_code=None,
            stdout_tail="",
            stderr_tail="",
        )
        self.state_store.save(record)
