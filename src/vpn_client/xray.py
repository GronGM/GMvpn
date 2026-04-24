from __future__ import annotations

import json
from pathlib import Path

from vpn_client.backend_state import BackendStateStore, now_utc_iso
from vpn_client.dataplane import (
    BackendProcessSupervisor,
    DataPlaneError,
    DataPlaneSession,
    LinuxUserspaceDataPlane,
)
from vpn_client.models import Endpoint, FailureClass, FailureReasonCode


class XrayConfigError(Exception):
    """Raised when an endpoint cannot be rendered into an xray-core config."""


class XrayConfigRenderer:
    def __init__(self, interface_name: str = "tun0"):
        self.interface_name = interface_name

    def render(self, endpoint: Endpoint) -> dict:
        metadata = endpoint.metadata
        protocol = str(metadata.get("xray_protocol", "vless"))
        stream_network = str(metadata.get("xray_stream_network", "tcp"))
        security = str(metadata.get("xray_security", "none"))

        config = {
            "log": {"loglevel": str(metadata.get("xray_log_level", "warning"))},
            "inbounds": [
                {
                    "tag": "tun-in",
                    "protocol": "tun",
                    "settings": {
                        "name": self.interface_name,
                        "mtu": int(metadata.get("xray_tun_mtu", 1380)),
                        "stack": str(metadata.get("xray_tun_stack", "system")),
                        "autoRoute": False,
                        "strictRoute": False,
                    },
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]},
                }
            ],
            "outbounds": [
                {
                    "tag": "proxy",
                    "protocol": protocol,
                    "settings": self._build_outbound_settings(endpoint, protocol),
                    "streamSettings": self._build_stream_settings(endpoint, stream_network, security),
                },
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {"type": "field", "inboundTag": ["tun-in"], "outboundTag": "proxy"},
                ],
            },
        }

        if security == "reality":
            config["outbounds"][0]["mux"] = {"enabled": False}

        return config

    def render_json(self, endpoint: Endpoint) -> str:
        return json.dumps(self.render(endpoint), indent=2, sort_keys=True)

    def _build_outbound_settings(self, endpoint: Endpoint, protocol: str) -> dict:
        metadata = endpoint.metadata
        if protocol in {"vless", "vmess"}:
            user_id = metadata.get("xray_user_id")
            if not user_id:
                raise XrayConfigError(f"endpoint '{endpoint.id}' is missing xray_user_id")
            user: dict[str, object] = {"id": str(user_id)}
            if protocol == "vless":
                flow = metadata.get("xray_flow")
                encryption = str(metadata.get("xray_encryption", "none"))
                user["encryption"] = encryption
                if flow:
                    user["flow"] = str(flow)
            else:
                security = metadata.get("xray_user_security")
                if security:
                    user["security"] = str(security)
                alter_id = metadata.get("xray_alter_id")
                if alter_id is not None:
                    user["alterId"] = int(alter_id)
            return {
                "vnext": [
                    {
                        "address": endpoint.host,
                        "port": endpoint.port,
                        "users": [user],
                    }
                ]
            }
        if protocol == "trojan":
            password = metadata.get("xray_password")
            if not password:
                raise XrayConfigError(f"endpoint '{endpoint.id}' is missing xray_password")
            return {
                "servers": [
                    {
                        "address": endpoint.host,
                        "port": endpoint.port,
                        "password": str(password),
                    }
                ]
            }
        raise XrayConfigError(f"endpoint '{endpoint.id}' uses unsupported xray protocol '{protocol}'")

    def _build_stream_settings(self, endpoint: Endpoint, stream_network: str, security: str) -> dict:
        metadata = endpoint.metadata
        stream_settings: dict[str, object] = {
            "network": stream_network,
            "security": security,
        }

        if security == "tls":
            tls_settings: dict[str, object] = {}
            server_name = metadata.get("xray_server_name")
            if server_name:
                tls_settings["serverName"] = str(server_name)
            alpn = metadata.get("xray_alpn")
            if isinstance(alpn, list) and alpn:
                tls_settings["alpn"] = [str(item) for item in alpn]
            fingerprint = metadata.get("xray_fingerprint")
            if fingerprint:
                tls_settings["fingerprint"] = str(fingerprint)
            stream_settings["tlsSettings"] = tls_settings
        elif security == "reality":
            public_key = metadata.get("xray_reality_public_key")
            short_id = metadata.get("xray_reality_short_id")
            if not public_key or short_id is None:
                raise XrayConfigError(
                    f"endpoint '{endpoint.id}' needs xray_reality_public_key and xray_reality_short_id"
                )
            reality_settings: dict[str, object] = {
                "publicKey": str(public_key),
                "shortId": str(short_id),
            }
            server_name = metadata.get("xray_server_name")
            if server_name:
                reality_settings["serverName"] = str(server_name)
            fingerprint = metadata.get("xray_fingerprint")
            if fingerprint:
                reality_settings["fingerprint"] = str(fingerprint)
            spider_x = metadata.get("xray_reality_spider_x")
            if spider_x:
                reality_settings["spiderX"] = str(spider_x)
            stream_settings["realitySettings"] = reality_settings
        elif security != "none":
            raise XrayConfigError(f"endpoint '{endpoint.id}' uses unsupported xray security '{security}'")

        if stream_network == "ws":
            ws_settings: dict[str, object] = {}
            path = metadata.get("xray_ws_path")
            if path:
                ws_settings["path"] = str(path)
            host = metadata.get("xray_ws_host")
            if host:
                ws_settings["headers"] = {"Host": str(host)}
            stream_settings["wsSettings"] = ws_settings
        elif stream_network == "grpc":
            service_name = metadata.get("xray_grpc_service_name")
            if not service_name:
                raise XrayConfigError(f"endpoint '{endpoint.id}' is missing xray_grpc_service_name")
            stream_settings["grpcSettings"] = {"serviceName": str(service_name)}
        elif stream_network != "tcp":
            raise XrayConfigError(f"endpoint '{endpoint.id}' uses unsupported xray stream '{stream_network}'")

        return stream_settings


def endpoint_declares_xray(endpoint: Endpoint) -> bool:
    metadata = endpoint.metadata
    return metadata.get("dataplane") == "xray-core" or any(str(key).startswith("xray_") for key in metadata)


def validate_xray_endpoint_metadata(endpoint: Endpoint) -> None:
    renderer = XrayConfigRenderer(
        interface_name=str(endpoint.metadata.get("xray_tun_name", "tun0")),
    )
    renderer.render(endpoint)


class XrayCoreDataPlane(LinuxUserspaceDataPlane):
    name = "xray-core"

    def __init__(
        self,
        interface_name: str = "tun0",
        dry_run: bool = True,
        supervisor: BackendProcessSupervisor | None = None,
        state_store: BackendStateStore | None = None,
        config_dir: Path | None = None,
        binary_path: str = "xray",
        renderer: XrayConfigRenderer | None = None,
    ) -> None:
        super().__init__(
            interface_name=interface_name,
            dry_run=dry_run,
            supervisor=supervisor,
            state_store=state_store,
        )
        self.config_dir = config_dir or Path(".cache/resilient-vpn/xray")
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.binary_path = binary_path
        self.renderer = renderer or XrayConfigRenderer(interface_name=interface_name)
        self.active_config_path: Path | None = None

    def connect(self, endpoint: Endpoint) -> DataPlaneSession:
        simulated = str(endpoint.metadata.get("dataplane_failure", ""))
        if simulated == "start":
            raise DataPlaneError(
                FailureClass.ENDPOINT_DOWN,
                "xray-core failed to start",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_START_FAILED,
            )

        config_path = self.config_dir / f"{endpoint.id}.json"
        config_path.write_text(self.renderer.render_json(endpoint), encoding="utf-8")
        self.active_config_path = config_path

        command = [self.binary_path, "run", "-config", str(config_path)]
        try:
            pid = self.supervisor.start(command, dry_run=self.dry_run)
        except Exception as exc:
            self._cleanup_config()
            raise DataPlaneError(
                FailureClass.ENDPOINT_DOWN,
                f"xray-core start failed: {exc}",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_START_FAILED,
            ) from exc

        self.session = DataPlaneSession(
            backend_name=self.name,
            endpoint_id=endpoint.id,
            active=True,
            dry_run=self.dry_run,
            command=command,
            pid=pid,
            restart_count=self.supervisor.restart_count,
            started_at=now_utc_iso(),
        )
        self._persist_state()
        return self.session

    def disconnect(self) -> None:
        super().disconnect()
        self._cleanup_config()

    def runtime_snapshot(self) -> dict:
        snapshot = super().runtime_snapshot()
        snapshot["config_path"] = str(self.active_config_path) if self.active_config_path else None
        return snapshot

    def _cleanup_config(self) -> None:
        if self.active_config_path and self.active_config_path.exists():
            self.active_config_path.unlink()
        self.active_config_path = None
