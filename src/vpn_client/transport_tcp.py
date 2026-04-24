from __future__ import annotations

import socket
from dataclasses import dataclass

from vpn_client.models import Endpoint, FailureClass, FailureReasonCode
from vpn_client.transport_base import Transport, TransportError


@dataclass(slots=True)
class TcpTransport(Transport):
    name: str = "https"
    connect_timeout_s: float = 1.5
    connected_endpoint_id: str | None = None

    def connect(self, endpoint: Endpoint) -> None:
        if endpoint.metadata.get("connect_mode") != "tcp":
            self.connected_endpoint_id = endpoint.id
            return

        try:
            with socket.create_connection((endpoint.host, endpoint.port), timeout=self.connect_timeout_s):
                self.connected_endpoint_id = endpoint.id
        except OSError as exc:
            raise TransportError(
                FailureClass.TCP_BLOCKED,
                f"tcp dial failed: {exc}",
                reason_code=FailureReasonCode.TCP_CONNECT_FAILED,
            ) from exc

    def disconnect(self) -> None:
        self.connected_endpoint_id = None
