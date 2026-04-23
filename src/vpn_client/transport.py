from __future__ import annotations

from dataclasses import dataclass

from vpn_client.models import Endpoint, FailureClass
from vpn_client.transport_base import Transport, TransportError
from vpn_client.transport_tcp import TcpTransport


@dataclass(slots=True)
class SimulatedTransport(Transport):
    name: str
    connected_endpoint_id: str | None = None

    def connect(self, endpoint: Endpoint) -> None:
        failure = str(endpoint.metadata.get("connect_failure", ""))
        if failure == "network_down":
            raise TransportError(FailureClass.NETWORK_DOWN, "network is unavailable")
        if failure == "endpoint_down":
            raise TransportError(FailureClass.ENDPOINT_DOWN, "endpoint rejects connection")
        if failure == "tls":
            raise TransportError(FailureClass.TLS_INTERFERENCE, "handshake is interrupted")
        if failure == "udp":
            raise TransportError(FailureClass.UDP_BLOCKED, "UDP packets are filtered")
        if failure == "tcp":
            raise TransportError(FailureClass.TCP_BLOCKED, "TCP path is blocked")

        self.connected_endpoint_id = endpoint.id

    def disconnect(self) -> None:
        self.connected_endpoint_id = None


def default_transport_registry() -> dict[str, Transport]:
    return {
        "wireguard": SimulatedTransport(name="wireguard"),
        "https": TcpTransport(name="https"),
        "quic": SimulatedTransport(name="quic"),
    }
