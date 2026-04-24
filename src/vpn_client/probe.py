from __future__ import annotations

from vpn_client.models import Endpoint, FailureClass, FailureReasonCode, ProbeResult


class ProbeEngine:
    """
    A lightweight classifier that simulates how the client should reason
    about network failures before touching the data plane.
    """

    def probe(self, endpoint: Endpoint) -> ProbeResult:
        simulated = str(endpoint.metadata.get("simulated_failure", ""))
        latency_ms = int(endpoint.metadata.get("latency_ms", 90))

        if simulated == "dns":
            return ProbeResult(
                endpoint_id=endpoint.id,
                reachable=False,
                failure_class=FailureClass.DNS_INTERFERENCE,
                reason_code=FailureReasonCode.DNS_LOOKUP_FAILED,
                detail="bootstrap hostname does not resolve consistently",
            )
        if simulated == "tls":
            return ProbeResult(
                endpoint_id=endpoint.id,
                reachable=False,
                failure_class=FailureClass.TLS_INTERFERENCE,
                reason_code=FailureReasonCode.TLS_HANDSHAKE_FAILED,
                detail="connection times out during TLS handshake",
            )
        if simulated == "udp":
            return ProbeResult(
                endpoint_id=endpoint.id,
                reachable=False,
                failure_class=FailureClass.UDP_BLOCKED,
                reason_code=FailureReasonCode.UDP_FILTERED,
                detail="UDP path appears blocked or filtered",
            )
        if simulated == "tcp":
            return ProbeResult(
                endpoint_id=endpoint.id,
                reachable=False,
                failure_class=FailureClass.TCP_BLOCKED,
                reason_code=FailureReasonCode.TCP_CONNECT_FAILED,
                detail="TCP connect fails repeatedly",
            )
        if simulated == "down":
            return ProbeResult(
                endpoint_id=endpoint.id,
                reachable=False,
                failure_class=FailureClass.ENDPOINT_DOWN,
                reason_code=FailureReasonCode.ENDPOINT_UNREACHABLE,
                detail="endpoint is not answering health probes",
            )

        return ProbeResult(
            endpoint_id=endpoint.id,
            reachable=True,
            latency_ms=latency_ms,
            detail="probe completed successfully",
        )
