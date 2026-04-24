from __future__ import annotations

from dataclasses import dataclass

from vpn_client.dataplane import DataPlaneBackend, DataPlaneError
from vpn_client.models import Endpoint, FailureClass, FailureReasonCode
from vpn_client.platform import NetworkStackError
from vpn_client.platform_adapters import PlatformNetworkAdapter
from vpn_client.telemetry import TelemetryRecorder


@dataclass(slots=True)
class HealthReport:
    healthy: bool
    failure_class: FailureClass = FailureClass.NONE
    reason_code: FailureReasonCode = FailureReasonCode.NONE
    detail: str = ""


@dataclass(slots=True)
class HealthPolicy:
    checks: int = 1
    auto_reconnect: bool = False


class SessionHealthMonitor:
    def __init__(
        self,
        dataplane: DataPlaneBackend,
        network_stack: PlatformNetworkAdapter,
        telemetry: TelemetryRecorder,
    ):
        self.dataplane = dataplane
        self.network_stack = network_stack
        self.telemetry = telemetry

    def check(self, endpoint: Endpoint) -> HealthReport:
        try:
            if self.network_stack.applied_state is None:
                raise NetworkStackError(
                    FailureClass.NETWORK_DOWN,
                    "network stack is not applied",
                    reason_code=FailureReasonCode.NETWORK_STACK_NOT_APPLIED,
                )
            self.dataplane.health_check(endpoint)
            self.telemetry.record(
                "session_health_ok",
                session_state=self._session_state(),
                endpoint_id=endpoint.id,
                transport=endpoint.transport,
                detail="health check passed",
            )
            return HealthReport(healthy=True)
        except (DataPlaneError, NetworkStackError) as exc:
            failure_class = exc.failure_class if hasattr(exc, "failure_class") else FailureClass.UNKNOWN
            reason_code = exc.reason_code if hasattr(exc, "reason_code") else FailureReasonCode.UNKNOWN
            detail = exc.detail if hasattr(exc, "detail") else str(exc)
            self.telemetry.record(
                "session_health_failed",
                session_state=self._session_state(),
                failure_class=failure_class,
                reason_code=reason_code,
                endpoint_id=endpoint.id,
                transport=endpoint.transport,
                detail=detail,
            )
            return HealthReport(
                healthy=False,
                failure_class=failure_class,
                reason_code=reason_code,
                detail=detail,
            )

    def run_cycle(self, endpoint: Endpoint, policy: HealthPolicy) -> list[HealthReport]:
        reports: list[HealthReport] = []
        for _ in range(max(policy.checks, 1)):
            reports.append(self.check(endpoint))
            if not reports[-1].healthy and not policy.auto_reconnect:
                break
        return reports

    def _session_state(self):
        from vpn_client.models import SessionState

        return SessionState.CONNECTED
