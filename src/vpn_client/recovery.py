from __future__ import annotations

from dataclasses import dataclass

from vpn_client.dataplane import DataPlaneBackend
from vpn_client.models import FailureClass
from vpn_client.platform_adapters import PlatformNetworkAdapter
from vpn_client.runtime import RuntimeMarker, RuntimeState
from vpn_client.state import StateManager
from vpn_client.telemetry import TelemetryRecorder
from vpn_client.models import SessionState


@dataclass(slots=True)
class RecoveryReport:
    stale_marker_found: bool
    actions: list[str]


class StartupRecovery:
    def __init__(
        self,
        runtime_state: RuntimeState,
        network_stack: PlatformNetworkAdapter,
        dataplane: DataPlaneBackend,
        telemetry: TelemetryRecorder,
        state_manager: StateManager | None = None,
    ):
        self.runtime_state = runtime_state
        self.network_stack = network_stack
        self.dataplane = dataplane
        self.telemetry = telemetry
        self.state_manager = state_manager

    def recover(self, cleanup_stale_runtime: bool) -> RecoveryReport:
        marker = self.runtime_state.load_marker()
        if marker is None:
            return RecoveryReport(stale_marker_found=False, actions=[])

        actions = [f"stale runtime marker for {marker.endpoint_id}"]
        if cleanup_stale_runtime:
            self._cleanup(marker)
            if self.state_manager:
                transport_disabled = self.state_manager.mark_stale_runtime(marker.endpoint_id, marker.transport)
                actions.append("state penalty applied")
                if transport_disabled:
                    actions.append(f"transport {marker.transport} disabled locally")
            actions.extend(["dataplane disconnect", "network stack disconnect", "runtime marker clear"])
        return RecoveryReport(stale_marker_found=True, actions=actions)

    def _cleanup(self, marker: RuntimeMarker) -> None:
        self.telemetry.record(
            "stale_runtime_cleanup",
            SessionState.IDLE,
            FailureClass.UNKNOWN,
            endpoint_id=marker.endpoint_id,
            transport=marker.transport,
            detail="stale marker cleared before startup",
        )
        self.dataplane.disconnect()
        if self.network_stack.supports_startup_reconciliation():
            reconciliation = self.network_stack.reconcile_startup()
            if reconciliation and reconciliation.commands:
                self.telemetry.record(
                    f"{self.network_stack.platform_name}_startup_reconciliation",
                    SessionState.IDLE,
                    endpoint_id=marker.endpoint_id,
                    transport=marker.transport,
                    detail=f"prepared {len(reconciliation.commands)} startup cleanup commands",
                )
        self.network_stack.disconnect()
        self.runtime_state.clear()
