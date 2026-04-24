from __future__ import annotations

from dataclasses import dataclass

from vpn_client.backend_state import BackendStateRecord, BackendStateStore
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
        backend_state_store: BackendStateStore | None = None,
    ):
        self.runtime_state = runtime_state
        self.network_stack = network_stack
        self.dataplane = dataplane
        self.telemetry = telemetry
        self.state_manager = state_manager
        self.backend_state_store = backend_state_store

    def recover(self, cleanup_stale_runtime: bool) -> RecoveryReport:
        marker = self.runtime_state.load_marker()
        if marker is None:
            return RecoveryReport(stale_marker_found=False, actions=[])

        actions = [f"stale runtime marker for {marker.endpoint_id}"]
        if cleanup_stale_runtime:
            self._cleanup(marker)
            if self.state_manager:
                backend_state = self.backend_state_store.load() if self.backend_state_store is not None else None
                if self._should_penalize_stale_runtime(marker, backend_state):
                    transport_disabled = self.state_manager.mark_stale_runtime(marker.endpoint_id, marker.transport)
                    actions.append("state penalty applied")
                    if transport_disabled:
                        actions.append(f"transport {marker.transport} disabled locally")
                else:
                    actions.append("state penalty skipped after orderly shutdown signal")
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

    def _should_penalize_stale_runtime(
        self,
        marker: RuntimeMarker,
        backend_state: BackendStateRecord | None,
    ) -> bool:
        if backend_state is None:
            return True
        if backend_state.endpoint_id != marker.endpoint_id:
            return True
        if backend_state.active:
            return True
        if backend_state.crashed:
            return True
        return False
