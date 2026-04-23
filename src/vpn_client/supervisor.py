from __future__ import annotations

from dataclasses import dataclass

from vpn_client.models import Manifest, SessionState
from vpn_client.runtime_tick import RuntimeTickPolicy, RuntimeTickReport
from vpn_client.session import SessionOrchestrator
from vpn_client.telemetry import TelemetryRecorder


@dataclass(slots=True)
class SupervisorCycleReport:
    cycle: int
    pending_total: int
    pending_ready_transports: list[str]
    reenabled_transports: list[str]


@dataclass(slots=True)
class SupervisorRunReport:
    cycles: list[SupervisorCycleReport]


class RuntimeSupervisor:
    def __init__(self, orchestrator: SessionOrchestrator, telemetry: TelemetryRecorder):
        self.orchestrator = orchestrator
        self.telemetry = telemetry

    def run_cycles(
        self,
        manifest: Manifest,
        num_cycles: int,
        tick_policy: RuntimeTickPolicy | None = None,
    ) -> SupervisorRunReport:
        policy = tick_policy or RuntimeTickPolicy()
        cycles: list[SupervisorCycleReport] = []

        for cycle in range(1, max(num_cycles, 0) + 1):
            self.telemetry.record(
                "supervisor_cycle_started",
                SessionState.IDLE if self.orchestrator.state is SessionState.IDLE else self.orchestrator.state,
                detail=f"cycle={cycle}",
            )
            tick = self.orchestrator.runtime_tick(manifest, policy=policy)
            cycles.append(
                SupervisorCycleReport(
                    cycle=cycle,
                    pending_total=tick.pending_total,
                    pending_ready_transports=tick.pending_ready_transports,
                    reenabled_transports=tick.reenabled_transports,
                )
            )
            self.telemetry.record(
                "supervisor_cycle_completed",
                SessionState.IDLE if self.orchestrator.state is SessionState.IDLE else self.orchestrator.state,
                detail=(
                    f"cycle={cycle} pending_total={tick.pending_total} "
                    f"reenabled={len(tick.reenabled_transports)}"
                ),
            )

        return SupervisorRunReport(cycles=cycles)
