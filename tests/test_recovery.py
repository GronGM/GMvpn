from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vpn_client.backend_state import BackendStateRecord, BackendStateStore
from vpn_client.dataplane import NullDataPlane
from vpn_client.linux import LinuxNetworkStack
from vpn_client.platform import SimulatedNetworkStack
from vpn_client.recovery import StartupRecovery
from vpn_client.runtime import RuntimeState
from vpn_client.state import StateManager, StateStore
from vpn_client.telemetry import TelemetryRecorder


class StartupRecoveryTests(unittest.TestCase):
    def test_recovery_cleans_stale_marker_when_requested(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = RuntimeState(Path(tmp) / "marker.json")
            runtime.mark_active("edge-1", "https")
            recovery = StartupRecovery(runtime, SimulatedNetworkStack(), NullDataPlane(), TelemetryRecorder())

            report = recovery.recover(cleanup_stale_runtime=True)

            self.assertTrue(report.stale_marker_found)
            self.assertIsNone(runtime.load_marker())
            self.assertIn("runtime marker clear", report.actions)

    def test_recovery_runs_linux_reconciliation_when_available(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = RuntimeState(Path(tmp) / "marker.json")
            runtime.mark_active("edge-1", "https")
            stack = LinuxNetworkStack(interface_name="tun42", dry_run=True)
            recovery = StartupRecovery(runtime, stack, NullDataPlane(), TelemetryRecorder())

            report = recovery.recover(cleanup_stale_runtime=True)

            self.assertTrue(report.stale_marker_found)
            self.assertIsNotNone(stack.last_reconciliation)
            self.assertEqual(stack.last_reconciliation.commands[0], ["resolvectl", "revert", "tun42"])

    def test_recovery_penalizes_stale_endpoint_when_cleanup_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = RuntimeState(Path(tmp) / "marker.json")
            runtime.mark_active("edge-1", "https")
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            recovery = StartupRecovery(
                runtime,
                SimulatedNetworkStack(),
                NullDataPlane(),
                TelemetryRecorder(),
                state_manager=state_manager,
            )

            report = recovery.recover(cleanup_stale_runtime=True)

            self.assertTrue(report.stale_marker_found)
            self.assertIn("state penalty applied", report.actions)
            self.assertTrue(state_manager.is_cooling_down("edge-1"))
            self.assertEqual(state_manager.transport_crash_streak("https"), 1)

    def test_recovery_skips_penalty_when_backend_state_shows_orderly_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            runtime = RuntimeState(tmp_path / "marker.json")
            runtime.mark_active("edge-1", "https")
            state_manager = StateManager(StateStore(tmp_path / "state.json"))
            backend_state_store = BackendStateStore(tmp_path / "backend-state.json")
            backend_state_store.save(
                BackendStateRecord(
                    backend="linux-userspace",
                    endpoint_id="edge-1",
                    pid=41001,
                    active=False,
                    started_at="2026-04-23T00:00:00+00:00",
                    stopped_at="2026-04-23T00:05:00+00:00",
                    command=["vpn-backend"],
                    restart_count=0,
                    crashed=False,
                    crash_reason=None,
                    last_exit_code=0,
                    stdout_tail="",
                    stderr_tail="",
                )
            )
            recovery = StartupRecovery(
                runtime,
                SimulatedNetworkStack(),
                NullDataPlane(),
                TelemetryRecorder(),
                state_manager=state_manager,
                backend_state_store=backend_state_store,
            )

            report = recovery.recover(cleanup_stale_runtime=True)

            self.assertTrue(report.stale_marker_found)
            self.assertIn("state penalty skipped after orderly shutdown signal", report.actions)
            self.assertFalse(state_manager.is_cooling_down("edge-1"))
            self.assertEqual(state_manager.transport_crash_streak("https"), 0)


if __name__ == "__main__":
    unittest.main()
