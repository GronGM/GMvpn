from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vpn_client.dataplane import NullDataPlane
from vpn_client.linux import LinuxCommandPlan, LinuxNetworkStack
from vpn_client.models import DnsMode, Endpoint, NetworkPolicy, TunnelMode
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

    def test_recovery_keeps_clearing_marker_when_linux_reconciliation_is_partial(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = RuntimeState(Path(tmp) / "marker.json")
            runtime.mark_active("edge-1", "https")
            stack = LinuxNetworkStack(
                interface_name="tun42",
                dry_run=False,
                command_exists=lambda _name: None,
            )
            telemetry = TelemetryRecorder()
            recovery = StartupRecovery(runtime, stack, NullDataPlane(), telemetry)

            report = recovery.recover(cleanup_stale_runtime=True)

            self.assertTrue(report.stale_marker_found)
            self.assertIsNone(runtime.load_marker())
            self.assertTrue(stack.last_reconciliation.partial_failure)
            self.assertEqual(stack.last_reconciliation.failure_reason_code, "platform_tool_missing")
            self.assertIn("runtime marker clear", report.actions)
            self.assertIn("cleanup remained partial", telemetry.events[-1].detail)

    def test_recovery_surfaces_partial_linux_disconnect_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = RuntimeState(Path(tmp) / "marker.json")
            runtime.mark_active("edge-1", "https")
            endpoint = Endpoint(
                id="edge-1",
                host="198.51.100.20",
                port=443,
                transport="https",
                region="eu-central",
            )
            policy = NetworkPolicy(
                tunnel_mode=TunnelMode.FULL,
                dns_mode=DnsMode.VPN_ONLY,
                kill_switch_enabled=True,
                ipv6_enabled=False,
            )

            def runner(command: list[str]) -> None:
                if command[:3] == ["ip", "route", "del"]:
                    raise RuntimeError("route still busy")

            stack = LinuxNetworkStack(
                interface_name="tun42",
                dry_run=False,
                command_runner=runner,
                command_exists=lambda _name: "/usr/bin/fake",
            )
            stack.last_plan = LinuxCommandPlan(
                commands=[],
                rollback_commands=stack._build_rollback_plan(endpoint, policy),
                dry_run=False,
            )
            telemetry = TelemetryRecorder()
            recovery = StartupRecovery(runtime, stack, NullDataPlane(), telemetry)

            report = recovery.recover(cleanup_stale_runtime=True)

            self.assertTrue(report.stale_marker_found)
            self.assertIsNone(runtime.load_marker())
            self.assertIn("network stack cleanup incomplete", report.actions)
            self.assertTrue(stack.last_execution.cleanup_incomplete)
            self.assertEqual(telemetry.events[-1].kind, "linux_disconnect_cleanup")
            self.assertEqual(telemetry.events[-1].reason_code, "route_programming_failed")


if __name__ == "__main__":
    unittest.main()
