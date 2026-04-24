from __future__ import annotations

import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path

from vpn_client.incident import build_incident_summary
from vpn_client.models import FailureClass, FailureReasonCode, Manifest, NetworkPolicy, SessionState, TransportPolicy
from vpn_client.state import StateManager, StateStore


@dataclass(slots=True)
class DummyReport:
    state: SessionState
    selected_endpoint_id: str | None = None
    selected_transport: str | None = None
    failure_class: FailureClass = FailureClass.NONE


@dataclass(slots=True)
class DummyRecoveryReport:
    stale_marker_found: bool


class IncidentSummaryTests(unittest.TestCase):
    def test_incident_summary_marks_startup_recovery_as_warning(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.mark_stale_runtime("edge-1", "https")

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.CONNECTED,
                    selected_endpoint_id="edge-1",
                    selected_transport="https",
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=True),
                recovery_cleanup_enabled=True,
                simulated_stale_runtime_endpoint_id="edge-1",
            )

            self.assertEqual(summary["headline"], "startup recovery handled a stale runtime marker")
            self.assertEqual(summary["severity"], "warning")
            self.assertEqual(
                summary["recommended_action"],
                "Review the last crash reason and monitor the recovered transport for repeat failures.",
            )
            self.assertEqual(summary["last_crash_transport"], "https")

    def test_incident_summary_marks_clean_connection_as_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.CONNECTED,
                    selected_endpoint_id="edge-1",
                    selected_transport="https",
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
            )

            self.assertEqual(summary["severity"], "ok")
            self.assertEqual(summary["recommended_action"], "No immediate action required.")

    def test_incident_summary_uses_failure_class_guidance_for_degraded_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.DEGRADED,
                    failure_class=FailureClass.TLS_INTERFERENCE,
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
            )

            self.assertEqual(summary["severity"], "warning")
            self.assertEqual(summary["failure_class"], "tls_interference")
            self.assertEqual(
                summary["recommended_action"],
                "Try an alternate transport or resolver path and inspect local interference signals before retrying.",
            )

    def test_incident_summary_uses_manifest_guidance_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                endpoints=[],
                transport_policy=TransportPolicy(preferred_order=["https"]),
                network_policy=NetworkPolicy(),
                features={
                    "incident_guidance_overrides": {
                        "tls_interference": {
                            "severity": "critical",
                            "recommended_action": "Use the provider emergency fallback profile before retrying.",
                        }
                    }
                },
            )

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.DEGRADED,
                    failure_class=FailureClass.TLS_INTERFERENCE,
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
                manifest=manifest,
            )

            self.assertEqual(summary["severity"], "critical")
            self.assertEqual(
                summary["recommended_action"],
                "Use the provider emergency fallback profile before retrying.",
            )

    def test_incident_summary_exposes_dns_mitigation_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.apply_failure_mitigation(FailureClass.DNS_INTERFERENCE)

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.CONNECTED,
                    selected_endpoint_id="edge-1",
                    selected_transport="https",
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
            )

            self.assertEqual(summary["headline"], "one or more local failure mitigations are active")
            self.assertEqual(summary["severity"], "warning")
            self.assertIn("force_system_dns_fallback", summary["active_incident_flags"])
            self.assertIn("force_system_dns_fallback", summary["active_mitigation_flags"])
            self.assertIn("force_system_dns_fallback", summary["mitigation_flag_expires_at"])

    def test_incident_summary_exposes_transport_disable_mitigation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.apply_failure_mitigation(FailureClass.UDP_BLOCKED, transport="wireguard")

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.CONNECTED,
                    selected_endpoint_id="edge-1",
                    selected_transport="https",
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
            )

            self.assertEqual(summary["headline"], "one or more transports are locally disabled")
            self.assertEqual(summary["severity"], "warning")
            self.assertIn("disable_transport_wireguard", summary["active_disable_flags"])
            self.assertIn("disable_transport_wireguard", summary["active_mitigation_flags"])
            self.assertIn("disable_transport_wireguard", summary["mitigation_flag_expires_at"])
            self.assertEqual(summary["primary_transport_issue"]["transport"], "wireguard")
            self.assertTrue(summary["primary_transport_issue"]["disabled"])

    def test_incident_summary_exposes_transport_focus_buckets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.record_transport_crash(
                "https",
                "backend crashed",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_CRASHED,
                threshold=1,
            )
            manager.record_transport_soft_failure(
                "wireguard",
                FailureClass.NETWORK_DOWN,
                FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
                threshold=5,
            )

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.CONNECTED,
                    selected_endpoint_id="edge-1",
                    selected_transport="https",
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
            )

            self.assertEqual(summary["transport_focus"][0]["transport"], "https")
            self.assertEqual(summary["transport_focus"][0]["crash_bucket"], "dataplane_backend_crashed")
            self.assertEqual(summary["transport_focus"][1]["soft_fail_bucket"], "network_down:dataplane_healthcheck_failed")

    def test_incident_summary_prioritizes_disabled_transport_issue_over_sorted_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.record_transport_soft_failure(
                "https",
                FailureClass.NETWORK_DOWN,
                FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
                threshold=5,
            )
            manager.apply_failure_mitigation(FailureClass.UDP_BLOCKED, transport="wireguard")

            summary = build_incident_summary(
                state_manager=manager,
                report=DummyReport(
                    state=SessionState.DEGRADED,
                    selected_endpoint_id="edge-1",
                    selected_transport="https",
                    failure_class=FailureClass.NETWORK_DOWN,
                ),
                recovery_report=DummyRecoveryReport(stale_marker_found=False),
                recovery_cleanup_enabled=False,
                simulated_stale_runtime_endpoint_id=None,
            )

            self.assertEqual(summary["transport_focus"][0]["transport"], "https")
            self.assertEqual(summary["primary_transport_issue"]["transport"], "wireguard")
            self.assertTrue(summary["primary_transport_issue"]["disabled"])


if __name__ == "__main__":
    unittest.main()
