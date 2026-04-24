from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vpn_client.models import FailureClass, FailureReasonCode
from vpn_client.state import StateManager, StateStore


class StateManagerTests(unittest.TestCase):
    def test_state_manager_persists_incident_flags_and_scores(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.set_incident_flag("force_system_dns_fallback", True)
            manager.mark_failure("edge-1", FailureClass.TLS_INTERFERENCE, "tls blocked")
            manager.mark_success("edge-1")

            reloaded = StateManager(StateStore(Path(tmp) / "state.json"))
            self.assertTrue(reloaded.incident_flag("force_system_dns_fallback"))
            self.assertEqual(reloaded.state.last_connected_endpoint_id, "edge-1")
            self.assertGreaterEqual(reloaded.score_for("edge-1"), 0)

    def test_failure_puts_endpoint_into_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.mark_failure("edge-1", FailureClass.TLS_INTERFERENCE, "tls blocked")

            self.assertTrue(manager.is_cooling_down("edge-1"))
            future = datetime.now(timezone.utc) + timedelta(hours=1)
            self.assertFalse(manager.is_cooling_down("edge-1", now=future))

    def test_transport_disable_flag_expires(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)

            self.assertTrue(manager.incident_flag("disable_transport_https"))
            manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"
            self.assertFalse(manager.incident_flag("disable_transport_https"))
            self.assertTrue(manager.transport_reenable_pending("https"))

    def test_transport_reenable_probe_respects_not_before(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.mark_transport_reenable_pending("https", True)
            manager.schedule_transport_reenable_probe("https", base_delay_seconds=60)

            self.assertFalse(manager.transport_reenable_ready("https"))

    def test_transport_reenable_failures_escalate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            manager.fail_transport_reenable("https", retry_delay_seconds=60)
            first_expiry = manager.state.incident_flag_expires_at["disable_transport_https"]
            manager.state.incident_flags["disable_transport_https"] = False
            manager.fail_transport_reenable("https", retry_delay_seconds=60)
            second_expiry = manager.state.incident_flag_expires_at["disable_transport_https"]

            self.assertEqual(manager.transport_reenable_fail_streak("https"), 2)
            self.assertGreater(second_expiry, first_expiry)

    def test_transport_reenable_failures_respect_max_retry_delay(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))
            for _ in range(4):
                manager.fail_transport_reenable(
                    "https",
                    retry_delay_seconds=120,
                    max_retry_delay_seconds=300,
                )
                manager.state.incident_flags["disable_transport_https"] = False

            expiry = datetime.fromisoformat(manager.state.incident_flag_expires_at["disable_transport_https"])
            now = datetime.now(timezone.utc)

            self.assertLessEqual((expiry - now).total_seconds(), 310)

    def test_stale_runtime_penalizes_endpoint_and_increments_transport_crash_streak(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            transport_disabled = manager.mark_stale_runtime("edge-1", "https")

            self.assertFalse(transport_disabled)
            self.assertTrue(manager.is_cooling_down("edge-1"))
            self.assertEqual(manager.transport_crash_streak("https"), 1)
            self.assertEqual(manager.transport_crash_reason("https"), "stale runtime marker recovered on startup")
            self.assertFalse(manager.incident_flag("disable_transport_https"))

    def test_clear_transport_crash_streak_keeps_last_crash_reason_for_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            manager.record_transport_crash("https", "userspace backend crashed", threshold=1)
            manager.clear_transport_crash_streak("https")

            self.assertEqual(manager.transport_crash_streak("https"), 0)
            self.assertEqual(manager.transport_crash_reason("https"), "userspace backend crashed")

    def test_dns_interference_enables_temporary_system_dns_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            actions = manager.apply_failure_mitigation(FailureClass.DNS_INTERFERENCE)

            self.assertEqual(actions, ["force_system_dns_fallback"])
            self.assertTrue(manager.incident_flag("force_system_dns_fallback"))

    def test_udp_blocked_temporarily_disables_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            actions = manager.apply_failure_mitigation(FailureClass.UDP_BLOCKED, transport="wireguard")

            self.assertEqual(actions, ["disable_transport_wireguard"])
            self.assertTrue(manager.incident_flag("disable_transport_wireguard"))

    def test_transport_soft_failure_resets_streak_when_reason_changes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            first = manager.record_transport_soft_failure(
                "https",
                FailureClass.NETWORK_DOWN,
                FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
            )
            second = manager.record_transport_soft_failure(
                "https",
                FailureClass.NETWORK_DOWN,
                FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
            )
            third = manager.record_transport_soft_failure(
                "https",
                FailureClass.NETWORK_DOWN,
                FailureReasonCode.DATAPLANE_SESSION_INACTIVE,
            )

            self.assertFalse(first)
            self.assertFalse(second)
            self.assertFalse(third)
            self.assertEqual(manager.transport_soft_fail_streak("https"), 1)
            self.assertEqual(
                manager.state.transport_soft_fail_buckets["https"],
                "network_down:dataplane_session_inactive",
            )

    def test_session_health_failure_clears_after_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            manager = StateManager(StateStore(Path(tmp) / "state.json"))

            confirmed = manager.record_session_health_failure(
                FailureClass.NETWORK_DOWN,
                FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
                threshold=2,
            )
            self.assertFalse(confirmed)
            self.assertTrue(manager.clear_session_health_failure())
            self.assertEqual(manager.state.session_health_fail_streak, 0)
            self.assertEqual(manager.state.session_health_fail_bucket, "")


if __name__ == "__main__":
    unittest.main()
