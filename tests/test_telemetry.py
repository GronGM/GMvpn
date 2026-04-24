from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vpn_client.models import FailureClass, FailureReasonCode, SessionState
from vpn_client.telemetry import TelemetryRecorder


class TelemetryRecorderTests(unittest.TestCase):
    def test_export_support_bundle_writes_bounded_events(self) -> None:
        recorder = TelemetryRecorder(max_events=2)
        recorder.record("a", SessionState.LOADING)
        recorder.record("b", SessionState.CONNECTING, endpoint_id="edge-1")
        recorder.record(
            "c",
            SessionState.DEGRADED,
            FailureClass.TLS_INTERFERENCE,
            reason_code=FailureReasonCode.TLS_HANDSHAKE_FAILED,
            incident_severity="warning",
            primary_transport_issue={
                "transport": "quic",
                "disabled": False,
                "pending_reenable": False,
                "crash_bucket": None,
                "soft_fail_bucket": "unknown:tls_handshake_failed",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = recorder.export_support_bundle(Path(tmp) / "bundle.json", extra={"version": 1})
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(len(payload["events"]), 2)
        self.assertEqual(payload["events"][0]["kind"], "b")
        self.assertEqual(payload["events"][1]["failure_class"], "tls_interference")
        self.assertEqual(payload["events"][1]["reason_code"], "tls_handshake_failed")
        self.assertEqual(payload["events"][1]["incident_severity"], "warning")
        self.assertEqual(payload["events"][1]["primary_transport_issue"]["transport"], "quic")
        self.assertEqual(payload["extra"]["version"], 1)

    def test_export_support_bundle_redacts_sensitive_extra_fields(self) -> None:
        recorder = TelemetryRecorder()
        recorder.record(
            "dataplane_failed",
            SessionState.DEGRADED,
            FailureClass.NETWORK_DOWN,
            reason_code=FailureReasonCode.DATAPLANE_BACKEND_CRASHED,
            detail="authorization=Bearer super-secret-token password=hunter2",
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = recorder.export_support_bundle(
                Path(tmp) / "bundle.json",
                extra={
                    "dataplane_runtime": {
                        "stdout_tail": "boot ok " + ("x" * 300),
                        "stderr_tail": (
                            "password=hunter2 "
                            "token=abcd1234 "
                            "11111111-1111-1111-1111-111111111111 "
                            + ("y" * 220)
                        ),
                    },
                    "backend_state_record": {
                        "token": "abcd1234",
                        "authorization": "Bearer super-secret-token",
                    },
                },
            )
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertIn("authorization=[redacted]", payload["events"][0]["detail"])
        self.assertIn("password=[redacted]", payload["events"][0]["detail"])
        self.assertEqual(payload["extra"]["backend_state_record"]["token"], "[redacted]")
        self.assertEqual(payload["extra"]["backend_state_record"]["authorization"], "[redacted]")
        self.assertIn("password=[redacted]", payload["extra"]["dataplane_runtime"]["stderr_tail"])
        self.assertIn("token=[redacted]", payload["extra"]["dataplane_runtime"]["stderr_tail"])
        self.assertIn("[redacted-uuid]", payload["extra"]["dataplane_runtime"]["stderr_tail"])
        self.assertLessEqual(len(payload["extra"]["dataplane_runtime"]["stdout_tail"]), 200)
        self.assertLessEqual(len(payload["extra"]["dataplane_runtime"]["stderr_tail"]), 200)


if __name__ == "__main__":
    unittest.main()
