from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "release_guardrail.py"
SPEC = importlib.util.spec_from_file_location("release_guardrail", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
release_guardrail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_guardrail)


class ReleaseGuardrailTests(unittest.TestCase):
    def test_check_required_snippets_reports_missing_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "checklist.md"
            sample.write_text("alpha\nbeta\n", encoding="utf-8")

            original_root = release_guardrail.ROOT
            try:
                release_guardrail.ROOT = root
                failures = release_guardrail._check_required_snippets(sample, ("alpha", "gamma"))
            finally:
                release_guardrail.ROOT = original_root

        self.assertEqual(failures, ["checklist.md is missing: gamma"])

    def test_linux_xray_smoke_gate_passes_for_repo_demo_manifest(self) -> None:
        failures = release_guardrail._check_linux_xray_smoke_gate()
        self.assertEqual(failures, [])

    def test_linux_xray_smoke_gate_reports_runtime_support_regression(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            examples = root / "examples"
            examples.mkdir(parents=True, exist_ok=True)
            sample = examples / "demo_manifest.json"
            sample.write_text(
                """
                {
                  "platform_capabilities": {
                    "linux": {
                      "platform": "linux",
                      "supported_dataplanes": ["xray-core"],
                      "network_adapter": "linux",
                      "startup_reconciliation": true,
                      "status": "prototype"
                    }
                  },
                  "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": true,
                    "ipv6_enabled": false,
                    "allow_lan_while_connected": false
                  },
                  "endpoints": [
                    {
                      "id": "edge-1",
                      "host": "198.51.100.20",
                      "port": 443,
                      "transport": "https",
                      "region": "eu-central",
                      "metadata": {
                        "dataplane": "xray-core",
                        "xray_protocol": "vless",
                        "xray_user_id": "11111111-1111-1111-1111-111111111111",
                        "xray_stream_network": "tcp",
                        "xray_security": "tls",
                        "xray_server_name": "cdn.example.net"
                      }
                    }
                  ]
                }
                """,
                encoding="utf-8",
            )

            original_root = release_guardrail.ROOT
            original_demo_manifest = release_guardrail.DEMO_MANIFEST
            try:
                release_guardrail.ROOT = root
                release_guardrail.DEMO_MANIFEST = sample
                failures = release_guardrail._check_linux_xray_smoke_gate()
            finally:
                release_guardrail.ROOT = original_root
                release_guardrail.DEMO_MANIFEST = original_demo_manifest

        self.assertEqual(
            failures,
            [
                "linux+xray smoke gate: runtime support no longer assesses linux + xray-core + linux adapter as mvp-supported"
            ],
        )

    def test_parse_cli_output_collects_release_facing_fields(self) -> None:
        parsed = release_guardrail._parse_cli_output(
            "\n".join(
                [
                    "state=SessionState.FAILED",
                    "session_health_checks=0",
                    "session_health_auto_reconnect=False",
                    "session_health_failure_threshold=2",
                    "runtime_tick_reevaluate_pending_transports_limit=2",
                    "runtime_support_tier=development-only",
                    "runtime_support_in_mvp_scope=False",
                    "incident_summary:",
                    "  - severity=warning",
                    "  - failure_class=tls_interference",
                    "  - primary_transport_issue=quic disabled=False pending_reenable=False crash_bucket=None soft_fail_bucket=tls_interference:tls_handshake_failed",
                ]
            )
        )

        self.assertEqual(parsed["session_health_failure_threshold"], "2")
        self.assertEqual(parsed["runtime_tick_reevaluate_pending_transports_limit"], "2")
        self.assertEqual(parsed["incident_summary"]["severity"], "warning")
        self.assertEqual(parsed["incident_summary"]["primary_transport_issue"]["transport"], "quic")
        self.assertEqual(
            parsed["incident_summary"]["primary_transport_issue"]["soft_fail_bucket"],
            "tls_interference:tls_handshake_failed",
        )

    def test_release_artifact_policy_parity_passes(self) -> None:
        failures = release_guardrail._check_release_artifact_policy()
        self.assertEqual(failures, [])

    def test_parse_incident_telemetry_detail_extracts_narrative_fields(self) -> None:
        parsed = release_guardrail._parse_incident_telemetry_detail(
            "warning: session did not connect and needs investigation; Retry using a transport on a different protocol or port profile and verify upstream filtering."
        )

        self.assertEqual(
            parsed,
            {
                "severity": "warning",
                "headline": "session did not connect and needs investigation",
                "recommended_action": (
                    "Retry using a transport on a different protocol or port profile and verify upstream filtering."
                ),
            },
        )

    def test_incident_narrative_consistency_passes(self) -> None:
        failures = release_guardrail._check_incident_narrative_consistency()
        self.assertEqual(failures, [])

    def test_structural_artifact_parity_passes(self) -> None:
        failures = release_guardrail._check_structural_artifact_parity()
        self.assertEqual(failures, [])

    def test_operational_tail_parity_passes(self) -> None:
        failures = release_guardrail._check_operational_tail_parity()
        self.assertEqual(failures, [])


if __name__ == "__main__":
    unittest.main()
