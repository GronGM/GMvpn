from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vpn_client import cli
from vpn_client.config import canonical_manifest_bytes
from vpn_client.security import generate_keypair, sign_payload


class CliTests(unittest.TestCase):
    def test_cli_can_simulate_stale_runtime_and_export_bundle(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source_manifest = json.loads((root / "examples" / "demo_manifest.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = tmp_path / "demo_manifest.json"
            public_key = tmp_path / "demo_public_key.pem"
            source_manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(source_manifest))
            manifest.write_text(json.dumps(source_manifest), encoding="utf-8")
            public_key.write_bytes(public_pem)
            support_bundle = tmp_path / "bundle.json"
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest),
                "--public-key",
                str(public_key),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(support_bundle),
                "--platform",
                "simulated",
                "--dataplane",
                "null",
                "--simulate-stale-runtime-endpoint",
                "ru-spb-https-1",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            payload = json.loads(support_bundle.read_text(encoding="utf-8"))

            self.assertEqual(exit_code, 0)
            self.assertIn("simulated_stale_runtime_endpoint=ru-spb-https-1", stdout.getvalue())
            self.assertEqual(payload["events"][-1]["kind"], "incident_summary")
            self.assertEqual(payload["events"][-1]["session_state"], "connected")
            self.assertEqual(payload["events"][-1]["failure_class"], "none")
            self.assertEqual(payload["events"][-1]["incident_severity"], "warning")
            self.assertEqual(
                payload["events"][-1]["primary_transport_issue"],
                payload["extra"]["incident_summary"]["primary_transport_issue"],
            )
            self.assertIn("startup recovery handled a stale runtime marker", payload["events"][-1]["detail"])
            self.assertEqual(
                payload["extra"]["incident_summary"]["headline"],
                "startup recovery handled a stale runtime marker",
            )
            self.assertEqual(payload["extra"]["incident_summary"]["severity"], "warning")
            self.assertTrue(payload["extra"]["incident_summary"]["startup_recovery_triggered"])
            self.assertEqual(payload["extra"]["incident_summary"]["selected_transport"], "https")
            self.assertEqual(payload["extra"]["endpoint_selection"]["selected_endpoint_id"], "ru-spb-https-1")
            self.assertEqual(
                payload["extra"]["endpoint_selection"]["candidate_order"],
                ["ru-mow-1", "ru-spb-quic-1", "ru-spb-https-1"],
            )
            self.assertIn(
                "endpoint_selection_order=ru-mow-1,ru-spb-quic-1,ru-spb-https-1",
                stdout.getvalue(),
            )
            self.assertIn(
                "endpoint_selection_summary=selected ru-spb-https-1",
                stdout.getvalue(),
            )
            self.assertIn("ru-mow-1", payload["extra"]["incident_summary"]["cooling_down_endpoints"])
            self.assertEqual(payload["extra"]["incident_summary"]["last_crash_transport"], "https")
            self.assertEqual(
                payload["extra"]["incident_summary"]["recommended_action"],
                "Review the last crash reason and monitor the recovered transport for repeat failures.",
            )
            self.assertTrue(payload["extra"]["startup_recovery"]["cleanup_enabled"])
            self.assertTrue(payload["extra"]["startup_recovery"]["stale_marker_found"])
            self.assertEqual(payload["extra"]["startup_recovery"]["simulated_endpoint_id"], "ru-spb-https-1")
            self.assertIn("state penalty applied", payload["extra"]["startup_recovery"]["actions"])
            self.assertEqual(payload["extra"]["session_health_checks"], 0)
            self.assertFalse(payload["extra"]["session_health_auto_reconnect"])
            self.assertEqual(payload["extra"]["runtime_support"]["tier"], "development-only")
            self.assertFalse(payload["extra"]["runtime_support"]["in_mvp_scope"])
            self.assertEqual(payload["extra"]["dataplane_runtime"]["backend"], "null")
            self.assertEqual(payload["extra"]["dataplane_runtime"]["restart_count"], 0)
            self.assertEqual(
                payload["extra"]["transport_reenable_policy_resolved"]["https"]["retry_delay_seconds"],
                120,
            )
            self.assertEqual(
                payload["extra"]["transport_reenable_policy_resolved"]["https"]["max_retry_delay_seconds"],
                1800,
            )
            self.assertEqual(
                payload["extra"]["transport_failure_policy_resolved"]["https"]["crash_threshold"],
                1,
            )
            self.assertEqual(
                payload["extra"]["transport_failure_policy_resolved"]["https"]["soft_fail_threshold"],
                3,
            )
            self.assertEqual(
                payload["extra"]["transport_recovery"]["https"]["crash_reason"],
                "stale runtime marker recovered on startup",
            )
            self.assertEqual(
                payload["extra"]["transport_recovery"]["https"]["crash_bucket"],
                None,
            )
            self.assertEqual(payload["extra"]["transport_recovery"]["https"]["crash_streak"], 0)
            self.assertIn("dataplane_backend=null", stdout.getvalue())
            self.assertIn("dataplane_restarts=0", stdout.getvalue())

    def test_cli_prints_linux_reconciliation_summary_for_startup_recovery(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source_manifest = json.loads((root / "examples" / "demo_manifest.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = tmp_path / "demo_manifest.json"
            public_key = tmp_path / "demo_public_key.pem"
            source_manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(source_manifest))
            manifest.write_text(json.dumps(source_manifest), encoding="utf-8")
            public_key.write_bytes(public_pem)
            support_bundle = tmp_path / "bundle.json"
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest),
                "--public-key",
                str(public_key),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(support_bundle),
                "--platform",
                "linux",
                "--client-platform",
                "linux",
                "--dataplane",
                "xray-core",
                "--simulate-stale-runtime-endpoint",
                "ru-spb-https-1",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads(support_bundle.read_text(encoding="utf-8"))

            self.assertEqual(exit_code, 0)
            self.assertIn("linux_reconciliation_dry_run=True", output)
            self.assertTrue(payload["extra"]["startup_recovery"]["cleanup_enabled"])
            self.assertTrue(payload["extra"]["startup_recovery"]["stale_marker_found"])
            self.assertTrue(payload["extra"]["linux_reconciliation"]["dry_run"])
            missing_commands = payload["extra"]["linux_reconciliation"]["missing_commands"]
            expected_missing_line = f"linux_reconciliation_missing_commands={','.join(missing_commands)}"
            if missing_commands:
                self.assertIn(expected_missing_line, output)
            else:
                self.assertNotIn("linux_reconciliation_missing_commands=", output)

    def test_cli_prints_linux_execution_summary_for_preflight_failure(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source_manifest = json.loads((root / "examples" / "demo_manifest.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = tmp_path / "demo_manifest.json"
            public_key = tmp_path / "demo_public_key.pem"
            source_manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(source_manifest))
            manifest.write_text(json.dumps(source_manifest), encoding="utf-8")
            public_key.write_bytes(public_pem)
            support_bundle = tmp_path / "bundle.json"
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest),
                "--public-key",
                str(public_key),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(support_bundle),
                "--platform",
                "linux",
                "--client-platform",
                "linux",
                "--dataplane",
                "xray-core",
                "--apply-network-changes",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads(support_bundle.read_text(encoding="utf-8"))
            linux_execution = payload["extra"]["linux_execution"]

            self.assertEqual(exit_code, 1)
            self.assertEqual(linux_execution["action"], "apply")
            self.assertIn(f"linux_execution_action={linux_execution['action']}", output)
            failure_reason = linux_execution["failure_reason_code"]
            if failure_reason is not None:
                self.assertIn(f"linux_execution_failure_reason={failure_reason}", output)
            else:
                self.assertNotIn("linux_execution_failure_reason=", output)
            missing_commands = linux_execution["missing_commands"]
            expected_missing_line = f"linux_execution_missing_commands={','.join(missing_commands)}"
            if missing_commands:
                self.assertIn(expected_missing_line, output)
            else:
                self.assertNotIn("linux_execution_missing_commands=", output)

    def test_cli_prints_incident_summary_for_degraded_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {"support_bundle_enabled": True},
                "transport_policy": {
                    "preferred_order": ["quic"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "quic-1",
                        "host": "198.51.100.30",
                        "port": 443,
                        "transport": "quic",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {"simulated_failure": "tls"},
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            state_path = tmp_path / "state.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            state_path.write_text(
                json.dumps(
                    {
                        "endpoint_health": {},
                        "last_connected_endpoint_id": None,
                        "incident_flags": {},
                        "incident_flag_expires_at": {},
                        "transport_crash_streaks": {},
                        "transport_crash_buckets": {},
                        "transport_crash_reasons": {},
                        "transport_soft_fail_streaks": {},
                        "transport_soft_fail_buckets": {},
                        "transport_reenable_pending": {},
                        "transport_reenable_not_before": {},
                        "transport_reenable_fail_streaks": {},
                        "session_health_fail_streak": 1,
                        "session_health_fail_bucket": "tls_interference:tls_handshake_failed",
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(state_path),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "simulated",
                "--dataplane",
                "null",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 1)
            self.assertIn("incident_summary:", output)
            self.assertIn("session_health_checks=0", output)
            self.assertIn("runtime_support_tier=development-only", output)
            self.assertIn("severity=warning", output)
            self.assertIn("failure_class=tls_interference", output)
            self.assertIn("session_health_fail_streak=1", output)
            self.assertIn("session_health_fail_bucket=tls_interference:tls_handshake_failed", output)
            self.assertIn(
                "recommended_action=Try an alternate transport or resolver path and inspect local interference signals before retrying.",
                output,
            )
            self.assertNotIn("primary_transport_issue=", output)
            self.assertEqual(payload["events"][-1]["kind"], "incident_summary")
            self.assertEqual(payload["events"][-1]["failure_class"], "tls_interference")
            self.assertEqual(payload["events"][-1]["incident_severity"], "warning")
            self.assertIsNone(payload["events"][-1]["primary_transport_issue"])
            self.assertEqual(payload["extra"]["session_health_fail_streak"], 1)
            self.assertEqual(payload["extra"]["session_health_fail_bucket"], "tls_interference:tls_handshake_failed")

    def test_cli_resolves_manifest_session_health_policy_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {
                    "support_bundle_enabled": True,
                    "session_health_policy": {
                        "default": {"checks": 1, "auto_reconnect": False, "failure_threshold": 2},
                        "by_transport": {"https": {"auto_reconnect": True}},
                    },
                },
                "transport_policy": {
                    "preferred_order": ["https"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "https-1",
                        "host": "198.51.100.20",
                        "port": 443,
                        "transport": "https",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {},
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "simulated",
                "--dataplane",
                "null",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertIn("session_health_checks=1", output)
            self.assertIn("session_health_auto_reconnect=True", output)
            self.assertIn("session_health_failure_threshold=2", output)
            self.assertIn("runtime_support_tier=development-only", output)
            self.assertIn("runtime_marker_present=True", output)
            self.assertIn("last_connected_endpoint_id=https-1", output)
            self.assertEqual(payload["extra"]["session_health_checks"], 1)
            self.assertTrue(payload["extra"]["session_health_auto_reconnect"])
            self.assertEqual(payload["extra"]["session_health_failure_threshold"], 2)
            self.assertEqual(payload["extra"]["runtime_support"]["tier"], "development-only")
            self.assertTrue(payload["extra"]["runtime_marker_present"])
            self.assertEqual(payload["extra"]["last_connected_endpoint_id"], "https-1")
            self.assertEqual(payload["extra"]["session_health_policy_resolved"]["checks"], 1)
            self.assertEqual(payload["extra"]["session_health_policy_resolved"]["failure_threshold"], 2)

    def test_cli_marks_linux_xray_runtime_as_mvp_supported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {"support_bundle_enabled": True},
                "platform_capabilities": {
                    "linux": {
                        "platform": "linux",
                        "supported_dataplanes": ["xray-core", "routed"],
                        "network_adapter": "linux",
                        "status": "mvp-supported",
                        "notes": "Primary MVP contour.",
                    }
                },
                "transport_policy": {
                    "preferred_order": ["https"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "desktop-1",
                        "host": "198.51.100.50",
                        "port": 443,
                        "transport": "https",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {
                            "dataplane": "xray-core",
                            "xray_protocol": "vless",
                            "xray_user_id": "11111111-1111-1111-1111-111111111111",
                            "xray_stream_network": "tcp",
                            "xray_security": "tls",
                            "xray_server_name": "cdn.example.net",
                            "supported_client_platforms": ["linux"],
                        },
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "linux",
                "--client-platform",
                "linux",
                "--dataplane",
                "xray-core",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertIn("runtime_support_tier=mvp-supported", output)
            self.assertIn("runtime_support_in_mvp_scope=True", output)
            self.assertEqual(payload["extra"]["runtime_support"]["tier"], "mvp-supported")
            self.assertTrue(payload["extra"]["runtime_support"]["in_mvp_scope"])
            self.assertEqual(payload["extra"]["runtime_support"]["declared_platform_capability"]["status"], "mvp-supported")

    def test_cli_marks_linux_xray_runtime_as_contract_mismatch_when_manifest_disagrees(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {"support_bundle_enabled": True},
                "platform_capabilities": {
                    "linux": {
                        "platform": "linux",
                        "supported_dataplanes": ["linux-userspace", "routed"],
                        "network_adapter": "linux",
                        "status": "prototype",
                        "notes": "Older contour declaration.",
                    }
                },
                "transport_policy": {
                    "preferred_order": ["https"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "desktop-1",
                        "host": "198.51.100.50",
                        "port": 443,
                        "transport": "https",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {
                            "dataplane": "xray-core",
                            "xray_protocol": "vless",
                            "xray_user_id": "11111111-1111-1111-1111-111111111111",
                            "xray_stream_network": "tcp",
                            "xray_security": "tls",
                            "xray_server_name": "cdn.example.net",
                            "supported_client_platforms": ["linux"],
                        },
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "linux",
                "--client-platform",
                "linux",
                "--dataplane",
                "xray-core",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertIn("runtime_support_tier=contract-mismatch", output)
            self.assertIn(
                "runtime_support_summary=repository MVP contour was selected, but the manifest support contract does not declare the same release contour",
                output,
            )
            self.assertIn(
                "runtime_support_caveats=manifest platform_capabilities for linux do not declare dataplane 'xray-core' | manifest platform_capabilities do not mark the linux xray contour as mvp-supported",
                output,
            )
            self.assertEqual(payload["extra"]["runtime_support"]["tier"], "contract-mismatch")
            self.assertEqual(
                payload["extra"]["runtime_support"]["summary"],
                "repository MVP contour was selected, but the manifest support contract does not declare the same release contour",
            )
            self.assertFalse(payload["extra"]["runtime_support"]["in_mvp_scope"])
            self.assertEqual(
                payload["extra"]["runtime_support"]["caveats"],
                [
                    "manifest platform_capabilities for linux do not declare dataplane 'xray-core'",
                    "manifest platform_capabilities do not mark the linux xray contour as mvp-supported",
                ],
            )

    def test_cli_blocks_runtime_contract_mismatch_when_manifest_requires_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {
                    "support_bundle_enabled": True,
                    "runtime_support_policy": {
                        "default": {"enforce_contract_match": True},
                    },
                },
                "platform_capabilities": {
                    "linux": {
                        "platform": "linux",
                        "supported_dataplanes": ["linux-userspace", "routed"],
                        "network_adapter": "linux",
                        "status": "prototype",
                        "notes": "Older contour declaration.",
                    }
                },
                "transport_policy": {
                    "preferred_order": ["https"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "desktop-1",
                        "host": "198.51.100.50",
                        "port": 443,
                        "transport": "https",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {
                            "dataplane": "xray-core",
                            "xray_protocol": "vless",
                            "xray_user_id": "11111111-1111-1111-1111-111111111111",
                            "xray_stream_network": "tcp",
                            "xray_security": "tls",
                            "xray_server_name": "cdn.example.net",
                            "supported_client_platforms": ["linux"],
                        },
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            support_bundle = tmp_path / "bundle.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(support_bundle),
                "--platform",
                "linux",
                "--client-platform",
                "linux",
                "--dataplane",
                "xray-core",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads(support_bundle.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 2)
            self.assertIn("runtime_support_gate_blocked=true", output)
            self.assertTrue(payload["extra"]["runtime_support_policy_resolved"]["enforce_contract_match"])
            self.assertFalse(payload["extra"]["runtime_support_policy_resolved"]["allow_contract_mismatch"])
            self.assertTrue(payload["extra"]["runtime_support_policy_resolved"]["gate_blocked"])

    def test_cli_uses_manifest_runtime_tick_policy_without_local_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {
                    "support_bundle_enabled": True,
                    "runtime_tick_policy": {
                        "default": {"reevaluate_pending_transports_limit": 2},
                    },
                },
                "transport_policy": {
                    "preferred_order": ["https"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "https-1",
                        "host": "198.51.100.20",
                        "port": 443,
                        "transport": "https",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {},
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            support_bundle = tmp_path / "bundle.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            state_path = tmp_path / "state.json"
            state_path.write_text(
                json.dumps(
                    {
                        "endpoint_health": {},
                        "last_connected_endpoint_id": None,
                        "incident_flags": {"disable_transport_https": False},
                        "incident_flag_expires_at": {"disable_transport_https": "2020-01-01T00:00:00+00:00"},
                        "transport_crash_streaks": {},
                        "transport_crash_buckets": {},
                        "transport_crash_reasons": {},
                        "transport_soft_fail_streaks": {},
                        "transport_soft_fail_buckets": {},
                        "transport_reenable_pending": {"https": True},
                        "transport_reenable_not_before": {"https": "2020-01-01T00:00:00+00:00"},
                        "transport_reenable_fail_streaks": {},
                        "session_health_fail_streak": 0,
                        "session_health_fail_bucket": "",
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(state_path),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(support_bundle),
                "--platform",
                "simulated",
                "--dataplane",
                "null",
                "--runtime-ticks",
                "1",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads(support_bundle.read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertIn("runtime_tick_reevaluate_pending_transports_limit=2", output)
            self.assertEqual(
                payload["extra"]["runtime_tick_policy_resolved"]["reevaluate_pending_transports_limit"],
                2,
            )

    def test_cli_uses_local_incident_guidance_file_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {
                    "support_bundle_enabled": True,
                    "incident_guidance_overrides": {
                        "tls_interference": {
                            "severity": "warning",
                            "recommended_action": "Manifest guidance should lose to local.",
                        }
                    },
                },
                "transport_policy": {
                    "preferred_order": ["quic"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "quic-1",
                        "host": "198.51.100.30",
                        "port": 443,
                        "transport": "quic",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {"simulated_failure": "tls"},
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            local_guidance_path = tmp_path / "incident-guidance.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            local_guidance_path.write_text(
                json.dumps(
                    {
                        "tls_interference": {
                            "severity": "critical",
                            "recommended_action": "Local operator guidance wins.",
                        }
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--incident-guidance-file",
                str(local_guidance_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "simulated",
                "--dataplane",
                "null",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 1)
            self.assertIn("severity=critical", output)
            self.assertIn("recommended_action=Local operator guidance wins.", output)
            self.assertTrue(payload["extra"]["local_incident_guidance_overrides_present"])
            self.assertEqual(payload["extra"]["incident_summary"]["severity"], "critical")
            self.assertEqual(payload["extra"]["incident_summary"]["recommended_action"], "Local operator guidance wins.")

    def test_cli_auto_loads_local_guidance_from_cache_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            cache_dir = tmp_path / "cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {"support_bundle_enabled": True},
                "transport_policy": {
                    "preferred_order": ["quic"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "quic-1",
                        "host": "198.51.100.30",
                        "port": 443,
                        "transport": "quic",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {"simulated_failure": "tls"},
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            auto_guidance_path = cache_dir / "incident-guidance.json"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            auto_guidance_path.write_text(
                json.dumps(
                    {
                        "tls_interference": {
                            "severity": "critical",
                            "recommended_action": "Auto-loaded local guidance.",
                        }
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()

            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(cache_dir),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "simulated",
                "--dataplane",
                "null",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 1)
            self.assertIn(f"incident_guidance_source={auto_guidance_path}", output)
            self.assertTrue(payload["extra"]["local_incident_guidance_overrides_present"])
            self.assertEqual(payload["extra"]["local_incident_guidance_source"], str(auto_guidance_path))
            self.assertEqual(payload["extra"]["incident_summary"]["recommended_action"], "Auto-loaded local guidance.")

    def test_cli_ios_routed_runtime_reaches_bridge_contract_stage(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = {
                "version": 1,
                "generated_at": "2026-04-23T00:00:00Z",
                "expires_at": "2026-04-30T00:00:00Z",
                "features": {"support_bundle_enabled": True},
                "platform_capabilities": {
                    "ios": {
                        "platform": "ios",
                        "supported_dataplanes": ["ios-bridge", "routed"],
                        "network_adapter": "ios",
                        "status": "planned",
                        "notes": "Bridge only",
                    }
                },
                "transport_policy": {
                    "preferred_order": ["https"],
                    "connect_timeout_ms": 2500,
                    "retry_budget": 1,
                    "probe_timeout_ms": 1000,
                },
                "network_policy": {
                    "tunnel_mode": "full",
                    "dns_mode": "vpn_only",
                    "kill_switch_enabled": True,
                    "ipv6_enabled": False,
                    "allow_lan_while_connected": False,
                },
                "endpoints": [
                    {
                        "id": "ios-1",
                        "host": "198.51.100.20",
                        "port": 443,
                        "transport": "https",
                        "region": "eu-central",
                        "tags": [],
                        "metadata": {
                            "dataplane": "ios-bridge",
                            "xray_protocol": "vless",
                            "xray_user_id": "11111111-1111-1111-1111-111111111111",
                            "xray_stream_network": "ws",
                            "xray_security": "tls",
                            "xray_server_name": "cdn.example.net",
                            "xray_ws_path": "/edge",
                            "xray_ws_host": "cdn.example.net",
                        },
                    }
                ],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
            manifest_path = tmp_path / "manifest.json"
            public_key_path = tmp_path / "public.pem"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            public_key_path.write_bytes(public_pem)
            stdout = io.StringIO()
            argv = [
                "vpn-client",
                "--manifest",
                str(manifest_path),
                "--public-key",
                str(public_key_path),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--ios-contract-dir",
                str(tmp_path / "ios-bridge"),
                "--platform",
                "simulated",
                "--client-platform",
                "ios",
                "--dataplane",
                "routed",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            self.assertEqual(exit_code, 1)
            self.assertTrue((tmp_path / "ios-bridge" / "ios-1.json").exists())
            self.assertIn("incident_summary:", output)
            self.assertIn("endpoint_selection_summary=selected ios-1", output)
            self.assertIn("runtime_support_tier=development-only", output)
            self.assertIn(
                "primary_transport_issue=https disabled=False pending_reenable=False crash_bucket=None soft_fail_bucket=unknown:dataplane_backend_unsupported",
                output,
            )
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["events"][-1]["incident_severity"], "critical")
            self.assertEqual(payload["events"][-1]["primary_transport_issue"]["transport"], "https")
            self.assertEqual(payload["extra"]["selected_endpoint_id"], "ios-1")
            self.assertEqual(payload["extra"]["endpoint_selection"]["client_platform"], "ios")
            self.assertEqual(payload["extra"]["endpoint_selection"]["candidate_order"], ["ios-1"])
            self.assertEqual(payload["extra"]["runtime_support"]["client_platform"], "ios")
            self.assertEqual(payload["extra"]["runtime_support"]["tier"], "development-only")
            self.assertEqual(
                payload["extra"]["runtime_support"]["declared_platform_capability"]["network_adapter"],
                "ios",
            )
            self.assertEqual(
                payload["extra"]["runtime_support"]["declared_platform_capability"]["supported_dataplanes"],
                ["ios-bridge", "routed"],
            )
            self.assertEqual(payload["extra"]["dataplane_runtime"]["backend"], "routed")
            self.assertIsNone(payload["extra"]["dataplane_runtime"]["active_backend"])

    def test_cli_provider_profile_selects_platform_specific_endpoint(self) -> None:
        root = Path(__file__).resolve().parents[1]
        source_manifest = json.loads((root / "examples" / "provider_profile_manifest.json").read_text(encoding="utf-8"))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            private_pem, public_pem = generate_keypair()
            manifest = tmp_path / "provider_profile_manifest.json"
            public_key = tmp_path / "demo_public_key.pem"
            source_manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(source_manifest))
            manifest.write_text(json.dumps(source_manifest), encoding="utf-8")
            public_key.write_bytes(public_pem)
            stdout = io.StringIO()
            argv = [
                "vpn-client",
                "--manifest",
                str(manifest),
                "--public-key",
                str(public_key),
                "--cache-dir",
                str(tmp_path / "cache"),
                "--state-file",
                str(tmp_path / "state.json"),
                "--runtime-marker",
                str(tmp_path / "runtime-marker.json"),
                "--backend-state-file",
                str(tmp_path / "backend-state.json"),
                "--support-bundle",
                str(tmp_path / "bundle.json"),
                "--platform",
                "simulated",
                "--client-platform",
                "android",
                "--dataplane",
                "routed",
            ]

            with patch("sys.argv", argv), contextlib.redirect_stdout(stdout):
                exit_code = cli.main()

            output = stdout.getvalue()
            payload = json.loads((tmp_path / "bundle.json").read_text(encoding="utf-8"))
            self.assertEqual(exit_code, 0)
            self.assertIn("endpoint=spb-main-desktop", output)
            self.assertIn("dataplane_backend=xray-core", output)
            self.assertIn("runtime_support_tier=development-only", output)
            self.assertIn("endpoint_selection_summary=selected spb-main-desktop", output)
            self.assertEqual(payload["extra"]["selected_endpoint_id"], "spb-main-desktop")
            self.assertEqual(payload["extra"]["endpoint_selection"]["client_platform"], "android")
            self.assertEqual(
                payload["extra"]["endpoint_selection"]["candidate_order"],
                ["spb-main-desktop", "spb-main-android-alt"],
            )
            self.assertEqual(payload["extra"]["runtime_support"]["client_platform"], "android")
            self.assertEqual(payload["extra"]["runtime_support"]["tier"], "development-only")
            self.assertEqual(
                payload["extra"]["runtime_support"]["declared_platform_capability"]["network_adapter"],
                "android",
            )
            self.assertEqual(
                payload["extra"]["runtime_support"]["declared_platform_capability"]["supported_dataplanes"],
                ["xray-core", "routed"],
            )
            self.assertEqual(payload["extra"]["dataplane_runtime"]["backend"], "xray-core")
            self.assertEqual(payload["extra"]["dataplane_runtime"]["active_backend"], "xray-core")
            self.assertEqual(payload["extra"]["dataplane_runtime"]["router_backend"], "routed")
            self.assertEqual(payload["extra"]["dataplane_runtime"]["client_platform"], "android")


if __name__ == "__main__":
    unittest.main()
