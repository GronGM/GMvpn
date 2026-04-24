from __future__ import annotations

import unittest
import tempfile
import time
from pathlib import Path

from vpn_client.backend_state import BackendStateStore
from vpn_client.client_platform import ClientPlatform
from vpn_client.dataplane import BackendProcessSupervisor, DataPlaneError, LinuxUserspaceDataPlane, RoutedDataPlane
from vpn_client.ios_bridge import (
    IOSBridgeState,
    IOSBridgeConfigError,
    IOSBridgeConfigRenderer,
    IOSBridgeDataPlane,
    build_ios_bridge_request,
)
from vpn_client.models import Endpoint
from vpn_client.process_adapter import LocalProcessAdapter
from vpn_client.xray import XrayConfigError, XrayConfigRenderer, XrayCoreDataPlane


class LinuxUserspaceDataPlaneTests(unittest.TestCase):
    def test_dataplane_starts_in_dry_run_mode(self) -> None:
        backend = LinuxUserspaceDataPlane(interface_name="tun42", dry_run=True)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
        )

        session = backend.connect(endpoint)

        self.assertEqual(session.backend_name, "linux-userspace")
        self.assertTrue(session.dry_run)
        self.assertTrue(session.active)

    def test_dataplane_health_failure_is_reported(self) -> None:
        backend = LinuxUserspaceDataPlane(interface_name="tun42", dry_run=True)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
            metadata={"dataplane_failure": "health"},
        )

        backend.connect(endpoint)
        with self.assertRaises(DataPlaneError):
            backend.health_check(endpoint)

    def test_dataplane_supervisor_tracks_pid_and_crash(self) -> None:
        supervisor = BackendProcessSupervisor()
        backend = LinuxUserspaceDataPlane(interface_name="tun42", dry_run=True, supervisor=supervisor)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
            metadata={"dataplane_failure": "crash"},
        )

        session = backend.connect(endpoint)
        self.assertIsNotNone(session.pid)

        with self.assertRaises(DataPlaneError):
            backend.health_check(endpoint)

        snapshot = backend.runtime_snapshot()
        self.assertTrue(snapshot["crashed"])
        self.assertEqual(snapshot["crash_reason"], "simulated backend crash")
        self.assertEqual(snapshot["last_exit_code"], 137)

    def test_dataplane_persists_backend_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = BackendStateStore(Path(tmp) / "backend-state.json")
            backend = LinuxUserspaceDataPlane(interface_name="tun42", dry_run=True, state_store=store)
            endpoint = Endpoint(
                id="edge-1",
                host="198.51.100.20",
                port=443,
                transport="https",
                region="eu-central",
            )

            backend.connect(endpoint)
            backend.disconnect()

            record = store.load()
            self.assertEqual(record.backend, "linux-userspace")
            self.assertEqual(record.endpoint_id, "edge-1")
            self.assertFalse(record.active)

    def test_backend_state_store_recovers_from_corrupted_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backend-state.json"
            path.write_text("{bad json", encoding="utf-8")
            store = BackendStateStore(path)

            self.assertIsNone(store.load())
            self.assertFalse(path.exists())

    def test_backend_state_store_recovers_from_invalid_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "backend-state.json"
            path.write_text('{"backend":"linux-userspace"}', encoding="utf-8")
            store = BackendStateStore(path)

            self.assertIsNone(store.load())
            self.assertFalse(path.exists())

    def test_real_process_adapter_captures_output(self) -> None:
        adapter = LocalProcessAdapter()
        supervisor = BackendProcessSupervisor(process_adapter=adapter)
        backend = LinuxUserspaceDataPlane(interface_name="tun42", dry_run=False, supervisor=supervisor)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
            metadata={
                "dataplane_command": [
                    "python",
                    "-c",
                    "import sys,time; print('boot ok'); sys.stdout.flush(); sys.stderr.write('warn\\n'); sys.stderr.flush(); time.sleep(0.5)",
                ]
            },
        )

        session = backend.connect(endpoint)
        time.sleep(0.1)
        snapshot = backend.runtime_snapshot()

        self.assertEqual(session.pid, snapshot["pid"])
        self.assertIn("boot ok", snapshot["stdout_tail"])
        self.assertIn("warn", snapshot["stderr_tail"])
        backend.disconnect()


class XrayCoreDataPlaneTests(unittest.TestCase):
    def test_renderer_builds_vless_reality_config(self) -> None:
        endpoint = Endpoint(
            id="edge-ru-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "tcp",
                "xray_security": "reality",
                "xray_server_name": "cdn.example.net",
                "xray_fingerprint": "chrome",
                "xray_reality_public_key": "pubkey",
                "xray_reality_short_id": "abcd1234",
            },
        )

        renderer = XrayConfigRenderer(interface_name="tun42")
        config = renderer.render(endpoint)

        self.assertEqual(config["inbounds"][0]["settings"]["name"], "tun42")
        self.assertEqual(config["outbounds"][0]["protocol"], "vless")
        self.assertEqual(config["outbounds"][0]["streamSettings"]["security"], "reality")
        self.assertEqual(
            config["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"],
            "pubkey",
        )

    def test_renderer_requires_identity_material(self) -> None:
        endpoint = Endpoint(
            id="edge-ru-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "xray_protocol": "vless",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
            },
        )

        renderer = XrayConfigRenderer()
        with self.assertRaises(XrayConfigError):
            renderer.render(endpoint)

    def test_xray_dataplane_writes_config_and_cleans_up(self) -> None:
        endpoint = Endpoint(
            id="edge-ru-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "ws",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
                "xray_ws_path": "/edge",
                "xray_ws_host": "cdn.example.net",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            backend = XrayCoreDataPlane(
                interface_name="tun42",
                dry_run=True,
                config_dir=Path(tmp),
                binary_path="xray-test",
            )

            session = backend.connect(endpoint)
            snapshot = backend.runtime_snapshot()

            self.assertEqual(session.backend_name, "xray-core")
            self.assertEqual(snapshot["command"][0], "xray-test")
            self.assertTrue(Path(snapshot["config_path"]).exists())

            backend.disconnect()
            self.assertIsNone(backend.runtime_snapshot()["config_path"])

    def test_xray_dataplane_persists_backend_state(self) -> None:
        endpoint = Endpoint(
            id="edge-ru-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "xray_protocol": "trojan",
                "xray_password": "secret",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            store = BackendStateStore(Path(tmp) / "backend-state.json")
            backend = XrayCoreDataPlane(
                interface_name="tun42",
                dry_run=True,
                config_dir=Path(tmp) / "xray",
                state_store=store,
            )

            backend.connect(endpoint)
            backend.disconnect()

            record = store.load()
            self.assertEqual(record.backend, "xray-core")
            self.assertEqual(record.endpoint_id, "edge-ru-1")
