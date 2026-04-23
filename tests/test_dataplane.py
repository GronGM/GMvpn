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
            self.assertFalse(record.active)


class RoutedDataPlaneTests(unittest.TestCase):
    def test_router_selects_backend_from_endpoint_metadata(self) -> None:
        endpoint = Endpoint(
            id="edge-ru-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "dataplane": "xray-core",
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            router = RoutedDataPlane(
                backends={
                    "linux-userspace": LinuxUserspaceDataPlane(dry_run=True),
                    "xray-core": XrayCoreDataPlane(dry_run=True, config_dir=Path(tmp)),
                },
                default_backend_name="linux-userspace",
                client_platform=ClientPlatform.ANDROID,
            )

            session = router.connect(endpoint)
            snapshot = router.runtime_snapshot()

            self.assertEqual(session.backend_name, "xray-core")
            self.assertEqual(snapshot["active_backend"], "xray-core")
            router.disconnect()

    def test_router_uses_default_backend_when_endpoint_has_no_override(self) -> None:
        endpoint = Endpoint(
            id="edge-wg-1",
            host="198.51.100.10",
            port=51820,
            transport="wireguard",
            region="ru-spb",
        )

        router = RoutedDataPlane(
            backends={
                "linux-userspace": LinuxUserspaceDataPlane(dry_run=True),
                "xray-core": XrayCoreDataPlane(dry_run=True),
            },
            default_backend_name="linux-userspace",
            client_platform=ClientPlatform.LINUX,
        )

        session = router.connect(endpoint)

        self.assertEqual(session.backend_name, "linux-userspace")
        router.disconnect()

    def test_router_rejects_backend_not_supported_on_platform(self) -> None:
        endpoint = Endpoint(
            id="edge-xray-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "dataplane": "xray-core",
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
            },
        )

        router = RoutedDataPlane(
            backends={
                "linux-userspace": LinuxUserspaceDataPlane(dry_run=True),
                "xray-core": XrayCoreDataPlane(dry_run=True),
            },
            default_backend_name="xray-core",
            client_platform=ClientPlatform.IOS,
        )

        with self.assertRaises(DataPlaneError) as ctx:
            router.connect(endpoint)

        self.assertIn("not supported on client platform 'ios'", str(ctx.exception))


class IOSBridgeDataPlaneTests(unittest.TestCase):
    def test_renderer_builds_ios_bridge_contract(self) -> None:
        endpoint = Endpoint(
            id="ios-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "dataplane": "ios-bridge",
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "ws",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
                "xray_ws_path": "/edge",
                "xray_ws_host": "cdn.example.net",
            },
        )

        contract = IOSBridgeConfigRenderer().render(endpoint)

        self.assertEqual(contract.provider_kind, "packet-tunnel")
        self.assertEqual(contract.transport, "ws")
        self.assertEqual(contract.security, "tls")
        self.assertEqual(contract.auth["id"], "11111111-1111-1111-1111-111111111111")
        request = build_ios_bridge_request(endpoint, contract)
        self.assertEqual(request.schema_version, 1)
        self.assertEqual(request.request_kind, "start_tunnel")
        self.assertEqual(request.routing["tunnel_mode"], "full")
        self.assertEqual(request.dns["mode"], "vpn_only")

    def test_renderer_rejects_missing_ios_bridge_identity(self) -> None:
        endpoint = Endpoint(
            id="ios-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "dataplane": "ios-bridge",
                "xray_protocol": "vless",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
            },
        )

        with self.assertRaises(IOSBridgeConfigError):
            IOSBridgeConfigRenderer().render(endpoint)

    def test_ios_bridge_writes_contract_before_unimplemented_runtime_error(self) -> None:
        endpoint = Endpoint(
            id="ios-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "dataplane": "ios-bridge",
                "xray_protocol": "trojan",
                "xray_password": "secret",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            backend = IOSBridgeDataPlane(contract_dir=Path(tmp))

            with self.assertRaises(DataPlaneError) as ctx:
                backend.connect(endpoint)

            snapshot = backend.runtime_snapshot()
            self.assertIn("Apple Network Extension runtime is not wired yet", str(ctx.exception))
            self.assertTrue(Path(snapshot["contract_path"]).exists())
            self.assertTrue(Path(snapshot["status_path"]).exists())
            self.assertEqual(snapshot["status"]["state"], IOSBridgeState.AWAITING_EXTENSION.value)

    def test_ios_bridge_status_advances_through_handshake(self) -> None:
        endpoint = Endpoint(
            id="ios-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="ru-spb",
            metadata={
                "dataplane": "ios-bridge",
                "xray_protocol": "trojan",
                "xray_password": "secret",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
            },
        )

        with tempfile.TemporaryDirectory() as tmp:
            backend = IOSBridgeDataPlane(contract_dir=Path(tmp))

            with self.assertRaises(DataPlaneError):
                backend.connect(endpoint)

            acknowledged = backend.mark_extension_acknowledged()
            network_ready = backend.mark_network_ready()
            tunnel_ready = backend.mark_tunnel_fd_ready()
            running = backend.mark_running()
            failed = backend.mark_failed("extension crashed during reload")

            self.assertEqual(acknowledged.state, IOSBridgeState.EXTENSION_ACKNOWLEDGED.value)
            self.assertEqual(network_ready.state, IOSBridgeState.NETWORK_READY.value)
            self.assertTrue(network_ready.network_ready)
            self.assertEqual(tunnel_ready.state, IOSBridgeState.TUNNEL_FD_READY.value)
            self.assertTrue(tunnel_ready.tunnel_file_descriptor_ready)
            self.assertEqual(running.state, IOSBridgeState.RUNNING.value)
            self.assertEqual(failed.state, IOSBridgeState.FAILED.value)
            self.assertEqual(failed.last_error, "extension crashed during reload")


if __name__ == "__main__":
    unittest.main()
