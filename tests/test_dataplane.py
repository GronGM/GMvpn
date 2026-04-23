from __future__ import annotations

import unittest
import tempfile
import time
from pathlib import Path

from vpn_client.backend_state import BackendStateStore
from vpn_client.dataplane import BackendProcessSupervisor, DataPlaneError, LinuxUserspaceDataPlane
from vpn_client.models import Endpoint
from vpn_client.process_adapter import LocalProcessAdapter


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


if __name__ == "__main__":
    unittest.main()
