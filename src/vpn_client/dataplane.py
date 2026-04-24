from __future__ import annotations

from dataclasses import dataclass
from itertools import count

from vpn_client.backend_state import BackendStateRecord, BackendStateStore, now_utc_iso
from vpn_client.client_platform import ClientPlatform, backend_supported_on_platform
from vpn_client.models import Endpoint, FailureClass, FailureReasonCode, default_reason_code_for_failure
from vpn_client.process_adapter import LocalProcessAdapter


class DataPlaneError(Exception):
    def __init__(
        self,
        failure_class: FailureClass,
        detail: str,
        reason_code: FailureReasonCode | None = None,
    ):
        super().__init__(detail)
        self.failure_class = failure_class
        self.reason_code = reason_code or default_reason_code_for_failure(failure_class)
        self.detail = detail


@dataclass(slots=True)
class DataPlaneSession:
    backend_name: str
    endpoint_id: str
    active: bool
    dry_run: bool
    command: list[str]
    pid: int | None = None
    restart_count: int = 0
    started_at: str | None = None


class DataPlaneBackend:
    name: str

    def connect(self, endpoint: Endpoint) -> DataPlaneSession:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError

    def health_check(self, endpoint: Endpoint) -> None:
        raise NotImplementedError

    def runtime_snapshot(self) -> dict:
        raise NotImplementedError


class NullDataPlane(DataPlaneBackend):
    name = "null"

    def __init__(self) -> None:
        self.session: DataPlaneSession | None = None

    def connect(self, endpoint: Endpoint) -> DataPlaneSession:
        self.session = DataPlaneSession(
            backend_name=self.name,
            endpoint_id=endpoint.id,
            active=True,
            dry_run=True,
            command=["noop"],
        )
        return self.session

    def disconnect(self) -> None:
        self.session = None

    def health_check(self, endpoint: Endpoint) -> None:
        return None

    def runtime_snapshot(self) -> dict:
        return {
            "backend": self.name,
            "active": self.session is not None,
            "pid": None,
            "running": None,
            "restart_count": 0,
            "crashed": False,
            "crash_reason": None,
            "last_exit_code": None,
            "stdout_tail": "",
            "stderr_tail": "",
        }


class RoutedDataPlane(DataPlaneBackend):
    name = "routed"

    def __init__(
        self,
        backends: dict[str, DataPlaneBackend],
        default_backend_name: str,
        client_platform: ClientPlatform = ClientPlatform.LINUX,
    ):
        if default_backend_name not in backends:
            raise ValueError(f"default backend '{default_backend_name}' is not registered")
        self.backends = backends
        self.default_backend_name = default_backend_name
        self.client_platform = client_platform
        self.active_backend_name: str | None = None
        self.active_backend: DataPlaneBackend | None = None
        self.session: DataPlaneSession | None = None

    def connect(self, endpoint: Endpoint) -> DataPlaneSession:
        backend_name = str(endpoint.metadata.get("dataplane", self.default_backend_name))
        if not backend_supported_on_platform(self.client_platform, backend_name):
            raise DataPlaneError(
                FailureClass.UNKNOWN,
                f"dataplane backend '{backend_name}' is not supported on client platform '{self.client_platform.value}'",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_UNSUPPORTED,
            )
        backend = self.backends.get(backend_name)
        if backend is None:
            raise DataPlaneError(
                FailureClass.UNKNOWN,
                f"dataplane backend '{backend_name}' is not registered",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_UNREGISTERED,
            )
        session = backend.connect(endpoint)
        self.active_backend_name = backend_name
        self.active_backend = backend
        self.session = session
        return session

    def disconnect(self) -> None:
        if self.active_backend is not None:
            self.active_backend.disconnect()
        self.active_backend_name = None
        self.active_backend = None
        self.session = None

    def health_check(self, endpoint: Endpoint) -> None:
        if self.active_backend is None:
            raise DataPlaneError(
                FailureClass.NETWORK_DOWN,
                "no active dataplane backend",
                reason_code=FailureReasonCode.DATAPLANE_SESSION_INACTIVE,
            )
        self.active_backend.health_check(endpoint)

    def runtime_snapshot(self) -> dict:
        if self.active_backend is None:
            return {
                "backend": self.name,
                "active_backend": None,
                "active": False,
                "pid": None,
                "running": None,
                "restart_count": 0,
                "crashed": False,
                "crash_reason": None,
                "last_exit_code": None,
                "stdout_tail": "",
                "stderr_tail": "",
            }
        snapshot = self.active_backend.runtime_snapshot()
        snapshot["router_backend"] = self.name
        snapshot["active_backend"] = self.active_backend_name
        snapshot["client_platform"] = self.client_platform.value
        return snapshot


class BackendProcessSupervisor:
    def __init__(self, process_adapter: LocalProcessAdapter | None = None):
        self.process_adapter = process_adapter or LocalProcessAdapter()
        self._pid_counter = count(41000)
        self._active_pid: int | None = None
        self._active_command: list[str] | None = None
        self.restart_count = 0
        self.crashed = False
        self.crash_reason: str | None = None
        self.last_exit_code: int | None = None
        self.stdout_tail: str = ""
        self.stderr_tail: str = ""

    def start(self, command: list[str], dry_run: bool) -> int | None:
        if self._active_pid is not None:
            self.stop(self._active_pid, dry_run=dry_run)
            self.restart_count += 1
        if dry_run:
            pid = next(self._pid_counter)
            self._active_pid = pid
            self._active_command = list(command)
            self.crashed = False
            self.crash_reason = None
            self.last_exit_code = None
            self.stdout_tail = ""
            self.stderr_tail = ""
            return pid
        pid = self.process_adapter.spawn(command)
        snapshot = self.process_adapter.snapshot(pid)
        self._active_pid = pid
        self._active_command = list(command)
        self.crashed = False
        self.crash_reason = None
        self.last_exit_code = None
        self.stdout_tail = snapshot.stdout_tail if snapshot else ""
        self.stderr_tail = snapshot.stderr_tail if snapshot else ""
        return pid

    def stop(self, pid: int | None, dry_run: bool) -> None:
        if pid is None:
            return
        if not dry_run:
            exit_code = self.process_adapter.stop(pid)
            self.last_exit_code = exit_code
        if self._active_pid == pid:
            self._active_pid = None
            self._active_command = None
            self.crashed = False
            self.crash_reason = None
            self.stdout_tail = ""
            self.stderr_tail = ""

    def assert_healthy(self, pid: int | None, dry_run: bool) -> None:
        if pid is None:
            raise DataPlaneError(
                FailureClass.NETWORK_DOWN,
                "data plane pid is missing",
                reason_code=FailureReasonCode.DATAPLANE_PID_MISSING,
            )
        if dry_run:
            if self.crashed:
                raise DataPlaneError(
                    FailureClass.NETWORK_DOWN,
                    self.crash_reason or "data plane supervisor detected a crashed backend",
                    reason_code=FailureReasonCode.DATAPLANE_BACKEND_CRASHED,
                )
            return
        snapshot = self.process_adapter.snapshot(pid)
        if snapshot is not None:
            self.stdout_tail = snapshot.stdout_tail[-400:]
            self.stderr_tail = snapshot.stderr_tail[-400:]
        if snapshot is None or not snapshot.running:
            self.crashed = True
            self.last_exit_code = snapshot.exit_code if snapshot is not None else self.last_exit_code
            self.crash_reason = self._build_exit_reason(snapshot)
            raise DataPlaneError(
                FailureClass.NETWORK_DOWN,
                self.crash_reason,
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_CRASHED,
            )

    def mark_crashed(self, reason: str, exit_code: int | None = None, stdout_tail: str = "", stderr_tail: str = "") -> None:
        self.crashed = True
        self.crash_reason = reason
        self.last_exit_code = exit_code
        if stdout_tail:
            self.stdout_tail = stdout_tail[-400:]
        if stderr_tail:
            self.stderr_tail = stderr_tail[-400:]

    def runtime_snapshot(self) -> dict:
        running: bool | None = None
        if self._active_pid is not None:
            snapshot = self.process_adapter.snapshot(self._active_pid)
            if snapshot is not None:
                running = snapshot.running
                self.stdout_tail = snapshot.stdout_tail[-400:]
                self.stderr_tail = snapshot.stderr_tail[-400:]
                self.last_exit_code = snapshot.exit_code if not snapshot.running else self.last_exit_code
                if not snapshot.running:
                    self.crashed = True
                    self.crash_reason = self.crash_reason or self._build_exit_reason(snapshot)
        return {
            "pid": self._active_pid,
            "running": running,
            "command": self._active_command,
            "restart_count": self.restart_count,
            "crashed": self.crashed,
            "crash_reason": self.crash_reason,
            "last_exit_code": self.last_exit_code,
            "stdout_tail": self.stdout_tail,
            "stderr_tail": self.stderr_tail,
        }

    def _build_exit_reason(self, snapshot) -> str:
        if snapshot is None:
            return "data plane backend is no longer running"

        detail_parts = ["data plane backend exited"]
        if snapshot.exit_code is not None:
            detail_parts.append(f"with code {snapshot.exit_code}")

        stderr_excerpt = snapshot.stderr_tail.strip()
        stdout_excerpt = snapshot.stdout_tail.strip()
        if stderr_excerpt:
            detail_parts.append(f"stderr: {stderr_excerpt[-120:]}")
        elif stdout_excerpt:
            detail_parts.append(f"stdout: {stdout_excerpt[-120:]}")

        return "; ".join(detail_parts)


class LinuxUserspaceDataPlane(DataPlaneBackend):
    name = "linux-userspace"

    def __init__(
        self,
        interface_name: str = "tun0",
        dry_run: bool = True,
        command_runner=None,
        supervisor: BackendProcessSupervisor | None = None,
        state_store: BackendStateStore | None = None,
    ) -> None:
        self.interface_name = interface_name
        self.dry_run = dry_run
        self.supervisor = supervisor or BackendProcessSupervisor()
        self.state_store = state_store
        self.session: DataPlaneSession | None = None

    def connect(self, endpoint: Endpoint) -> DataPlaneSession:
        backend_cmd = endpoint.metadata.get("dataplane_command")
        command = (
            list(backend_cmd)
            if isinstance(backend_cmd, list)
            else ["vpn-backend", "--interface", self.interface_name, "--endpoint", f"{endpoint.host}:{endpoint.port}"]
        )
        simulated = str(endpoint.metadata.get("dataplane_failure", ""))
        if simulated == "start":
            raise DataPlaneError(
                FailureClass.ENDPOINT_DOWN,
                "data plane backend failed to start",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_START_FAILED,
            )
        try:
            pid = self.supervisor.start(command, dry_run=self.dry_run)
        except Exception as exc:
            raise DataPlaneError(
                FailureClass.ENDPOINT_DOWN,
                f"data plane start failed: {exc}",
                reason_code=FailureReasonCode.DATAPLANE_BACKEND_START_FAILED,
            ) from exc
        self.session = DataPlaneSession(
            backend_name=self.name,
            endpoint_id=endpoint.id,
            active=True,
            dry_run=self.dry_run,
            command=command,
            pid=pid,
            restart_count=self.supervisor.restart_count,
            started_at=now_utc_iso(),
        )
        self._persist_state()
        return self.session

    def disconnect(self) -> None:
        if self.session is not None:
            self.supervisor.stop(self.session.pid, dry_run=self.session.dry_run)
            self._persist_state(active=False)
        self.session = None

    def health_check(self, endpoint: Endpoint) -> None:
        simulated = str(endpoint.metadata.get("dataplane_failure", ""))
        if simulated == "health":
            raise DataPlaneError(
                FailureClass.NETWORK_DOWN,
                "data plane health check failed",
                reason_code=FailureReasonCode.DATAPLANE_HEALTHCHECK_FAILED,
            )
        if simulated == "crash":
            self.supervisor.mark_crashed("simulated backend crash", exit_code=137, stderr_tail="backend terminated unexpectedly")
            self._persist_state(active=False)
        if self.session is None:
            raise DataPlaneError(
                FailureClass.NETWORK_DOWN,
                "data plane session is not active",
                reason_code=FailureReasonCode.DATAPLANE_SESSION_INACTIVE,
            )
        try:
            self.supervisor.assert_healthy(self.session.pid, dry_run=self.session.dry_run)
        except DataPlaneError:
            self._persist_state(active=False)
            raise

    def runtime_snapshot(self) -> dict:
        snapshot = self.supervisor.runtime_snapshot()
        return {
            "backend": self.name,
            "active": self.session is not None,
            "endpoint_id": self.session.endpoint_id if self.session else None,
            "pid": snapshot["pid"],
            "running": snapshot["running"],
            "restart_count": snapshot["restart_count"],
            "crashed": snapshot["crashed"],
            "crash_reason": snapshot["crash_reason"],
            "last_exit_code": snapshot["last_exit_code"],
            "stdout_tail": snapshot["stdout_tail"],
            "stderr_tail": snapshot["stderr_tail"],
            "command": snapshot["command"],
        }

    def _persist_state(self, active: bool = True) -> None:
        if self.state_store is None:
            return
        snapshot = self.runtime_snapshot()
        record = BackendStateRecord(
            backend=self.name,
            endpoint_id=self.session.endpoint_id if self.session else None,
            pid=snapshot["pid"],
            active=active and self.session is not None,
            started_at=self.session.started_at if self.session else None,
            stopped_at=None if active and self.session is not None else now_utc_iso(),
            command=snapshot["command"] or [],
            restart_count=snapshot["restart_count"],
            crashed=snapshot["crashed"],
            crash_reason=snapshot["crash_reason"],
            last_exit_code=snapshot["last_exit_code"],
            stdout_tail=snapshot["stdout_tail"],
            stderr_tail=snapshot["stderr_tail"],
        )
        self.state_store.save(record)
