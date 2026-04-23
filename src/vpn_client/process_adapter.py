from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import subprocess
import threading


class RingBuffer:
    def __init__(self, max_chars: int = 4000):
        self.max_chars = max_chars
        self._chunks: deque[str] = deque()
        self._size = 0
        self._lock = threading.Lock()

    def append(self, text: str) -> None:
        if not text:
            return
        with self._lock:
            self._chunks.append(text)
            self._size += len(text)
            while self._size > self.max_chars and self._chunks:
                removed = self._chunks.popleft()
                self._size -= len(removed)

    def get_value(self) -> str:
        with self._lock:
            return "".join(self._chunks)[-self.max_chars :]


@dataclass(slots=True)
class ProcessSnapshot:
    pid: int
    running: bool
    exit_code: int | None
    stdout_tail: str
    stderr_tail: str


class ManagedProcess:
    def __init__(self, process: subprocess.Popen[str], stdout_buffer: RingBuffer, stderr_buffer: RingBuffer):
        self.process = process
        self.stdout_buffer = stdout_buffer
        self.stderr_buffer = stderr_buffer
        self._threads: list[threading.Thread] = []

    def start_readers(self) -> None:
        if self.process.stdout is not None:
            self._threads.append(threading.Thread(target=self._reader, args=(self.process.stdout, self.stdout_buffer), daemon=True))
        if self.process.stderr is not None:
            self._threads.append(threading.Thread(target=self._reader, args=(self.process.stderr, self.stderr_buffer), daemon=True))
        for thread in self._threads:
            thread.start()

    def snapshot(self) -> ProcessSnapshot:
        return ProcessSnapshot(
            pid=self.process.pid,
            running=self.process.poll() is None,
            exit_code=self.process.poll(),
            stdout_tail=self.stdout_buffer.get_value(),
            stderr_tail=self.stderr_buffer.get_value(),
        )

    def stop(self) -> int | None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        return self.process.poll()

    def _reader(self, stream, buffer: RingBuffer) -> None:
        try:
            for line in iter(stream.readline, ""):
                if not line:
                    break
                buffer.append(line)
        finally:
            try:
                stream.close()
            except Exception:
                pass


class LocalProcessAdapter:
    def __init__(self):
        self._processes: dict[int, ManagedProcess] = {}

    def spawn(self, command: list[str]) -> int:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        managed = ManagedProcess(process, RingBuffer(), RingBuffer())
        managed.start_readers()
        self._processes[process.pid] = managed
        return process.pid

    def stop(self, pid: int) -> int | None:
        managed = self._processes.get(pid)
        if managed is None:
            return None
        exit_code = managed.stop()
        return exit_code

    def snapshot(self, pid: int) -> ProcessSnapshot | None:
        managed = self._processes.get(pid)
        if managed is None:
            return None
        snapshot = managed.snapshot()
        if not snapshot.running:
            self._processes.pop(pid, None)
        return snapshot
