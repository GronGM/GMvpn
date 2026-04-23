from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class BackendStateRecord:
    backend: str
    endpoint_id: str | None
    pid: int | None
    active: bool
    started_at: str | None
    stopped_at: str | None
    command: list[str]
    restart_count: int
    crashed: bool
    crash_reason: str | None
    last_exit_code: int | None
    stdout_tail: str
    stderr_tail: str


class BackendStateStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> BackendStateRecord | None:
        if not self.path.exists():
            return None
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        return BackendStateRecord(**payload)

    def save(self, record: BackendStateRecord) -> None:
        self.path.write_text(json.dumps(asdict(record), indent=2, sort_keys=True), encoding="utf-8")

    def clear(self) -> None:
        if self.path.exists():
            self.path.unlink()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
