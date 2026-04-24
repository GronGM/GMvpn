from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(slots=True)
class RuntimeMarker:
    endpoint_id: str
    transport: str
    started_at: str


class RuntimeState:
    def __init__(self, marker_path: Path):
        self.marker_path = marker_path
        self.marker_path.parent.mkdir(parents=True, exist_ok=True)

    def load_marker(self) -> RuntimeMarker | None:
        if not self.marker_path.exists():
            return None
        try:
            payload = json.loads(self.marker_path.read_text(encoding="utf-8"))
            return RuntimeMarker(**payload)
        except (json.JSONDecodeError, TypeError, ValueError):
            self.clear()
            return None

    def mark_active(self, endpoint_id: str, transport: str) -> None:
        marker = RuntimeMarker(
            endpoint_id=endpoint_id,
            transport=transport,
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        self.marker_path.write_text(json.dumps(asdict(marker), indent=2, sort_keys=True), encoding="utf-8")

    def clear(self) -> None:
        if self.marker_path.exists():
            self.marker_path.unlink()
