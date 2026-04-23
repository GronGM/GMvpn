from __future__ import annotations

from pathlib import Path


class StartupRecovery:
    def __init__(self, runtime_marker: Path) -> None:
        self.runtime_marker = runtime_marker
        self.runtime_marker.parent.mkdir(parents=True, exist_ok=True)

    def recover(self) -> list[str]:
        actions: list[str] = []
        if self.runtime_marker.exists():
            self.runtime_marker.unlink()
            actions.append("removed_stale_runtime_marker")
        return actions

    def mark_active(self) -> None:
        self.runtime_marker.write_text("active", encoding="utf-8")

    def clear(self) -> None:
        if self.runtime_marker.exists():
            self.runtime_marker.unlink()
