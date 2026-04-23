from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from vpnclient.core.models import EndpointHealth, utcnow


class StateManager:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write(self._default_state())

    def _default_state(self) -> dict[str, Any]:
        return {
            "endpoint_health": {},
            "incident_flags": {},
            "incident_flag_expires_at": {},
            "transport_crash_streaks": {},
            "transport_soft_fail_streaks": {},
            "last_known_good_endpoint": None,
        }

    def _read(self) -> dict[str, Any]:
        return json.loads(self.path.read_text(encoding="utf-8"))

    def _write(self, state: dict[str, Any]) -> None:
        self.path.write_text(json.dumps(state, indent=2), encoding="utf-8")

    def get_state(self) -> dict[str, Any]:
        state = self._read()
        self._expire_flags(state)
        self._write(state)
        return state

    def _expire_flags(self, state: dict[str, Any]) -> None:
        now = utcnow().isoformat()
        expired = [
            name for name, expires_at in state["incident_flag_expires_at"].items()
            if expires_at <= now
        ]
        for name in expired:
            state["incident_flags"].pop(name, None)
            state["incident_flag_expires_at"].pop(name, None)

    def update_endpoint_success(self, endpoint_name: str) -> None:
        state = self.get_state()
        entry = state["endpoint_health"].get(endpoint_name, asdict(EndpointHealth(endpoint_name=endpoint_name)))
        entry["score"] = int(entry.get("score", 0)) + 10
        entry["consecutive_failures"] = 0
        entry["cooldown_until"] = None
        entry["last_success_at"] = utcnow().isoformat()
        entry["last_error"] = None
        state["endpoint_health"][endpoint_name] = entry
        state["last_known_good_endpoint"] = endpoint_name
        self._write(state)

    def update_endpoint_failure(self, endpoint_name: str, error: str, cooldown_seconds: int) -> None:
        state = self.get_state()
        entry = state["endpoint_health"].get(endpoint_name, asdict(EndpointHealth(endpoint_name=endpoint_name)))
        failures = int(entry.get("consecutive_failures", 0)) + 1
        entry["score"] = int(entry.get("score", 0)) - 10
        entry["consecutive_failures"] = failures
        entry["last_error"] = error
        entry["cooldown_until"] = (utcnow()).timestamp() + cooldown_seconds
        from datetime import datetime, UTC
        entry["cooldown_until"] = datetime.fromtimestamp(entry["cooldown_until"], UTC).isoformat()
        state["endpoint_health"][endpoint_name] = entry
        self._write(state)

    def set_incident_flag(self, name: str, ttl_seconds: int) -> None:
        state = self.get_state()
        from datetime import timedelta
        expires = utcnow() + timedelta(seconds=ttl_seconds)
        state["incident_flags"][name] = True
        state["incident_flag_expires_at"][name] = expires.isoformat()
        self._write(state)

    def is_flag_active(self, name: str) -> bool:
        state = self.get_state()
        return bool(state["incident_flags"].get(name, False))

    def bump_transport_crash(self, transport: str) -> int:
        state = self.get_state()
        streak = int(state["transport_crash_streaks"].get(transport, 0)) + 1
        state["transport_crash_streaks"][transport] = streak
        self._write(state)
        return streak

    def clear_transport_crash(self, transport: str) -> None:
        state = self.get_state()
        state["transport_crash_streaks"][transport] = 0
        self._write(state)

    def bump_transport_soft_fail(self, transport: str) -> int:
        state = self.get_state()
        streak = int(state["transport_soft_fail_streaks"].get(transport, 0)) + 1
        state["transport_soft_fail_streaks"][transport] = streak
        self._write(state)
        return streak

    def clear_transport_soft_fail(self, transport: str) -> None:
        state = self.get_state()
        state["transport_soft_fail_streaks"][transport] = 0
        self._write(state)
