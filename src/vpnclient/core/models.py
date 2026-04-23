from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, UTC
from typing import Any


def utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(slots=True)
class Endpoint:
    name: str
    host: str
    port: int
    transport: str
    priority: int = 100


@dataclass(slots=True)
class Manifest:
    version: int
    expires_at: str
    endpoints: list[Endpoint]
    network: dict[str, Any]
    features: dict[str, Any] = field(default_factory=dict)

    def is_expired(self, now: datetime | None = None) -> bool:
        now = now or utcnow()
        return datetime.fromisoformat(self.expires_at) <= now


@dataclass(slots=True)
class EndpointHealth:
    endpoint_name: str
    score: int = 0
    consecutive_failures: int = 0
    cooldown_until: str | None = None
    last_error: str | None = None
    last_success_at: str | None = None

    def cooling_down(self, now: datetime | None = None) -> bool:
        if not self.cooldown_until:
            return False
        now = now or utcnow()
        return datetime.fromisoformat(self.cooldown_until) > now


@dataclass(slots=True)
class DataPlaneRuntime:
    backend_name: str
    pid: int | None = None
    command: list[str] = field(default_factory=list)
    started_at: str | None = None
    stopped_at: str | None = None
    crashed: bool = False
    crash_reason: str | None = None
    restart_count: int = 0
    last_exit_code: int | None = None
    stdout_tail: list[str] = field(default_factory=list)
    stderr_tail: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SessionResult:
    connected: bool
    endpoint: str | None = None
    transport: str | None = None
    error: str | None = None
    degraded: bool = False


@dataclass(slots=True)
class Event:
    kind: str
    at: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IncidentDecision:
    flag_name: str
    ttl_seconds: int

    def expires_at(self, now: datetime | None = None) -> str:
        now = now or utcnow()
        return (now + timedelta(seconds=self.ttl_seconds)).isoformat()


def endpoint_to_dict(endpoint: Endpoint) -> dict[str, Any]:
    return asdict(endpoint)
