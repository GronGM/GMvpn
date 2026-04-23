from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from vpnclient.core.models import Endpoint


@dataclass(slots=True)
class TransportAttempt:
    ok: bool
    error: str | None = None


class TransportAdapter(Protocol):
    name: str

    def connect(self, endpoint: Endpoint) -> TransportAttempt: ...


class SimulatedTransport:
    def __init__(self, name: str, blocked_hosts: set[str] | None = None) -> None:
        self.name = name
        self.blocked_hosts = blocked_hosts or set()

    def connect(self, endpoint: Endpoint) -> TransportAttempt:
        if endpoint.host in self.blocked_hosts:
            return TransportAttempt(ok=False, error="blocked_by_network")
        return TransportAttempt(ok=True)
