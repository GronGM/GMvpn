from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RuntimeTickPolicy:
    reevaluate_pending_transports_limit: int = 1


@dataclass(slots=True)
class RuntimeTickReport:
    reenabled_transports: list[str]
    pending_ready_transports: list[str]
    pending_total: int
