from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from vpn_client.models import FailureClass


@dataclass(slots=True)
class EndpointHealth:
    endpoint_id: str
    score: int = 0
    consecutive_failures: int = 0
    cooldown_until: str | None = None
    last_failure_class: str = FailureClass.NONE.value
    last_detail: str = ""
    updated_at: str = ""


@dataclass(slots=True)
class PersistentState:
    endpoint_health: dict[str, EndpointHealth] = field(default_factory=dict)
    incident_flags: dict[str, bool] = field(default_factory=dict)
    incident_flag_expires_at: dict[str, str] = field(default_factory=dict)
    transport_crash_streaks: dict[str, int] = field(default_factory=dict)
    transport_crash_reasons: dict[str, str] = field(default_factory=dict)
    transport_soft_fail_streaks: dict[str, int] = field(default_factory=dict)
    transport_reenable_pending: dict[str, bool] = field(default_factory=dict)
    transport_reenable_not_before: dict[str, str] = field(default_factory=dict)
    transport_reenable_fail_streaks: dict[str, int] = field(default_factory=dict)
    last_connected_endpoint_id: str | None = None


class StateStore:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> PersistentState:
        if not self.path.exists():
            return PersistentState()

        payload = json.loads(self.path.read_text(encoding="utf-8"))
        endpoint_health = {
            endpoint_id: EndpointHealth(**value)
            for endpoint_id, value in payload.get("endpoint_health", {}).items()
        }
        return PersistentState(
            endpoint_health=endpoint_health,
            incident_flags=payload.get("incident_flags", {}),
            incident_flag_expires_at=payload.get("incident_flag_expires_at", {}),
            transport_crash_streaks=payload.get("transport_crash_streaks", {}),
            transport_crash_reasons=payload.get("transport_crash_reasons", {}),
            transport_soft_fail_streaks=payload.get("transport_soft_fail_streaks", {}),
            transport_reenable_pending=payload.get("transport_reenable_pending", {}),
            transport_reenable_not_before=payload.get("transport_reenable_not_before", {}),
            transport_reenable_fail_streaks=payload.get("transport_reenable_fail_streaks", {}),
            last_connected_endpoint_id=payload.get("last_connected_endpoint_id"),
        )

    def save(self, state: PersistentState) -> None:
        payload = {
            "endpoint_health": {
                endpoint_id: asdict(health)
                for endpoint_id, health in state.endpoint_health.items()
            },
            "incident_flags": state.incident_flags,
            "incident_flag_expires_at": state.incident_flag_expires_at,
            "transport_crash_streaks": state.transport_crash_streaks,
            "transport_crash_reasons": state.transport_crash_reasons,
            "transport_soft_fail_streaks": state.transport_soft_fail_streaks,
            "transport_reenable_pending": state.transport_reenable_pending,
            "transport_reenable_not_before": state.transport_reenable_not_before,
            "transport_reenable_fail_streaks": state.transport_reenable_fail_streaks,
            "last_connected_endpoint_id": state.last_connected_endpoint_id,
        }
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


class StateManager:
    def __init__(self, store: StateStore):
        self.store = store
        self.state = self.store.load()

    def incident_flag(self, name: str) -> bool:
        if self._flag_expired(name):
            self.state.incident_flags[name] = False
            self.state.incident_flag_expires_at.pop(name, None)
            self.store.save(self.state)
        return bool(self.state.incident_flags.get(name, False))

    def set_incident_flag(self, name: str, enabled: bool) -> None:
        self.state.incident_flags[name] = enabled
        if not enabled:
            self.state.incident_flag_expires_at.pop(name, None)
        self.store.save(self.state)

    def set_incident_flag_with_ttl(self, name: str, enabled: bool, ttl_seconds: int) -> None:
        self.state.incident_flags[name] = enabled
        if enabled:
            self.state.incident_flag_expires_at[name] = (
                datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
            ).isoformat()
        else:
            self.state.incident_flag_expires_at.pop(name, None)
        self.store.save(self.state)

    def mark_success(self, endpoint_id: str) -> None:
        now = datetime.now(timezone.utc)
        health = self.state.endpoint_health.get(endpoint_id, EndpointHealth(endpoint_id=endpoint_id))
        health.score = min(max(health.score + 2, 1), 10)
        health.consecutive_failures = 0
        health.cooldown_until = None
        health.last_failure_class = FailureClass.NONE.value
        health.last_detail = "connected"
        health.updated_at = now.isoformat()
        self.state.endpoint_health[endpoint_id] = health
        self.state.last_connected_endpoint_id = endpoint_id
        self.store.save(self.state)

    def clear_transport_crash_streak(self, transport: str) -> None:
        self.state.transport_crash_streaks[transport] = 0
        self.state.transport_soft_fail_streaks[transport] = 0
        self.state.transport_reenable_pending[transport] = False
        self.state.transport_reenable_not_before.pop(transport, None)
        self.state.transport_reenable_fail_streaks[transport] = 0
        self.state.incident_flags[f"disable_transport_{transport}"] = False
        self.state.incident_flags.pop(f"transport_{transport}_crash_reason_present", None)
        self.state.incident_flag_expires_at.pop(f"disable_transport_{transport}", None)
        self.store.save(self.state)

    def transport_reenable_pending(self, transport: str) -> bool:
        return bool(self.state.transport_reenable_pending.get(transport, False))

    def mark_transport_reenable_pending(self, transport: str, enabled: bool = True) -> None:
        self.state.transport_reenable_pending[transport] = enabled
        if enabled:
            self.schedule_transport_reenable_probe(transport, base_delay_seconds=0)
        else:
            self.state.transport_reenable_not_before.pop(transport, None)
        self.store.save(self.state)

    def transport_reenable_ready(self, transport: str, now: datetime | None = None) -> bool:
        if not self.transport_reenable_pending(transport):
            return False
        not_before = self.state.transport_reenable_not_before.get(transport)
        if not not_before:
            return True
        current_time = now or datetime.now(timezone.utc)
        return self._parse_timestamp(not_before) <= current_time

    def schedule_transport_reenable_probe(self, transport: str, base_delay_seconds: int = 60) -> None:
        jitter_seconds = self._transport_jitter_seconds(transport)
        when = datetime.now(timezone.utc) + timedelta(seconds=base_delay_seconds + jitter_seconds)
        self.state.transport_reenable_not_before[transport] = when.isoformat()
        self.store.save(self.state)

    def fail_transport_reenable(self, transport: str, retry_delay_seconds: int = 120) -> None:
        streak = self.state.transport_reenable_fail_streaks.get(transport, 0) + 1
        self.state.transport_reenable_fail_streaks[transport] = streak
        self.state.transport_reenable_pending[transport] = False
        self.state.transport_reenable_not_before.pop(transport, None)
        escalated_delay = min(retry_delay_seconds * (2 ** max(streak - 1, 0)), 1800)
        self.set_incident_flag_with_ttl(f"disable_transport_{transport}", True, ttl_seconds=escalated_delay)
        self.store.save(self.state)

    def ready_transports_for_reenable(self) -> list[str]:
        return sorted(
            transport
            for transport, pending in self.state.transport_reenable_pending.items()
            if pending and self.transport_reenable_ready(transport)
        )

    def pending_transports_for_reenable(self) -> list[str]:
        return sorted(
            transport
            for transport, pending in self.state.transport_reenable_pending.items()
            if pending
        )

    def transport_reenable_fail_streak(self, transport: str) -> int:
        return self.state.transport_reenable_fail_streaks.get(transport, 0)

    def mark_failure(self, endpoint_id: str, failure_class: FailureClass, detail: str) -> None:
        now = datetime.now(timezone.utc)
        health = self.state.endpoint_health.get(endpoint_id, EndpointHealth(endpoint_id=endpoint_id))
        penalty = 3 if failure_class in {FailureClass.TLS_INTERFERENCE, FailureClass.DNS_INTERFERENCE} else 1
        health.score = max(health.score - penalty, -10)
        health.consecutive_failures += 1
        health.cooldown_until = (now + timedelta(seconds=self._backoff_seconds(health, failure_class))).isoformat()
        health.last_failure_class = failure_class.value
        health.last_detail = detail[:160]
        health.updated_at = now.isoformat()
        self.state.endpoint_health[endpoint_id] = health
        self.store.save(self.state)

    def apply_failure_mitigation(self, failure_class: FailureClass, transport: str | None = None) -> list[str]:
        actions: list[str] = []
        if failure_class is FailureClass.DNS_INTERFERENCE:
            self.set_incident_flag_with_ttl("force_system_dns_fallback", True, ttl_seconds=300)
            actions.append("force_system_dns_fallback")
        if failure_class is FailureClass.UDP_BLOCKED and transport:
            self.set_incident_flag_with_ttl(f"disable_transport_{transport}", True, ttl_seconds=180)
            actions.append(f"disable_transport_{transport}")
        return actions

    def mark_stale_runtime(
        self,
        endpoint_id: str,
        transport: str,
        detail: str = "stale runtime marker recovered on startup",
    ) -> bool:
        self.mark_failure(endpoint_id, FailureClass.UNKNOWN, detail)
        return self.record_transport_crash(transport, detail)

    def score_for(self, endpoint_id: str) -> int:
        return self.state.endpoint_health.get(endpoint_id, EndpointHealth(endpoint_id=endpoint_id)).score

    def is_cooling_down(self, endpoint_id: str, now: datetime | None = None) -> bool:
        health = self.state.endpoint_health.get(endpoint_id)
        if not health or not health.cooldown_until:
            return False
        current_time = now or datetime.now(timezone.utc)
        return self._parse_timestamp(health.cooldown_until) > current_time

    def cooldown_remaining_seconds(self, endpoint_id: str, now: datetime | None = None) -> int:
        health = self.state.endpoint_health.get(endpoint_id)
        if not health or not health.cooldown_until:
            return 0
        current_time = now or datetime.now(timezone.utc)
        remaining = self._parse_timestamp(health.cooldown_until) - current_time
        return max(int(remaining.total_seconds()), 0)

    def record_transport_crash(self, transport: str, detail: str, threshold: int = 2, disable_ttl_seconds: int = 900) -> bool:
        streak = self.state.transport_crash_streaks.get(transport, 0) + 1
        self.state.transport_crash_streaks[transport] = streak
        if detail:
            self.state.transport_crash_reasons[transport] = detail[:160]
        disabled = streak >= threshold
        if disabled:
            self.state.incident_flags[f"disable_transport_{transport}"] = True
            self.state.incident_flag_expires_at[f"disable_transport_{transport}"] = (
                datetime.now(timezone.utc) + timedelta(seconds=disable_ttl_seconds)
            ).isoformat()
            self.state.incident_flags[f"transport_{transport}_crash_reason_present"] = bool(detail)
        self.store.save(self.state)
        return disabled

    def transport_crash_streak(self, transport: str) -> int:
        return self.state.transport_crash_streaks.get(transport, 0)

    def transport_crash_reason(self, transport: str) -> str | None:
        return self.state.transport_crash_reasons.get(transport)

    def record_transport_soft_failure(self, transport: str, threshold: int = 3, disable_ttl_seconds: int = 300) -> bool:
        streak = self.state.transport_soft_fail_streaks.get(transport, 0) + 1
        self.state.transport_soft_fail_streaks[transport] = streak
        disabled = streak >= threshold
        if disabled:
            self.state.incident_flags[f"disable_transport_{transport}"] = True
            self.state.incident_flag_expires_at[f"disable_transport_{transport}"] = (
                datetime.now(timezone.utc) + timedelta(seconds=disable_ttl_seconds)
            ).isoformat()
        self.store.save(self.state)
        return disabled

    def transport_soft_fail_streak(self, transport: str) -> int:
        return self.state.transport_soft_fail_streaks.get(transport, 0)

    def _backoff_seconds(self, health: EndpointHealth, failure_class: FailureClass) -> int:
        base_seconds = 30 if failure_class in {FailureClass.TLS_INTERFERENCE, FailureClass.DNS_INTERFERENCE} else 10
        multiplier = min(2 ** max(health.consecutive_failures - 1, 0), 16)
        return min(base_seconds * multiplier, 900)

    def _parse_timestamp(self, value: str) -> datetime:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _flag_expired(self, name: str) -> bool:
        expires_at = self.state.incident_flag_expires_at.get(name)
        if not expires_at or not self.state.incident_flags.get(name):
            return False
        expired = self._parse_timestamp(expires_at) <= datetime.now(timezone.utc)
        if expired and name.startswith("disable_transport_"):
            transport = name.removeprefix("disable_transport_")
            self.state.transport_reenable_pending[transport] = True
            self.schedule_transport_reenable_probe(transport, base_delay_seconds=0)
        return expired

    def _transport_jitter_seconds(self, transport: str) -> int:
        return sum(ord(char) for char in transport) % 7
