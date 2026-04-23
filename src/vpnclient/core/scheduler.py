from __future__ import annotations

from datetime import datetime

from vpnclient.core.models import Endpoint


class EndpointScheduler:
    def rank(self, endpoints: list[Endpoint], state: dict) -> list[Endpoint]:
        health = state["endpoint_health"]
        lkg = state.get("last_known_good_endpoint")
        disabled = {
            name.removeprefix("disable_transport_")
            for name, enabled in state["incident_flags"].items()
            if enabled and name.startswith("disable_transport_")
        }

        filtered = [ep for ep in endpoints if ep.transport not in disabled]

        def score(ep: Endpoint) -> tuple[int, int, int]:
            entry = health.get(ep.name, {})
            cooldown_until = entry.get("cooldown_until")
            cooling = 0
            if cooldown_until:
                cooldown_dt = datetime.fromisoformat(cooldown_until)
                if cooldown_dt > datetime.now(cooldown_dt.tzinfo):
                    cooling = 1
            lkg_bonus = -1 if ep.name == lkg else 0
            return (cooling, -int(entry.get("score", 0)), ep.priority + lkg_bonus)

        return sorted(filtered, key=score)
