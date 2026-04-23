from __future__ import annotations

from dataclasses import dataclass

from vpn_client.models import Endpoint, Manifest
from vpn_client.state import StateManager


@dataclass(slots=True)
class ScheduledEndpoint:
    endpoint: Endpoint
    cooling_down: bool
    cooldown_remaining_seconds: int
    score: int
    pending_reenable: bool = False
    reenable_ready: bool = False


class EndpointScheduler:
    def __init__(self, state_manager: StateManager | None = None):
        self.state_manager = state_manager

    def schedule(
        self,
        manifest: Manifest,
        last_known_good_endpoint_id: str | None = None,
    ) -> list[ScheduledEndpoint]:
        transport_order = {name: index for index, name in enumerate(manifest.transport_policy.preferred_order)}

        def build(endpoint: Endpoint) -> ScheduledEndpoint:
            if not self.state_manager:
                return ScheduledEndpoint(
                    endpoint=endpoint,
                    cooling_down=False,
                    cooldown_remaining_seconds=0,
                    score=0,
                )
            return ScheduledEndpoint(
                endpoint=endpoint,
                cooling_down=self.state_manager.is_cooling_down(endpoint.id),
                cooldown_remaining_seconds=self.state_manager.cooldown_remaining_seconds(endpoint.id),
                score=self.state_manager.score_for(endpoint.id),
                pending_reenable=self.state_manager.transport_reenable_pending(endpoint.transport),
                reenable_ready=self.state_manager.transport_reenable_ready(endpoint.transport),
            )

        candidate_endpoints = manifest.endpoints
        if self.state_manager:
            filtered = [
                endpoint
                for endpoint in manifest.endpoints
                if not self.state_manager.incident_flag(f"disable_transport_{endpoint.transport}")
            ]
            candidate_endpoints = filtered or manifest.endpoints

        scheduled = [build(endpoint) for endpoint in candidate_endpoints]

        def sort_key(item: ScheduledEndpoint):
            transport_rank = transport_order.get(item.endpoint.transport, len(transport_order) + 1)
            last_good_bonus = 0 if item.endpoint.id == last_known_good_endpoint_id else 1
            cooldown_rank = 1 if item.cooling_down else 0
            pending_rank = 1 if item.pending_reenable else 0
            pending_not_ready_rank = 1 if item.pending_reenable and not item.reenable_ready else 0
            health_rank = -item.score
            cooldown_seconds = item.cooldown_remaining_seconds if item.cooling_down else 0
            return (
                cooldown_rank,
                pending_not_ready_rank,
                pending_rank,
                transport_rank,
                last_good_bonus,
                health_rank,
                cooldown_seconds,
                item.endpoint.region,
                item.endpoint.id,
            )

        ordered = sorted(scheduled, key=sort_key)
        budget = max(manifest.transport_policy.retry_budget, 1)
        return ordered[:budget]
