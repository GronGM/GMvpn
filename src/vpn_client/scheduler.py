from __future__ import annotations

from dataclasses import dataclass

from vpn_client.client_platform import ClientPlatform
from vpn_client.android_runtime import android_policy
from vpn_client.desktop_policy import desktop_rank_priority
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
        client_platform: ClientPlatform | None = None,
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
        if client_platform is not None:
            platform_filtered = [
                endpoint
                for endpoint in candidate_endpoints
                if self._supports_client_platform(endpoint, client_platform)
            ]
            candidate_endpoints = platform_filtered or candidate_endpoints
        if self.state_manager:
            # Keep all prior narrowing, especially client-platform filtering. Local
            # transport mitigations must not reintroduce endpoints that are not
            # valid for the current platform.
            filtered = [
                endpoint
                for endpoint in candidate_endpoints
                if not self.state_manager.incident_flag(f"disable_transport_{endpoint.transport}")
            ]
            candidate_endpoints = filtered or candidate_endpoints

        scheduled = [build(endpoint) for endpoint in candidate_endpoints]

        def sort_key(item: ScheduledEndpoint):
            transport_rank = transport_order.get(item.endpoint.transport, len(transport_order) + 1)
            platform_rank = self._platform_rank(item.endpoint, client_platform)
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
                platform_rank,
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

    def _supports_client_platform(self, endpoint: Endpoint, client_platform: ClientPlatform) -> bool:
        supported = endpoint.metadata.get("supported_client_platforms")
        if supported is None:
            return True
        return client_platform.value in supported

    def _platform_rank(self, endpoint: Endpoint, client_platform: ClientPlatform | None) -> int:
        if client_platform is ClientPlatform.ANDROID:
            policy = android_policy(endpoint.metadata)
            value = policy.get("rank_priority", endpoint.metadata.get("android_rank_priority", 100))
            if isinstance(value, int):
                return value
        if client_platform in {
            ClientPlatform.LINUX,
            ClientPlatform.WINDOWS,
            ClientPlatform.MACOS,
            ClientPlatform.SIMULATED,
        }:
            return desktop_rank_priority(endpoint, client_platform)
        return 100
