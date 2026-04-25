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


@dataclass(slots=True)
class EndpointSelectionSummary:
    selected_endpoint_id: str
    selected_transport: str
    client_platform: str | None
    platform_rank: int
    transport_rank: int
    was_last_known_good: bool
    cooling_down: bool
    cooldown_remaining_seconds: int
    pending_reenable: bool
    reenable_ready: bool
    health_score: int
    retry_budget: int
    candidate_order: list[str]
    summary: str


class EndpointScheduler:
    def __init__(self, state_manager: StateManager | None = None):
        self.state_manager = state_manager

    def schedule(
        self,
        manifest: Manifest,
        last_known_good_endpoint_id: str | None = None,
        client_platform: ClientPlatform | None = None,
    ) -> list[ScheduledEndpoint]:
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
            return self._sort_key(
                item,
                manifest=manifest,
                last_known_good_endpoint_id=last_known_good_endpoint_id,
                client_platform=client_platform,
            )

        ordered = sorted(scheduled, key=sort_key)
        budget = max(manifest.transport_policy.retry_budget, 1)
        return ordered[:budget]

    def summarize_selection(
        self,
        scheduled_endpoints: list[ScheduledEndpoint],
        selected_endpoint_id: str | None,
        manifest: Manifest,
        last_known_good_endpoint_id: str | None = None,
        client_platform: ClientPlatform | None = None,
    ) -> EndpointSelectionSummary | None:
        if selected_endpoint_id is None:
            return None
        selected = next(
            (item for item in scheduled_endpoints if item.endpoint.id == selected_endpoint_id),
            None,
        )
        if selected is None:
            return None

        transport_rank = self._transport_rank(selected.endpoint, manifest)
        platform_rank = self._platform_rank(selected.endpoint, client_platform)
        summary_parts = [
            f"selected {selected.endpoint.id}",
            f"transport {selected.endpoint.transport} ranked {transport_rank + 1}/{max(len(manifest.transport_policy.preferred_order), 1)}",
            f"platform rank {platform_rank}",
        ]
        if client_platform is not None:
            summary_parts.append(f"client platform {client_platform.value}")
        if selected.endpoint.id == last_known_good_endpoint_id:
            summary_parts.append("matched last-known-good endpoint")
        if selected.cooling_down:
            summary_parts.append(f"cooldown active ({selected.cooldown_remaining_seconds}s remaining)")
        else:
            summary_parts.append("not cooling down")
        if selected.pending_reenable:
            if selected.reenable_ready:
                summary_parts.append("transport re-enable probe was ready")
            else:
                summary_parts.append("transport still pending re-enable")
        summary_parts.append(f"health score {selected.score}")
        summary_parts.append("candidate order " + " -> ".join(item.endpoint.id for item in scheduled_endpoints))
        return EndpointSelectionSummary(
            selected_endpoint_id=selected.endpoint.id,
            selected_transport=selected.endpoint.transport,
            client_platform=client_platform.value if client_platform is not None else None,
            platform_rank=platform_rank,
            transport_rank=transport_rank,
            was_last_known_good=selected.endpoint.id == last_known_good_endpoint_id,
            cooling_down=selected.cooling_down,
            cooldown_remaining_seconds=selected.cooldown_remaining_seconds,
            pending_reenable=selected.pending_reenable,
            reenable_ready=selected.reenable_ready,
            health_score=selected.score,
            retry_budget=max(manifest.transport_policy.retry_budget, 1),
            candidate_order=[item.endpoint.id for item in scheduled_endpoints],
            summary="; ".join(summary_parts),
        )

    def _supports_client_platform(self, endpoint: Endpoint, client_platform: ClientPlatform) -> bool:
        supported = endpoint.metadata.get("supported_client_platforms")
        if supported is None:
            return True
        return client_platform.value in supported

    def _transport_rank(self, endpoint: Endpoint, manifest: Manifest) -> int:
        transport_order = {name: index for index, name in enumerate(manifest.transport_policy.preferred_order)}
        return transport_order.get(endpoint.transport, len(transport_order) + 1)

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

    def _sort_key(
        self,
        item: ScheduledEndpoint,
        manifest: Manifest,
        last_known_good_endpoint_id: str | None,
        client_platform: ClientPlatform | None,
    ) -> tuple[int, int, int, int, int, int, int, int, str, str]:
        transport_rank = self._transport_rank(item.endpoint, manifest)
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
