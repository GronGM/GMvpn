from __future__ import annotations

from vpn_client.client_platform import ClientPlatform
from vpn_client.models import Endpoint


class DesktopPolicyError(Exception):
    """Raised when desktop policy metadata is malformed."""


def desktop_policy(metadata: dict[str, object]) -> dict[str, object]:
    policy = metadata.get("desktop_policy")
    if isinstance(policy, dict):
        return policy
    return {}


def endpoint_declares_desktop_policy(endpoint: Endpoint) -> bool:
    metadata = endpoint.metadata
    return "desktop_policy" in metadata or any(str(key).startswith("desktop_") for key in metadata)


def validate_desktop_policy_endpoint_metadata(endpoint: Endpoint) -> None:
    policy = desktop_policy(endpoint.metadata)
    rank_priority = policy.get("rank_priority")
    if rank_priority is not None and not isinstance(rank_priority, int):
        raise DesktopPolicyError(f"endpoint '{endpoint.id}' has non-integer desktop rank_priority")

    ranks = policy.get("platform_rank_priority")
    if ranks is not None:
        if not isinstance(ranks, dict):
            raise DesktopPolicyError(f"endpoint '{endpoint.id}' has invalid platform_rank_priority block")
        valid_platforms = {
            ClientPlatform.LINUX.value,
            ClientPlatform.WINDOWS.value,
            ClientPlatform.MACOS.value,
            ClientPlatform.SIMULATED.value,
        }
        for platform_name, value in ranks.items():
            if platform_name not in valid_platforms:
                raise DesktopPolicyError(
                    f"endpoint '{endpoint.id}' references unsupported desktop platform '{platform_name}'"
                )
            if not isinstance(value, int):
                raise DesktopPolicyError(
                    f"endpoint '{endpoint.id}' has non-integer desktop rank for '{platform_name}'"
                )


def desktop_rank_priority(endpoint: Endpoint, client_platform: ClientPlatform | None) -> int:
    policy = desktop_policy(endpoint.metadata)
    ranks = policy.get("platform_rank_priority")
    if isinstance(ranks, dict) and client_platform is not None:
        value = ranks.get(client_platform.value)
        if isinstance(value, int):
            return value
    rank_priority = policy.get("rank_priority", endpoint.metadata.get("desktop_rank_priority", 100))
    if isinstance(rank_priority, int):
        return rank_priority
    return 100
