from __future__ import annotations

from dataclasses import dataclass

from vpn_client.state import StateManager
from vpn_client.models import DnsMode, FailureClass, Manifest, NetworkPolicy, TunnelMode


@dataclass(slots=True)
class IncidentGuidance:
    severity: str
    recommended_action: str


def validate_incident_guidance_overrides(overrides: object) -> None:
    if not isinstance(overrides, dict):
        raise ValueError("incident_guidance_overrides must be an object")

    valid_failure_classes = {failure_class.value for failure_class in FailureClass if failure_class is not FailureClass.NONE}
    valid_severities = {"ok", "info", "warning", "critical"}

    for failure_name, override in overrides.items():
        if failure_name not in valid_failure_classes:
            raise ValueError(f"unsupported incident guidance override key: {failure_name}")
        if not isinstance(override, dict):
            raise ValueError(f"incident guidance override for {failure_name} must be an object")

        severity = override.get("severity")
        recommended_action = override.get("recommended_action")

        if severity not in valid_severities:
            raise ValueError(f"incident guidance override for {failure_name} has invalid severity")
        if not isinstance(recommended_action, str) or not recommended_action.strip():
            raise ValueError(f"incident guidance override for {failure_name} must include a non-empty recommended_action")


class PolicyEngine:
    """
    Produces a concrete local network policy from the signed manifest.
    Feature flags can only reduce capability or relax behavior in bounded ways.
    """

    def __init__(
        self,
        state_manager: StateManager | None = None,
        local_incident_guidance_overrides: dict[str, object] | None = None,
    ):
        self.state_manager = state_manager
        self.local_incident_guidance_overrides = local_incident_guidance_overrides

    def resolve_network_policy(self, manifest: Manifest) -> NetworkPolicy:
        policy = manifest.network_policy
        features = manifest.features
        disable_kill_switch = features.get("disable_kill_switch", False)
        force_system_dns_fallback = features.get("allow_system_dns_fallback", False)

        if self.state_manager and self.state_manager.incident_flag("force_system_dns_fallback"):
            force_system_dns_fallback = True
        if self.state_manager and self.state_manager.incident_flag("disable_kill_switch"):
            disable_kill_switch = True

        return NetworkPolicy(
            tunnel_mode=TunnelMode.SPLIT if features.get("force_split_tunnel", False) else policy.tunnel_mode,
            dns_mode=(
                DnsMode.SYSTEM_FALLBACK
                if force_system_dns_fallback
                else policy.dns_mode
            ),
            kill_switch_enabled=False if disable_kill_switch else policy.kill_switch_enabled,
            ipv6_enabled=policy.ipv6_enabled and not features.get("disable_ipv6", False),
            allow_lan_while_connected=policy.allow_lan_while_connected,
        )

    def incident_guidance_for_failure(self, failure_class: FailureClass, manifest: Manifest | None = None) -> IncidentGuidance:
        override = self._incident_guidance_override(failure_class, manifest)
        if override is not None:
            return override
        if failure_class in {FailureClass.DNS_INTERFERENCE, FailureClass.TLS_INTERFERENCE}:
            return IncidentGuidance(
                severity="warning",
                recommended_action="Try an alternate transport or resolver path and inspect local interference signals before retrying.",
            )
        if failure_class in {FailureClass.UDP_BLOCKED, FailureClass.TCP_BLOCKED}:
            return IncidentGuidance(
                severity="warning",
                recommended_action="Retry using a transport on a different protocol or port profile and verify upstream filtering.",
            )
        if failure_class is FailureClass.NETWORK_DOWN:
            return IncidentGuidance(
                severity="critical",
                recommended_action="Check local network reachability and dataplane backend health before attempting another connection.",
            )
        if failure_class is FailureClass.ENDPOINT_DOWN:
            return IncidentGuidance(
                severity="warning",
                recommended_action="Fail over to another endpoint and verify reachability of the affected server before re-enabling it.",
            )
        return IncidentGuidance(
            severity="critical",
            recommended_action="Collect the support bundle and inspect the last failed transport and endpoint path.",
        )

    def _incident_guidance_override(
        self,
        failure_class: FailureClass,
        manifest: Manifest | None,
    ) -> IncidentGuidance | None:
        if self.local_incident_guidance_overrides is not None:
            override = self._incident_guidance_from_mapping(self.local_incident_guidance_overrides, failure_class)
            if override is not None:
                return override
        if manifest is None:
            return None

        overrides = manifest.features.get("incident_guidance_overrides")
        return self._incident_guidance_from_mapping(overrides, failure_class)

    def _incident_guidance_from_mapping(
        self,
        overrides: object,
        failure_class: FailureClass,
    ) -> IncidentGuidance | None:
        if not isinstance(overrides, dict):
            return None
        override = overrides.get(failure_class.value)
        if not isinstance(override, dict):
            return None

        severity = override.get("severity")
        recommended_action = override.get("recommended_action")
        if severity not in {"ok", "info", "warning", "critical"}:
            return None
        if not isinstance(recommended_action, str) or not recommended_action.strip():
            return None

        return IncidentGuidance(
            severity=severity,
            recommended_action=recommended_action.strip(),
        )
