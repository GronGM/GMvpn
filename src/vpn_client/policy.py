from __future__ import annotations

from dataclasses import dataclass, replace

from vpn_client.client_platform import ClientPlatform
from vpn_client.state import StateManager
from vpn_client.models import DnsMode, FailureClass, Manifest, NetworkPolicy, TunnelMode
from vpn_client.runtime_tick import RuntimeTickPolicy


@dataclass(slots=True)
class IncidentGuidance:
    severity: str
    recommended_action: str


@dataclass(slots=True)
class SessionHealthPolicy:
    checks: int = 0
    auto_reconnect: bool = False
    failure_threshold: int = 3


@dataclass(slots=True)
class RuntimeSupportPolicy:
    enforce_contract_match: bool = False


@dataclass(slots=True)
class TransportReenablePolicy:
    retry_delay_seconds: int = 120
    max_retry_delay_seconds: int = 1800


@dataclass(slots=True)
class TransportFailurePolicy:
    crash_threshold: int = 1
    soft_fail_threshold: int = 3
    crash_disable_ttl_seconds: int = 900
    soft_fail_disable_ttl_seconds: int = 300


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


def validate_session_health_policy(policy: object) -> None:
    if not isinstance(policy, dict):
        raise ValueError("session_health_policy must be an object")

    allowed_keys = {"default", "by_client_platform", "by_transport"}
    unexpected = set(policy) - allowed_keys
    if unexpected:
        raise ValueError(f"session_health_policy contains unsupported keys: {', '.join(sorted(unexpected))}")

    if "default" in policy:
        _validate_session_health_policy_override(policy["default"], context="session_health_policy.default")

    by_client_platform = policy.get("by_client_platform")
    if by_client_platform is not None:
        if not isinstance(by_client_platform, dict):
            raise ValueError("session_health_policy.by_client_platform must be an object")
        valid_platforms = {platform.value for platform in ClientPlatform}
        for platform_name, override in by_client_platform.items():
            if platform_name not in valid_platforms:
                raise ValueError(f"session_health_policy.by_client_platform has unsupported platform '{platform_name}'")
            _validate_session_health_policy_override(
                override,
                context=f"session_health_policy.by_client_platform.{platform_name}",
            )

    by_transport = policy.get("by_transport")
    if by_transport is not None:
        if not isinstance(by_transport, dict):
            raise ValueError("session_health_policy.by_transport must be an object")
        for transport_name, override in by_transport.items():
            if not isinstance(transport_name, str) or not transport_name:
                raise ValueError("session_health_policy.by_transport keys must be non-empty strings")
            _validate_session_health_policy_override(
                override,
                context=f"session_health_policy.by_transport.{transport_name}",
            )


def validate_runtime_support_policy(policy: object) -> None:
    if not isinstance(policy, dict):
        raise ValueError("runtime_support_policy must be an object")

    allowed_keys = {"default"}
    unexpected = set(policy) - allowed_keys
    if unexpected:
        raise ValueError(f"runtime_support_policy contains unsupported keys: {', '.join(sorted(unexpected))}")

    if "default" in policy:
        _validate_runtime_support_policy_override(
            policy["default"],
            context="runtime_support_policy.default",
        )


def validate_runtime_tick_policy(policy: object) -> None:
    if not isinstance(policy, dict):
        raise ValueError("runtime_tick_policy must be an object")

    allowed_keys = {"default"}
    unexpected = set(policy) - allowed_keys
    if unexpected:
        raise ValueError(f"runtime_tick_policy contains unsupported keys: {', '.join(sorted(unexpected))}")

    if "default" in policy:
        _validate_runtime_tick_policy_override(
            policy["default"],
            context="runtime_tick_policy.default",
        )


def validate_transport_reenable_policy(policy: object) -> None:
    if not isinstance(policy, dict):
        raise ValueError("transport_reenable_policy must be an object")

    allowed_keys = {"default", "by_transport"}
    unexpected = set(policy) - allowed_keys
    if unexpected:
        raise ValueError(f"transport_reenable_policy contains unsupported keys: {', '.join(sorted(unexpected))}")

    if "default" in policy:
        _validate_transport_reenable_policy_override(
            policy["default"],
            context="transport_reenable_policy.default",
        )

    by_transport = policy.get("by_transport")
    if by_transport is not None:
        if not isinstance(by_transport, dict):
            raise ValueError("transport_reenable_policy.by_transport must be an object")
        for transport_name, override in by_transport.items():
            if not isinstance(transport_name, str) or not transport_name:
                raise ValueError("transport_reenable_policy.by_transport keys must be non-empty strings")
            _validate_transport_reenable_policy_override(
                override,
                context=f"transport_reenable_policy.by_transport.{transport_name}",
            )


def validate_transport_failure_policy(policy: object) -> None:
    if not isinstance(policy, dict):
        raise ValueError("transport_failure_policy must be an object")

    allowed_keys = {"default", "by_transport"}
    unexpected = set(policy) - allowed_keys
    if unexpected:
        raise ValueError(f"transport_failure_policy contains unsupported keys: {', '.join(sorted(unexpected))}")

    if "default" in policy:
        _validate_transport_failure_policy_override(
            policy["default"],
            context="transport_failure_policy.default",
        )

    by_transport = policy.get("by_transport")
    if by_transport is not None:
        if not isinstance(by_transport, dict):
            raise ValueError("transport_failure_policy.by_transport must be an object")
        for transport_name, override in by_transport.items():
            if not isinstance(transport_name, str) or not transport_name:
                raise ValueError("transport_failure_policy.by_transport keys must be non-empty strings")
            _validate_transport_failure_policy_override(
                override,
                context=f"transport_failure_policy.by_transport.{transport_name}",
            )


def _validate_session_health_policy_override(override: object, context: str) -> None:
    if not isinstance(override, dict):
        raise ValueError(f"{context} must be an object")

    allowed_keys = {"checks", "auto_reconnect", "failure_threshold"}
    unexpected = set(override) - allowed_keys
    if unexpected:
        raise ValueError(f"{context} contains unsupported keys: {', '.join(sorted(unexpected))}")

    checks = override.get("checks")
    if checks is not None and (not isinstance(checks, int) or isinstance(checks, bool) or checks < 0 or checks > 10):
        raise ValueError(f"{context}.checks must be an integer between 0 and 10")

    auto_reconnect = override.get("auto_reconnect")
    if auto_reconnect is not None and not isinstance(auto_reconnect, bool):
        raise ValueError(f"{context}.auto_reconnect must be a boolean")

    failure_threshold = override.get("failure_threshold")
    if failure_threshold is not None and (
        not isinstance(failure_threshold, int)
        or isinstance(failure_threshold, bool)
        or failure_threshold < 1
        or failure_threshold > 5
    ):
        raise ValueError(f"{context}.failure_threshold must be an integer between 1 and 5")


def _validate_runtime_support_policy_override(override: object, context: str) -> None:
    if not isinstance(override, dict):
        raise ValueError(f"{context} must be an object")

    allowed_keys = {"enforce_contract_match"}
    unexpected = set(override) - allowed_keys
    if unexpected:
        raise ValueError(f"{context} contains unsupported keys: {', '.join(sorted(unexpected))}")

    enforce_contract_match = override.get("enforce_contract_match")
    if enforce_contract_match is not None and not isinstance(enforce_contract_match, bool):
        raise ValueError(f"{context}.enforce_contract_match must be a boolean")


def _validate_runtime_tick_policy_override(override: object, context: str) -> None:
    if not isinstance(override, dict):
        raise ValueError(f"{context} must be an object")

    allowed_keys = {"reevaluate_pending_transports_limit"}
    unexpected = set(override) - allowed_keys
    if unexpected:
        raise ValueError(f"{context} contains unsupported keys: {', '.join(sorted(unexpected))}")

    limit = override.get("reevaluate_pending_transports_limit")
    if limit is not None and (
        not isinstance(limit, int)
        or isinstance(limit, bool)
        or limit < 1
        or limit > 5
    ):
        raise ValueError(f"{context}.reevaluate_pending_transports_limit must be an integer between 1 and 5")


def _validate_transport_reenable_policy_override(override: object, context: str) -> None:
    if not isinstance(override, dict):
        raise ValueError(f"{context} must be an object")

    allowed_keys = {"retry_delay_seconds", "max_retry_delay_seconds"}
    unexpected = set(override) - allowed_keys
    if unexpected:
        raise ValueError(f"{context} contains unsupported keys: {', '.join(sorted(unexpected))}")

    retry_delay_seconds = override.get("retry_delay_seconds")
    if retry_delay_seconds is not None and (
        not isinstance(retry_delay_seconds, int)
        or isinstance(retry_delay_seconds, bool)
        or retry_delay_seconds < 60
        or retry_delay_seconds > 900
    ):
        raise ValueError(f"{context}.retry_delay_seconds must be an integer between 60 and 900")

    max_retry_delay_seconds = override.get("max_retry_delay_seconds")
    if max_retry_delay_seconds is not None and (
        not isinstance(max_retry_delay_seconds, int)
        or isinstance(max_retry_delay_seconds, bool)
        or max_retry_delay_seconds < 120
        or max_retry_delay_seconds > 3600
    ):
        raise ValueError(f"{context}.max_retry_delay_seconds must be an integer between 120 and 3600")

    if (
        retry_delay_seconds is not None
        and max_retry_delay_seconds is not None
        and max_retry_delay_seconds < retry_delay_seconds
    ):
        raise ValueError(f"{context}.max_retry_delay_seconds must be greater than or equal to retry_delay_seconds")


def _validate_transport_failure_policy_override(override: object, context: str) -> None:
    if not isinstance(override, dict):
        raise ValueError(f"{context} must be an object")

    allowed_keys = {
        "crash_threshold",
        "soft_fail_threshold",
        "crash_disable_ttl_seconds",
        "soft_fail_disable_ttl_seconds",
    }
    unexpected = set(override) - allowed_keys
    if unexpected:
        raise ValueError(f"{context} contains unsupported keys: {', '.join(sorted(unexpected))}")

    crash_threshold = override.get("crash_threshold")
    if crash_threshold is not None and (
        not isinstance(crash_threshold, int)
        or isinstance(crash_threshold, bool)
        or crash_threshold < 1
        or crash_threshold > 5
    ):
        raise ValueError(f"{context}.crash_threshold must be an integer between 1 and 5")

    soft_fail_threshold = override.get("soft_fail_threshold")
    if soft_fail_threshold is not None and (
        not isinstance(soft_fail_threshold, int)
        or isinstance(soft_fail_threshold, bool)
        or soft_fail_threshold < 1
        or soft_fail_threshold > 5
    ):
        raise ValueError(f"{context}.soft_fail_threshold must be an integer between 1 and 5")

    crash_disable_ttl_seconds = override.get("crash_disable_ttl_seconds")
    if crash_disable_ttl_seconds is not None and (
        not isinstance(crash_disable_ttl_seconds, int)
        or isinstance(crash_disable_ttl_seconds, bool)
        or crash_disable_ttl_seconds < 60
        or crash_disable_ttl_seconds > 3600
    ):
        raise ValueError(f"{context}.crash_disable_ttl_seconds must be an integer between 60 and 3600")

    soft_fail_disable_ttl_seconds = override.get("soft_fail_disable_ttl_seconds")
    if soft_fail_disable_ttl_seconds is not None and (
        not isinstance(soft_fail_disable_ttl_seconds, int)
        or isinstance(soft_fail_disable_ttl_seconds, bool)
        or soft_fail_disable_ttl_seconds < 60
        or soft_fail_disable_ttl_seconds > 1800
    ):
        raise ValueError(f"{context}.soft_fail_disable_ttl_seconds must be an integer between 60 and 1800")


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

    def resolve_session_health_policy(
        self,
        manifest: Manifest,
        client_platform: ClientPlatform | None = None,
        transport: str | None = None,
    ) -> SessionHealthPolicy:
        resolved = SessionHealthPolicy()
        raw_policy = manifest.features.get("session_health_policy")
        if not isinstance(raw_policy, dict):
            return resolved

        resolved = _merge_session_health_policy(resolved, raw_policy.get("default"))
        if client_platform is not None:
            resolved = _merge_session_health_policy(
                resolved,
                raw_policy.get("by_client_platform", {}).get(client_platform.value),
            )
        if transport is not None:
            resolved = _merge_session_health_policy(
                resolved,
                raw_policy.get("by_transport", {}).get(transport),
            )
        return resolved

    def resolve_runtime_support_policy(self, manifest: Manifest) -> RuntimeSupportPolicy:
        resolved = RuntimeSupportPolicy()
        raw_policy = manifest.features.get("runtime_support_policy")
        if not isinstance(raw_policy, dict):
            return resolved

        return _merge_runtime_support_policy(resolved, raw_policy.get("default"))

    def resolve_runtime_tick_policy(self, manifest: Manifest) -> RuntimeTickPolicy:
        resolved = RuntimeTickPolicy()
        raw_policy = manifest.features.get("runtime_tick_policy")
        if not isinstance(raw_policy, dict):
            return resolved

        return _merge_runtime_tick_policy(resolved, raw_policy.get("default"))

    def resolve_transport_reenable_policy(
        self,
        manifest: Manifest,
        transport: str | None = None,
    ) -> TransportReenablePolicy:
        resolved = TransportReenablePolicy()
        raw_policy = manifest.features.get("transport_reenable_policy")
        if not isinstance(raw_policy, dict):
            return resolved

        resolved = _merge_transport_reenable_policy(resolved, raw_policy.get("default"))
        if transport is not None:
            resolved = _merge_transport_reenable_policy(
                resolved,
                raw_policy.get("by_transport", {}).get(transport),
            )
        return resolved

    def resolve_transport_failure_policy(
        self,
        manifest: Manifest,
        transport: str | None = None,
    ) -> TransportFailurePolicy:
        resolved = TransportFailurePolicy()
        raw_policy = manifest.features.get("transport_failure_policy")
        if not isinstance(raw_policy, dict):
            return resolved

        resolved = _merge_transport_failure_policy(resolved, raw_policy.get("default"))
        if transport is not None:
            resolved = _merge_transport_failure_policy(
                resolved,
                raw_policy.get("by_transport", {}).get(transport),
            )
        return resolved

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


def _merge_session_health_policy(base: SessionHealthPolicy, override: object) -> SessionHealthPolicy:
    if not isinstance(override, dict):
        return base

    merged = base
    if "checks" in override:
        merged = replace(merged, checks=override["checks"])
    if "auto_reconnect" in override:
        merged = replace(merged, auto_reconnect=override["auto_reconnect"])
    if "failure_threshold" in override:
        merged = replace(merged, failure_threshold=override["failure_threshold"])
    return merged


def _merge_runtime_support_policy(base: RuntimeSupportPolicy, override: object) -> RuntimeSupportPolicy:
    if not isinstance(override, dict):
        return base

    merged = base
    if "enforce_contract_match" in override:
        merged = replace(merged, enforce_contract_match=override["enforce_contract_match"])
    return merged


def _merge_runtime_tick_policy(base: RuntimeTickPolicy, override: object) -> RuntimeTickPolicy:
    if not isinstance(override, dict):
        return base

    merged = base
    if "reevaluate_pending_transports_limit" in override:
        merged = replace(
            merged,
            reevaluate_pending_transports_limit=override["reevaluate_pending_transports_limit"],
        )
    return merged


def _merge_transport_reenable_policy(base: TransportReenablePolicy, override: object) -> TransportReenablePolicy:
    if not isinstance(override, dict):
        return base

    merged = base
    if "retry_delay_seconds" in override:
        merged = replace(merged, retry_delay_seconds=override["retry_delay_seconds"])
    if "max_retry_delay_seconds" in override:
        merged = replace(merged, max_retry_delay_seconds=override["max_retry_delay_seconds"])
    return merged


def _merge_transport_failure_policy(base: TransportFailurePolicy, override: object) -> TransportFailurePolicy:
    if not isinstance(override, dict):
        return base

    merged = base
    if "crash_threshold" in override:
        merged = replace(merged, crash_threshold=override["crash_threshold"])
    if "soft_fail_threshold" in override:
        merged = replace(merged, soft_fail_threshold=override["soft_fail_threshold"])
    if "crash_disable_ttl_seconds" in override:
        merged = replace(merged, crash_disable_ttl_seconds=override["crash_disable_ttl_seconds"])
    if "soft_fail_disable_ttl_seconds" in override:
        merged = replace(merged, soft_fail_disable_ttl_seconds=override["soft_fail_disable_ttl_seconds"])
    return merged
