from __future__ import annotations

from typing import Protocol

from vpn_client.models import FailureClass, Manifest, SessionState
from vpn_client.policy import PolicyEngine
from vpn_client.state import StateManager


class _ReportLike(Protocol):
    state: SessionState
    selected_endpoint_id: str | None
    selected_transport: str | None
    failure_class: FailureClass


class _RecoveryReportLike(Protocol):
    stale_marker_found: bool


MITIGATION_FLAG_NAMES = {"force_system_dns_fallback"}
MITIGATION_FLAG_PREFIXES = ("disable_transport_",)


def _active_incident_flags(state_manager: StateManager) -> list[str]:
    return sorted(
        name
        for name in state_manager.state.incident_flags
        if state_manager.incident_flag(name)
    )


def _is_mitigation_flag(name: str) -> bool:
    return name in MITIGATION_FLAG_NAMES or any(
        name.startswith(prefix)
        for prefix in MITIGATION_FLAG_PREFIXES
    )


def _transport_issue_priority(item: dict[str, object], selected_transport: str | None) -> tuple[int, int, str]:
    if item["disabled"]:
        severity_rank = 0
    elif item["pending_reenable"]:
        severity_rank = 1
    elif item["crash_bucket"] is not None:
        severity_rank = 2
    elif item["soft_fail_bucket"] is not None:
        severity_rank = 3
    else:
        severity_rank = 4

    selected_rank = 0 if item["transport"] == selected_transport else 1
    return severity_rank, selected_rank, str(item["transport"])


def build_incident_summary(
    state_manager: StateManager,
    report: _ReportLike,
    recovery_report: _RecoveryReportLike,
    recovery_cleanup_enabled: bool,
    simulated_stale_runtime_endpoint_id: str | None,
    manifest: Manifest | None = None,
    policy_engine: PolicyEngine | None = None,
) -> dict[str, object]:
    active_incident_flags = _active_incident_flags(state_manager)
    active_disable_flags = sorted(
        name
        for name in active_incident_flags
        if name.startswith("disable_transport_")
    )
    active_mitigation_flags = sorted(
        name
        for name in active_incident_flags
        if _is_mitigation_flag(name)
    )
    mitigation_flag_expires_at = {
        name: state_manager.state.incident_flag_expires_at.get(name)
        for name in active_mitigation_flags
        if name in state_manager.state.incident_flag_expires_at
    }
    cooling_down_endpoints = sorted(
        endpoint_id
        for endpoint_id in state_manager.state.endpoint_health
        if state_manager.is_cooling_down(endpoint_id)
    )
    reenable_pending_transports = sorted(
        transport
        for transport, pending in state_manager.state.transport_reenable_pending.items()
        if pending
    )
    transport_focus = [
        {
            "transport": transport,
            "disabled": bool(state_manager.state.incident_flags.get(f"disable_transport_{transport}", False)),
            "pending_reenable": bool(state_manager.state.transport_reenable_pending.get(transport, False)),
            "crash_bucket": state_manager.state.transport_crash_buckets.get(transport),
            "crash_reason": state_manager.state.transport_crash_reasons.get(transport),
            "soft_fail_bucket": state_manager.state.transport_soft_fail_buckets.get(transport),
        }
        for transport in sorted(
            {
                *state_manager.state.transport_crash_buckets.keys(),
                *state_manager.state.transport_crash_reasons.keys(),
                *state_manager.state.transport_soft_fail_buckets.keys(),
                *state_manager.state.transport_reenable_pending.keys(),
                *{
                    name.removeprefix("disable_transport_")
                    for name in active_disable_flags
                },
            }
        )
    ]
    primary_transport_issue_candidates = [
        item
        for item in transport_focus
        if (
            item["disabled"]
            or item["pending_reenable"]
            or item["crash_bucket"] is not None
            or item["crash_reason"] is not None
            or item["soft_fail_bucket"] is not None
        )
    ]
    primary_transport_issue = (
        min(
            primary_transport_issue_candidates,
            key=lambda item: _transport_issue_priority(item, report.selected_transport),
        )
        if primary_transport_issue_candidates
        else None
    )
    last_crash_transport = next(
        (
            transport
            for transport in sorted(state_manager.state.transport_crash_reasons)
            if state_manager.state.transport_crash_reasons.get(transport)
        ),
        None,
    )
    last_crash_reason = (
        state_manager.state.transport_crash_reasons.get(last_crash_transport)
        if last_crash_transport
        else None
    )
    startup_recovery_triggered = bool(recovery_report.stale_marker_found and recovery_cleanup_enabled)

    if startup_recovery_triggered:
        headline = "startup recovery handled a stale runtime marker"
        severity = "warning"
        recommended_action = "Review the last crash reason and monitor the recovered transport for repeat failures."
    elif report.state in {SessionState.DEGRADED, SessionState.FAILED}:
        headline = "session did not connect and needs investigation"
        guidance = (policy_engine or PolicyEngine(state_manager=state_manager)).incident_guidance_for_failure(
            report.failure_class,
            manifest=manifest,
        )
        severity = guidance.severity
        recommended_action = guidance.recommended_action
    elif active_disable_flags:
        headline = "one or more transports are locally disabled"
        severity = "warning"
        recommended_action = "Inspect the disabled transport state before re-enabling it on affected clients."
    elif active_mitigation_flags:
        headline = "one or more local failure mitigations are active"
        severity = "warning"
        recommended_action = "Review active mitigation flags and confirm they expire after the affected network condition clears."
    elif cooling_down_endpoints:
        headline = "one or more endpoints are cooling down after recent failures"
        severity = "info"
        recommended_action = "Allow cooldown to expire or inspect the failing endpoints if degradation persists."
    elif report.state is SessionState.CONNECTED:
        headline = "session connected without active incident flags"
        severity = "ok"
        recommended_action = "No immediate action required."
    else:
        headline = "session did not connect and needs investigation"
        severity = "critical"
        recommended_action = "Collect the support bundle and inspect the last failed transport and endpoint path."

    return {
        "headline": headline,
        "severity": severity,
        "recommended_action": recommended_action,
        "session_outcome": report.state.value,
        "failure_class": report.failure_class.value,
        "startup_recovery_triggered": startup_recovery_triggered,
        "simulated_stale_runtime_endpoint_id": simulated_stale_runtime_endpoint_id,
        "selected_endpoint_id": report.selected_endpoint_id,
        "selected_transport": report.selected_transport,
        "active_incident_flags": active_incident_flags,
        "active_disable_flags": active_disable_flags,
        "active_mitigation_flags": active_mitigation_flags,
        "mitigation_flag_expires_at": mitigation_flag_expires_at,
        "cooling_down_endpoints": cooling_down_endpoints,
        "reenable_pending_transports": reenable_pending_transports,
        "transport_focus": transport_focus,
        "primary_transport_issue": primary_transport_issue,
        "last_crash_transport": last_crash_transport,
        "last_crash_reason": last_crash_reason,
    }
