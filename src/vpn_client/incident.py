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


def build_incident_summary(
    state_manager: StateManager,
    report: _ReportLike,
    recovery_report: _RecoveryReportLike,
    recovery_cleanup_enabled: bool,
    simulated_stale_runtime_endpoint_id: str | None,
    manifest: Manifest | None = None,
    policy_engine: PolicyEngine | None = None,
) -> dict[str, object]:
    active_disable_flags = sorted(
        name
        for name, enabled in state_manager.state.incident_flags.items()
        if enabled and name.startswith("disable_transport_")
    )
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
    elif cooling_down_endpoints:
        headline = "one or more endpoints are cooling down after recent failures"
        severity = "info"
        recommended_action = "Allow cooldown to expire or inspect the failing endpoints if degradation persists."
    elif report.state in {SessionState.IDLE, SessionState.LOADING, SessionState.PROBING, SessionState.CONNECTING}:
        headline = "no active runtime incidents detected"
        severity = "ok"
        recommended_action = "No immediate action required."
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
        "active_disable_flags": active_disable_flags,
        "cooling_down_endpoints": cooling_down_endpoints,
        "reenable_pending_transports": reenable_pending_transports,
        "last_crash_transport": last_crash_transport,
        "last_crash_reason": last_crash_reason,
    }
