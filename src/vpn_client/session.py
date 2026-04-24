from __future__ import annotations

from dataclasses import dataclass, field

from vpn_client.client_platform import ClientPlatform
from vpn_client.dataplane import DataPlaneBackend, DataPlaneError, NullDataPlane
from vpn_client.health import HealthPolicy, SessionHealthMonitor
from vpn_client.incident import build_incident_summary
from vpn_client.models import ConnectionAttempt, FailureClass, FailureReasonCode, Manifest, SessionState
from vpn_client.platform import NetworkStackError
from vpn_client.platform_adapters import BasePlatformAdapter, PlatformNetworkAdapter
from vpn_client.policy import PolicyEngine
from vpn_client.probe import ProbeEngine
from vpn_client.runtime import RuntimeState
from vpn_client.runtime_tick import RuntimeTickPolicy, RuntimeTickReport
from vpn_client.scheduler import EndpointScheduler
from vpn_client.state import StateManager
from vpn_client.telemetry import TelemetryRecorder
from vpn_client.transport import Transport
from vpn_client.transport_base import TransportError


@dataclass(slots=True)
class SessionReport:
    state: SessionState
    attempts: list[ConnectionAttempt] = field(default_factory=list)
    selected_endpoint_id: str | None = None
    selected_transport: str | None = None
    applied_tunnel_mode: str | None = None
    kill_switch_active: bool = False
    failure_class: FailureClass = FailureClass.NONE
    reason_code: FailureReasonCode = FailureReasonCode.NONE
    detail: str = ""


class SessionOrchestrator:
    def __init__(
        self,
        transports: dict[str, Transport],
        probe_engine: ProbeEngine,
        policy_engine: PolicyEngine | None = None,
        network_stack: PlatformNetworkAdapter | None = None,
        telemetry: TelemetryRecorder | None = None,
        state_manager: StateManager | None = None,
        dataplane: DataPlaneBackend | None = None,
        runtime_state: RuntimeState | None = None,
        client_platform: ClientPlatform | None = None,
    ):
        self.transports = transports
        self.probe_engine = probe_engine
        self.policy_engine = policy_engine or PolicyEngine()
        self.network_stack = network_stack or BasePlatformAdapter()
        self.telemetry = telemetry or TelemetryRecorder()
        self.state_manager = state_manager
        self.dataplane = dataplane or NullDataPlane()
        self.runtime_state = runtime_state
        self.client_platform = client_platform
        self.scheduler = EndpointScheduler(state_manager=state_manager)
        self.health_monitor = SessionHealthMonitor(self.dataplane, self.network_stack, self.telemetry)
        self.state = SessionState.IDLE
        self.last_known_good_endpoint_id: str | None = None

    def _cleanup_after_failed_attempt(self, transport: Transport, disconnect_network_stack: bool) -> None:
        transport.disconnect()
        if disconnect_network_stack:
            self.network_stack.disconnect()
        self.dataplane.disconnect()
        if self.runtime_state:
            self.runtime_state.clear()

    def connect(self, manifest: Manifest) -> SessionReport:
        self.state = SessionState.LOADING
        attempts: list[ConnectionAttempt] = []
        network_policy = self.policy_engine.resolve_network_policy(manifest)
        self.telemetry.record("session_start", self.state)

        scheduled_endpoints = self.scheduler.schedule(
            manifest,
            last_known_good_endpoint_id=self.last_known_good_endpoint_id,
            client_platform=self.client_platform,
        )
        self.state = SessionState.PROBING

        last_failure = FailureClass.UNKNOWN
        last_reason_code = FailureReasonCode.UNKNOWN
        last_detail = "no endpoints available"
        last_endpoint_id: str | None = None
        last_transport: str | None = None

        for scheduled in scheduled_endpoints:
            endpoint = scheduled.endpoint
            last_endpoint_id = endpoint.id
            last_transport = endpoint.transport
            if scheduled.cooling_down:
                self.telemetry.record(
                    "endpoint_cooling_down",
                    self.state,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=f"cooldown remaining {scheduled.cooldown_remaining_seconds}s",
                )
            if scheduled.pending_reenable:
                self.telemetry.record(
                    "transport_reenable_probe",
                    self.state,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail="transport is being re-evaluated after local disable expiry",
                )
            probe = self.probe_engine.probe(endpoint)
            if not probe.reachable:
                mitigation_actions: list[str] = []
                if self.state_manager and scheduled.pending_reenable:
                    self.state_manager.mark_transport_reenable_pending(endpoint.transport, False)
                    self.state_manager.set_incident_flag_with_ttl(
                        f"disable_transport_{endpoint.transport}",
                        True,
                        ttl_seconds=120,
                    )
                if self.state_manager:
                    self.state_manager.mark_failure_with_reason(
                        endpoint.id,
                        probe.failure_class,
                        probe.reason_code,
                        probe.detail,
                    )
                    mitigation_actions = self.state_manager.apply_failure_mitigation(
                        probe.failure_class,
                        transport=endpoint.transport,
                    )
                self.telemetry.record(
                    "probe_failed",
                    self.state,
                    probe.failure_class,
                    reason_code=probe.reason_code,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=(
                        f"{probe.detail}; mitigations={','.join(mitigation_actions)}"
                        if mitigation_actions
                        else probe.detail
                    ),
                )
                attempts.append(
                    ConnectionAttempt(
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        success=False,
                        failure_class=probe.failure_class,
                        reason_code=probe.reason_code,
                        detail=(
                            f"{probe.detail}; mitigations={','.join(mitigation_actions)}"
                            if mitigation_actions
                            else probe.detail
                        ),
                    )
                )
                last_failure = probe.failure_class
                last_reason_code = probe.reason_code
                last_detail = (
                    f"{probe.detail}; mitigations={','.join(mitigation_actions)}"
                    if mitigation_actions
                    else probe.detail
                )
                continue

            transport = self.transports.get(endpoint.transport)
            if transport is None:
                if self.state_manager:
                    self.state_manager.mark_failure_with_reason(
                        endpoint.id,
                        FailureClass.UNKNOWN,
                        FailureReasonCode.TRANSPORT_NOT_REGISTERED,
                        "transport is not registered",
                    )
                attempts.append(
                    ConnectionAttempt(
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        success=False,
                        failure_class=FailureClass.UNKNOWN,
                        reason_code=FailureReasonCode.TRANSPORT_NOT_REGISTERED,
                        detail=f"transport '{endpoint.transport}' is not registered",
                    )
                )
                last_failure = FailureClass.UNKNOWN
                last_reason_code = FailureReasonCode.TRANSPORT_NOT_REGISTERED
                last_detail = "transport is not registered"
                continue

            self.state = SessionState.CONNECTING
            try:
                transport.connect(endpoint)
                apply_fn = self.network_stack.reconnect if self.network_stack.applied_state else self.network_stack.apply
                applied = apply_fn(endpoint, network_policy)
                self.dataplane.connect(endpoint)
                health_report = self.health_monitor.check(endpoint)
                if not health_report.healthy:
                    raise DataPlaneError(
                        health_report.failure_class,
                        health_report.detail,
                        reason_code=health_report.reason_code,
                    )
                self.state = SessionState.CONNECTED
                self.last_known_good_endpoint_id = endpoint.id
                self.telemetry.record(
                    "connect_succeeded",
                    self.state,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail="transport, network policy, and initial health check passed",
                )
                attempts.append(
                    ConnectionAttempt(
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        success=True,
                        failure_class=FailureClass.NONE,
                        reason_code=FailureReasonCode.NONE,
                        detail="connected",
                    )
                )
                if self.state_manager:
                    self.state_manager.mark_success(endpoint.id)
                    self.state_manager.clear_transport_crash_streak(endpoint.transport)
                    if scheduled.pending_reenable:
                        self.state_manager.mark_transport_reenable_pending(endpoint.transport, False)
                if self.runtime_state:
                    self.runtime_state.mark_active(endpoint.id, endpoint.transport)
                return SessionReport(
                    state=self.state,
                    attempts=attempts,
                    selected_endpoint_id=endpoint.id,
                    selected_transport=endpoint.transport,
                    applied_tunnel_mode=applied.tunnel_mode,
                    kill_switch_active=self.network_stack.kill_switch_active,
                    detail="session established",
                )
            except TransportError as exc:
                if self.state_manager:
                    self.state_manager.mark_failure_with_reason(
                        endpoint.id,
                        exc.failure_class,
                        exc.reason_code,
                        exc.detail,
                    )
                    if scheduled.pending_reenable:
                        self.state_manager.mark_transport_reenable_pending(endpoint.transport, False)
                        self.state_manager.set_incident_flag_with_ttl(
                            f"disable_transport_{endpoint.transport}",
                            True,
                            ttl_seconds=120,
                        )
                self.telemetry.record(
                    "connect_failed",
                    self.state,
                    exc.failure_class,
                    reason_code=exc.reason_code,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=exc.detail,
                )
                attempts.append(
                    ConnectionAttempt(
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        success=False,
                        failure_class=exc.failure_class,
                        reason_code=exc.reason_code,
                        detail=exc.detail,
                    )
                )
                last_failure = exc.failure_class
                last_reason_code = exc.reason_code
                last_detail = exc.detail
            except DataPlaneError as exc:
                disabled_transport = False
                runtime_snapshot = self.dataplane.runtime_snapshot()
                self._cleanup_after_failed_attempt(transport, disconnect_network_stack=True)
                if self.state_manager:
                    self.state_manager.mark_failure_with_reason(
                        endpoint.id,
                        exc.failure_class,
                        exc.reason_code,
                        exc.detail,
                    )
                    if runtime_snapshot.get("crashed"):
                        disabled_transport = self.state_manager.record_transport_crash(
                            endpoint.transport,
                            runtime_snapshot.get("crash_reason") or exc.detail,
                            threshold=1,
                        )
                    else:
                        disabled_transport = self.state_manager.record_transport_soft_failure(
                            endpoint.transport,
                            exc.failure_class,
                            exc.reason_code,
                            threshold=3,
                        )
                    if scheduled.pending_reenable and not disabled_transport:
                        self.state_manager.mark_transport_reenable_pending(endpoint.transport, False)
                        self.state_manager.set_incident_flag_with_ttl(
                            f"disable_transport_{endpoint.transport}",
                            True,
                            ttl_seconds=120,
                        )
                self.telemetry.record(
                    "dataplane_failed",
                    self.state,
                    exc.failure_class,
                    reason_code=exc.reason_code,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=(
                        f"{exc.detail}; transport disabled locally"
                        if disabled_transport
                        else exc.detail
                    ),
                )
                attempts.append(
                    ConnectionAttempt(
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        success=False,
                        failure_class=exc.failure_class,
                        reason_code=exc.reason_code,
                        detail=(
                            f"{exc.detail}; transport disabled locally"
                            if disabled_transport
                            else exc.detail
                        ),
                    )
                )
                last_failure = exc.failure_class
                last_reason_code = exc.reason_code
                last_detail = (
                    f"{exc.detail}; transport disabled locally"
                    if disabled_transport
                    else exc.detail
                )
            except NetworkStackError as exc:
                self._cleanup_after_failed_attempt(transport, disconnect_network_stack=False)
                if self.state_manager:
                    self.state_manager.mark_failure_with_reason(
                        endpoint.id,
                        exc.failure_class,
                        exc.reason_code,
                        exc.detail,
                    )
                    if scheduled.pending_reenable:
                        self.state_manager.mark_transport_reenable_pending(endpoint.transport, False)
                        self.state_manager.set_incident_flag_with_ttl(
                            f"disable_transport_{endpoint.transport}",
                            True,
                            ttl_seconds=120,
                        )
                self.telemetry.record(
                    "network_policy_failed",
                    self.state,
                    exc.failure_class,
                    reason_code=exc.reason_code,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=exc.detail,
                )
                attempts.append(
                    ConnectionAttempt(
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        success=False,
                        failure_class=exc.failure_class,
                        reason_code=exc.reason_code,
                        detail=exc.detail,
                    )
                )
                last_failure = exc.failure_class
                last_reason_code = exc.reason_code
                last_detail = exc.detail

        self.state = SessionState.DEGRADED if attempts else SessionState.FAILED
        self.telemetry.record(
            "session_degraded",
            self.state,
            last_failure,
            reason_code=last_reason_code,
            endpoint_id=last_endpoint_id,
            transport=last_transport,
            detail=last_detail,
        )
        return SessionReport(
            state=self.state,
            attempts=attempts,
            selected_endpoint_id=last_endpoint_id,
            selected_transport=last_transport,
            kill_switch_active=self.network_stack.kill_switch_active,
            failure_class=last_failure,
            reason_code=last_reason_code,
            detail=last_detail,
        )

    def disconnect_all(self) -> None:
        for transport in self.transports.values():
            transport.disconnect()
        self.dataplane.disconnect()
        self.network_stack.disconnect()
        if self.runtime_state:
            self.runtime_state.clear()
        self.telemetry.record("session_disconnected", SessionState.IDLE)
        self.state = SessionState.IDLE

    def reconnect(self, manifest: Manifest) -> SessionReport:
        self.telemetry.record("session_reconnect_requested", self.state)
        self.disconnect_all()
        return self.connect(manifest)

    def reevaluate_pending_transports(self, manifest: Manifest, limit: int = 1) -> list[str]:
        if not self.state_manager:
            return []

        reenabled: list[str] = []
        for transport_name in self.state_manager.ready_transports_for_reenable()[: max(limit, 1)]:
            endpoint = next((item for item in manifest.endpoints if item.transport == transport_name), None)
            if endpoint is None:
                self.state_manager.mark_transport_reenable_pending(transport_name, False)
                continue

            self.telemetry.record(
                "transport_reenable_tick",
                SessionState.IDLE,
                endpoint_id=endpoint.id,
                transport=transport_name,
                detail="running background re-enable probe",
            )
            probe = self.probe_engine.probe(endpoint)
            if probe.reachable:
                self.state_manager.mark_transport_reenable_pending(transport_name, False)
                self.state_manager.state.transport_reenable_fail_streaks[transport_name] = 0
                self.state_manager.store.save(self.state_manager.state)
                reenabled.append(transport_name)
                self.telemetry.record(
                    "transport_reenabled",
                    SessionState.IDLE,
                    endpoint_id=endpoint.id,
                    transport=transport_name,
                    detail="background probe succeeded",
                )
            else:
                self.state_manager.fail_transport_reenable(transport_name, retry_delay_seconds=120)
                self.telemetry.record(
                    "transport_reenable_failed",
                    SessionState.IDLE,
                    probe.failure_class,
                    endpoint_id=endpoint.id,
                    transport=transport_name,
                    detail=(
                        f"{probe.detail}; fail_streak={self.state_manager.transport_reenable_fail_streak(transport_name)}"
                    ),
                )
        return reenabled

    def runtime_tick(self, manifest: Manifest, policy: RuntimeTickPolicy | None = None) -> RuntimeTickReport:
        if not self.state_manager:
            return RuntimeTickReport(reenabled_transports=[], pending_ready_transports=[], pending_total=0)

        tick_policy = policy or RuntimeTickPolicy()
        pending_ready = self.state_manager.ready_transports_for_reenable()
        pending_total = len(self.state_manager.pending_transports_for_reenable())
        self.telemetry.record(
            "runtime_tick",
            SessionState.IDLE if self.state is SessionState.IDLE else self.state,
            detail=f"pending_ready={len(pending_ready)} pending_total={pending_total}",
        )
        reenabled = self.reevaluate_pending_transports(
            manifest,
            limit=tick_policy.reevaluate_pending_transports_limit,
        )
        return RuntimeTickReport(
            reenabled_transports=reenabled,
            pending_ready_transports=pending_ready,
            pending_total=pending_total,
        )

    def build_incident_summary(
        self,
        manifest: Manifest,
        report: SessionReport,
        recovery_report,
        recovery_cleanup_enabled: bool,
        simulated_stale_runtime_endpoint_id: str | None = None,
    ) -> dict[str, object]:
        if self.state_manager is None:
            raise RuntimeError("incident summary requires a state manager")

        return build_incident_summary(
            state_manager=self.state_manager,
            report=report,
            recovery_report=recovery_report,
            recovery_cleanup_enabled=recovery_cleanup_enabled,
            simulated_stale_runtime_endpoint_id=simulated_stale_runtime_endpoint_id,
            manifest=manifest,
            policy_engine=self.policy_engine,
        )

    def emit_incident_summary(self, report: SessionReport, incident_summary: dict[str, object]) -> None:
        if incident_summary["severity"] == "ok":
            return

        self.telemetry.record(
            "incident_summary",
            report.state,
            FailureClass(incident_summary["failure_class"]),
            reason_code=report.reason_code,
            endpoint_id=report.selected_endpoint_id,
            transport=report.selected_transport,
            detail=(
                f"{incident_summary['severity']}: {incident_summary['headline']}; "
                f"{incident_summary['recommended_action']}"
            ),
        )

    def _degrade_current_session(
        self,
        endpoint,
        failure_class: FailureClass,
        reason_code: FailureReasonCode,
        detail: str,
    ) -> SessionReport:
        applied_state = self.network_stack.applied_state
        applied_tunnel_mode = applied_state.tunnel_mode if applied_state is not None else None
        self.dataplane.disconnect()
        if self.runtime_state:
            self.runtime_state.clear()
        self.state = SessionState.DEGRADED
        self.telemetry.record(
            "session_degraded",
            self.state,
            failure_class,
            reason_code=reason_code,
            endpoint_id=endpoint.id,
            transport=endpoint.transport,
            detail=detail,
        )
        return SessionReport(
            state=self.state,
            selected_endpoint_id=endpoint.id,
            selected_transport=endpoint.transport,
            applied_tunnel_mode=applied_tunnel_mode,
            kill_switch_active=self.network_stack.kill_switch_active,
            failure_class=failure_class,
            reason_code=reason_code,
            detail=detail,
        )

    def monitor_connection(self, manifest: Manifest, checks: int = 1, auto_reconnect: bool = False) -> SessionReport | None:
        if self.state is not SessionState.CONNECTED or self.network_stack.applied_state is None:
            return None

        endpoint_id = self.network_stack.applied_state.endpoint_id
        endpoint = next((item for item in manifest.endpoints if item.id == endpoint_id), None)
        if endpoint is None:
            return None

        reports = self.health_monitor.run_cycle(
            endpoint,
            HealthPolicy(checks=checks, auto_reconnect=auto_reconnect),
        )
        for report in reports:
            if report.healthy:
                had_pending_failure = False
                if self.state_manager:
                    had_pending_failure = self.state_manager.clear_session_health_failure()
                    self.state_manager.clear_transport_soft_failures(endpoint.transport)
                if had_pending_failure:
                    self.telemetry.record(
                        "session_health_recovered",
                        SessionState.CONNECTED,
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        detail="transient health failure recovered before degradation threshold",
                    )
                continue

            if self.state_manager is None:
                if auto_reconnect:
                    self.telemetry.record(
                        "session_auto_reconnect",
                        SessionState.CONNECTED,
                        report.failure_class,
                        reason_code=report.reason_code,
                        endpoint_id=endpoint.id,
                        transport=endpoint.transport,
                        detail=report.detail,
                    )
                    return self.reconnect(manifest)
                return self._degrade_current_session(
                    endpoint,
                    report.failure_class,
                    report.reason_code,
                    report.detail,
                )

            confirmed_failure = False
            disabled_transport = False
            runtime_snapshot = self.dataplane.runtime_snapshot()
            self.state_manager.mark_failure_with_reason(
                endpoint.id,
                report.failure_class,
                report.reason_code,
                report.detail,
            )
            if runtime_snapshot.get("crashed"):
                self.state_manager.clear_session_health_failure()
                disabled_transport = self.state_manager.record_transport_crash(
                    endpoint.transport,
                    runtime_snapshot.get("crash_reason") or report.detail,
                    threshold=1,
                )
                confirmed_failure = True
            else:
                disabled_transport = self.state_manager.record_transport_soft_failure(
                    endpoint.transport,
                    report.failure_class,
                    report.reason_code,
                    threshold=3,
                )
                confirmed_failure = self.state_manager.record_session_health_failure(
                    report.failure_class,
                    report.reason_code,
                    threshold=3,
                )

            failure_detail = report.detail
            if disabled_transport:
                failure_detail = f"{failure_detail}; transport disabled locally"

            if not confirmed_failure:
                pending_streak = self.state_manager.state.session_health_fail_streak if self.state_manager else 1
                self.telemetry.record(
                    "session_health_suppressed",
                    SessionState.CONNECTED,
                    report.failure_class,
                    reason_code=report.reason_code,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=f"{failure_detail}; streak={pending_streak}/3",
                )
                continue

            if auto_reconnect:
                self.telemetry.record(
                    "session_auto_reconnect",
                    SessionState.CONNECTED,
                    report.failure_class,
                    reason_code=report.reason_code,
                    endpoint_id=endpoint.id,
                    transport=endpoint.transport,
                    detail=failure_detail,
                )
                return self.reconnect(manifest)
            return self._degrade_current_session(
                endpoint,
                report.failure_class,
                report.reason_code,
                failure_detail,
            )
        return SessionReport(
            state=self.state,
            selected_endpoint_id=endpoint.id,
            selected_transport=endpoint.transport,
            applied_tunnel_mode=self.network_stack.applied_state.tunnel_mode,
            kill_switch_active=self.network_stack.kill_switch_active,
            detail="health checks passed",
        )
