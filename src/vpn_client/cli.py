from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from vpn_client.backend_state import BackendStateStore
from vpn_client.client_platform import ClientPlatform, backend_supported_on_platform, default_backend_for_platform
from vpn_client.dataplane import LinuxUserspaceDataPlane, NullDataPlane, RoutedDataPlane
from vpn_client.config import ManifestStore, SignedManifestLoader
from vpn_client.models import FailureClass, FailureReasonCode, SessionState
from vpn_client.platform_adapters import LinuxPlatformAdapter, create_platform_adapter
from vpn_client.policy import PolicyEngine, validate_incident_guidance_overrides
from vpn_client.probe import ProbeEngine
from vpn_client.recovery import StartupRecovery
from vpn_client.runtime import RuntimeState
from vpn_client.runtime_support import assess_runtime_support
from vpn_client.runtime_tick import RuntimeTickPolicy
from vpn_client.security import Ed25519Verifier
from vpn_client.session import SessionOrchestrator, SessionReport
from vpn_client.state import StateManager, StateStore
from vpn_client.supervisor import RuntimeSupervisor
from vpn_client.telemetry import TelemetryRecorder
from vpn_client.transport import default_transport_registry
from vpn_client.ios_bridge import IOSBridgeDataPlane
from vpn_client.xray import XrayCoreDataPlane


def _load_local_incident_guidance_overrides(
    parser: argparse.ArgumentParser,
    explicit_path: Path | None,
    cache_dir: Path,
) -> tuple[dict[str, object] | None, Path | None]:
    guidance_path = explicit_path
    if guidance_path is None:
        candidate = cache_dir / "incident-guidance.json"
        if candidate.exists():
            guidance_path = candidate

    if guidance_path is None:
        return None, None

    try:
        overrides = json.loads(guidance_path.read_text(encoding="utf-8"))
        validate_incident_guidance_overrides(overrides)
        return overrides, guidance_path
    except FileNotFoundError:
        parser.error(f"--incident-guidance-file '{guidance_path}' was not found")
    except json.JSONDecodeError as exc:
        parser.error(f"--incident-guidance-file '{guidance_path}' is not valid JSON: {exc}")
    except ValueError as exc:
        parser.error(f"--incident-guidance-file '{guidance_path}' is invalid: {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Resilient VPN client prototype CLI")
    parser.add_argument("--manifest", type=Path, required=True, help="Path to signed manifest JSON")
    parser.add_argument("--public-key", type=Path, required=True, help="Path to Ed25519 public key PEM")
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path(".cache/resilient-vpn"),
        help="Directory used for last-known-good manifest cache",
    )
    parser.add_argument(
        "--support-bundle",
        type=Path,
        help="Optional path to export a minimal diagnostic support bundle",
    )
    parser.add_argument(
        "--incident-guidance-file",
        type=Path,
        help="Optional local JSON file with unsigned incident guidance overrides",
    )
    parser.add_argument(
        "--state-file",
        type=Path,
        default=Path(".cache/resilient-vpn/runtime-state.json"),
        help="Persistent local state for endpoint health and incident flags",
    )
    parser.add_argument(
        "--platform",
        choices=["simulated", "linux", "windows", "macos", "android", "ios"],
        default="linux",
        help="Which network stack implementation to use",
    )
    parser.add_argument(
        "--client-platform",
        choices=[platform.value for platform in ClientPlatform],
        default=ClientPlatform.LINUX.value,
        help="Target client runtime platform for backend capability selection",
    )
    parser.add_argument(
        "--apply-network-changes",
        action="store_true",
        help="Allow the linux stack to leave dry-run mode",
    )
    parser.add_argument(
        "--reconnect-once",
        action="store_true",
        help="Connect, disconnect, and connect again to exercise the reconnect path",
    )
    parser.add_argument(
        "--runtime-marker",
        type=Path,
        default=Path(".cache/resilient-vpn/runtime-marker.json"),
        help="Marker file used to detect stale active sessions from previous runs",
    )
    parser.add_argument(
        "--cleanup-stale-runtime",
        action="store_true",
        help="Clear any stale runtime marker before connecting",
    )
    parser.add_argument(
        "--simulate-stale-runtime-endpoint",
        type=str,
        help="Seed a stale runtime marker for the given endpoint id before startup recovery",
    )
    parser.add_argument(
        "--dataplane",
        choices=["null", "linux-userspace", "xray-core", "ios-bridge", "routed"],
        default="routed",
        help="Which data-plane backend to use",
    )
    parser.add_argument(
        "--xray-binary",
        type=str,
        default="xray",
        help="xray-core executable path when --dataplane=xray-core",
    )
    parser.add_argument(
        "--xray-config-dir",
        type=Path,
        default=Path(".cache/resilient-vpn/xray"),
        help="Directory for rendered xray-core runtime configs",
    )
    parser.add_argument(
        "--ios-contract-dir",
        type=Path,
        default=Path(".cache/resilient-vpn/ios-bridge"),
        help="Directory for rendered iOS bridge contracts",
    )
    parser.add_argument(
        "--health-checks",
        type=int,
        default=None,
        help="Override post-connect health checks before exit",
    )
    parser.add_argument(
        "--auto-reconnect-on-health-failure",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Override whether to reconnect automatically if a post-connect health check fails",
    )
    parser.add_argument(
        "--backend-state-file",
        type=Path,
        default=Path(".cache/resilient-vpn/backend-state.json"),
        help="Persistent backend process state for crash diagnostics",
    )
    parser.add_argument(
        "--allow-runtime-contract-mismatch",
        action="store_true",
        help="Allow startup to continue even when strict runtime support contract enforcement would block it",
    )
    parser.add_argument(
        "--reevaluate-pending-transports",
        type=int,
        default=None,
        help="Override the per-tick pending-transport reevaluation limit for this local run",
    )
    parser.add_argument(
        "--runtime-ticks",
        type=int,
        default=0,
        help="Run N runtime maintenance ticks before exit",
    )
    parser.add_argument(
        "--supervisor-cycles",
        type=int,
        default=0,
        help="Run N supervisor maintenance cycles before exit",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    client_platform = ClientPlatform(args.client_platform)

    verifier = Ed25519Verifier.from_public_key_pem(args.public_key.read_bytes())
    store = ManifestStore(args.cache_dir)
    loader = SignedManifestLoader(verifier=verifier, store=store)
    manifest = loader.load_with_fallback(args.manifest)
    state_manager = StateManager(StateStore(args.state_file))
    runtime_state = RuntimeState(args.runtime_marker)
    backend_state_store = BackendStateStore(args.backend_state_file)
    local_incident_guidance_overrides, local_incident_guidance_source = _load_local_incident_guidance_overrides(
        parser=parser,
        explicit_path=args.incident_guidance_file,
        cache_dir=args.cache_dir,
    )
    recovery_cleanup_enabled = args.cleanup_stale_runtime
    simulated_stale_runtime_endpoint_id: str | None = None

    if args.simulate_stale_runtime_endpoint:
        seeded_endpoint = next(
            (endpoint for endpoint in manifest.endpoints if endpoint.id == args.simulate_stale_runtime_endpoint),
            None,
        )
        if seeded_endpoint is None:
            parser.error(
                f"--simulate-stale-runtime-endpoint '{args.simulate_stale_runtime_endpoint}' is not present in the manifest"
            )
        runtime_state.mark_active(seeded_endpoint.id, seeded_endpoint.transport)
        recovery_cleanup_enabled = True
        simulated_stale_runtime_endpoint_id = seeded_endpoint.id

    telemetry = TelemetryRecorder()
    network_stack = create_platform_adapter(
        args.platform,
        dry_run=not args.apply_network_changes,
    )
    if not backend_supported_on_platform(client_platform, args.dataplane):
        parser.error(
            f"--dataplane {args.dataplane} is not supported on --client-platform {client_platform.value}"
        )
    if args.dataplane == "null":
        dataplane = NullDataPlane()
    else:
        linux_userspace = LinuxUserspaceDataPlane(
            dry_run=not args.apply_network_changes,
            state_store=backend_state_store,
        )
        xray_core = XrayCoreDataPlane(
            dry_run=not args.apply_network_changes,
            state_store=backend_state_store,
            binary_path=args.xray_binary,
            config_dir=args.xray_config_dir,
        )
        ios_bridge = IOSBridgeDataPlane(
            contract_dir=args.ios_contract_dir,
            state_store=backend_state_store,
        )
        if args.dataplane == "linux-userspace":
            dataplane = linux_userspace
        elif args.dataplane == "xray-core":
            dataplane = xray_core
        elif args.dataplane == "ios-bridge":
            dataplane = ios_bridge
        else:
            default_backend_name = default_backend_for_platform(client_platform)
            dataplane = RoutedDataPlane(
                backends={
                    "linux-userspace": linux_userspace,
                    "xray-core": xray_core,
                    "ios-bridge": ios_bridge,
                },
                default_backend_name=default_backend_name,
                client_platform=client_platform,
            )
    recovery = StartupRecovery(runtime_state, network_stack, dataplane, telemetry, state_manager=state_manager)
    recovery_report = recovery.recover(cleanup_stale_runtime=recovery_cleanup_enabled)
    runtime_support = assess_runtime_support(
        client_platform=client_platform,
        dataplane_name=args.dataplane,
        platform_adapter_name=getattr(network_stack, "platform_name", args.platform),
        platform_capability=manifest.platform_capabilities.get(client_platform.value),
    )
    orchestrator = SessionOrchestrator(
        transports=default_transport_registry(),
        probe_engine=ProbeEngine(),
        policy_engine=PolicyEngine(
            state_manager=state_manager,
            local_incident_guidance_overrides=local_incident_guidance_overrides,
        ),
        network_stack=network_stack,
        telemetry=telemetry,
        state_manager=state_manager,
        dataplane=dataplane,
        runtime_state=runtime_state,
        client_platform=client_platform,
    )
    resolved_runtime_support_policy = orchestrator.policy_engine.resolve_runtime_support_policy(manifest)
    resolved_runtime_tick_policy = orchestrator.policy_engine.resolve_runtime_tick_policy(manifest)
    runtime_support_gate_blocked = (
        resolved_runtime_support_policy.enforce_contract_match
        and runtime_support.tier == "contract-mismatch"
        and not args.allow_runtime_contract_mismatch
    )
    supervisor = RuntimeSupervisor(orchestrator, telemetry)
    if runtime_support_gate_blocked:
        telemetry.record(
            "runtime_support_gate_blocked",
            SessionState.FAILED,
            FailureClass.UNKNOWN,
            reason_code=FailureReasonCode.UNKNOWN,
            detail=runtime_support.summary,
        )
        report = SessionReport(
            state=SessionState.FAILED,
            failure_class=FailureClass.UNKNOWN,
            reason_code=FailureReasonCode.UNKNOWN,
            detail=runtime_support.summary,
        )
    else:
        report = orchestrator.connect(manifest)
        if args.reconnect_once and report.state is SessionState.CONNECTED:
            report = orchestrator.reconnect(manifest)
    effective_session_health_policy = orchestrator.policy_engine.resolve_session_health_policy(
        manifest,
        client_platform=client_platform,
        transport=report.selected_transport,
    )
    resolved_transport_reenable_policy = {
        transport_name: asdict(
            orchestrator.policy_engine.resolve_transport_reenable_policy(
                manifest,
                transport=transport_name,
            )
        )
        for transport_name in sorted({endpoint.transport for endpoint in manifest.endpoints})
    }
    resolved_transport_failure_policy = {
        transport_name: asdict(
            orchestrator.policy_engine.resolve_transport_failure_policy(
                manifest,
                transport=transport_name,
            )
        )
        for transport_name in sorted({endpoint.transport for endpoint in manifest.endpoints})
    }
    effective_health_checks = (
        args.health_checks if args.health_checks is not None else effective_session_health_policy.checks
    )
    effective_auto_reconnect = (
        args.auto_reconnect_on_health_failure
        if args.auto_reconnect_on_health_failure is not None
        else effective_session_health_policy.auto_reconnect
    )
    runtime_tick_limit = (
        max(args.reevaluate_pending_transports, 1)
        if args.reevaluate_pending_transports is not None and args.reevaluate_pending_transports > 0
        else resolved_runtime_tick_policy.reevaluate_pending_transports_limit
    )
    if not runtime_support_gate_blocked and effective_health_checks > 0 and report.state is SessionState.CONNECTED:
        monitored = orchestrator.monitor_connection(
            manifest,
            checks=effective_health_checks,
            auto_reconnect=effective_auto_reconnect,
        )
        if monitored is not None:
            report = monitored
    reenabled_transports: list[str] = []
    if not runtime_support_gate_blocked and args.reevaluate_pending_transports is not None and args.reevaluate_pending_transports > 0:
        reenabled_transports = orchestrator.reevaluate_pending_transports(
            manifest,
            limit=max(args.reevaluate_pending_transports, 1),
        )
    runtime_tick_reports: list[dict] = []
    if not runtime_support_gate_blocked and args.runtime_ticks > 0:
        for _ in range(args.runtime_ticks):
            tick_report = orchestrator.runtime_tick(
                manifest,
                policy=RuntimeTickPolicy(
                    reevaluate_pending_transports_limit=runtime_tick_limit,
                ),
            )
            runtime_tick_reports.append(
                {
                    "reenabled_transports": tick_report.reenabled_transports,
                    "pending_ready_transports": tick_report.pending_ready_transports,
                    "pending_total": tick_report.pending_total,
                }
            )
    supervisor_cycles: list[dict] = []
    if not runtime_support_gate_blocked and args.supervisor_cycles > 0:
        supervisor_report = supervisor.run_cycles(
            manifest,
            num_cycles=args.supervisor_cycles,
            tick_policy=RuntimeTickPolicy(
                reevaluate_pending_transports_limit=runtime_tick_limit,
            ),
        )
        supervisor_cycles = [
            {
                "cycle": cycle.cycle,
                "pending_total": cycle.pending_total,
                "pending_ready_transports": cycle.pending_ready_transports,
                "reenabled_transports": cycle.reenabled_transports,
            }
            for cycle in supervisor_report.cycles
        ]
    incident_summary = orchestrator.build_incident_summary(
        report=report,
        manifest=manifest,
        recovery_report=recovery_report,
        recovery_cleanup_enabled=recovery_cleanup_enabled,
        simulated_stale_runtime_endpoint_id=simulated_stale_runtime_endpoint_id,
    )
    orchestrator.emit_incident_summary(report, incident_summary)

    print(f"state={report.state}")
    print(f"detail={report.detail}")
    if report.selected_endpoint_id:
        print(f"endpoint={report.selected_endpoint_id}")
    if report.selected_transport:
        print(f"transport={report.selected_transport}")
    if report.selection_summary is not None:
        print(f"endpoint_selection_summary={report.selection_summary['summary']}")
        print(
            "endpoint_selection_order="
            + ",".join(str(item) for item in report.selection_summary["candidate_order"])
        )
    if report.applied_tunnel_mode:
        print(f"tunnel_mode={report.applied_tunnel_mode}")
    print(f"session_health_checks={effective_health_checks}")
    print(f"session_health_auto_reconnect={effective_auto_reconnect}")
    print(f"session_health_failure_threshold={effective_session_health_policy.failure_threshold}")
    print(f"runtime_tick_reevaluate_pending_transports_limit={runtime_tick_limit}")
    print(f"runtime_support_tier={runtime_support.tier}")
    print(f"runtime_support_summary={runtime_support.summary}")
    print(f"runtime_support_in_mvp_scope={runtime_support.in_mvp_scope}")
    if runtime_support_gate_blocked:
        print("runtime_support_gate_blocked=true")
    if runtime_support.caveats:
        print(f"runtime_support_caveats={' | '.join(runtime_support.caveats)}")
    print(f"kill_switch_active={report.kill_switch_active}")
    print(f"startup_recovered={recovery_report.stale_marker_found and recovery_cleanup_enabled}")
    print(f"runtime_marker_present={runtime_state.load_marker() is not None}")
    if state_manager.state.last_connected_endpoint_id is not None:
        print(f"last_connected_endpoint_id={state_manager.state.last_connected_endpoint_id}")
    print(f"session_health_fail_streak={state_manager.state.session_health_fail_streak}")
    print(f"session_health_fail_bucket={state_manager.state.session_health_fail_bucket}")
    if recovery_report.actions:
        print(f"startup_recovery_actions_count={len(recovery_report.actions)}")
    if local_incident_guidance_source is not None:
        print(f"incident_guidance_source={local_incident_guidance_source}")
    if simulated_stale_runtime_endpoint_id:
        print(f"simulated_stale_runtime_endpoint={simulated_stale_runtime_endpoint_id}")
    if reenabled_transports:
        print(f"reenabled_transports={','.join(reenabled_transports)}")
    if runtime_tick_reports:
        print(f"runtime_ticks={len(runtime_tick_reports)}")
    if supervisor_cycles:
        print(f"supervisor_cycles={len(supervisor_cycles)}")
    if getattr(dataplane, "session", None):
        print(f"dataplane_backend={dataplane.session.backend_name}")
        print(f"dataplane_dry_run={dataplane.session.dry_run}")
        print(f"dataplane_pid={dataplane.session.pid}")
        print(f"dataplane_restarts={dataplane.session.restart_count}")
        print(f"dataplane_command={' '.join(dataplane.session.command)}")
    if isinstance(network_stack, LinuxPlatformAdapter) and network_stack.last_plan:
        print(f"linux_dry_run={network_stack.last_plan.dry_run}")
        print("linux_plan:")
        for command in network_stack.last_plan.commands:
            print(f"  - {' '.join(command)}")
        if network_stack.last_plan.rollback_commands:
            print("linux_rollback_plan:")
            for command in network_stack.last_plan.rollback_commands:
                print(f"  - {' '.join(command)}")
    if isinstance(network_stack, LinuxPlatformAdapter) and network_stack.last_reconciliation:
        print(f"linux_reconciliation_dry_run={network_stack.last_reconciliation.dry_run}")
        print("linux_reconciliation_plan:")
        for command in network_stack.last_reconciliation.commands:
            print(f"  - {' '.join(command)}")
        if network_stack.last_reconciliation.failure_reason_code is not None:
            print(f"linux_reconciliation_failure_reason={network_stack.last_reconciliation.failure_reason_code}")
        if network_stack.last_reconciliation.missing_commands:
            print(f"linux_reconciliation_missing_commands={','.join(network_stack.last_reconciliation.missing_commands)}")
        if network_stack.last_reconciliation.failed_commands:
            print(f"linux_reconciliation_failed_commands={len(network_stack.last_reconciliation.failed_commands)}")
    if isinstance(network_stack, LinuxPlatformAdapter) and network_stack.last_execution:
        print(f"linux_execution_action={network_stack.last_execution.action}")
        if network_stack.last_execution.failure_reason_code is not None:
            print(f"linux_execution_failure_reason={network_stack.last_execution.failure_reason_code}")
        if network_stack.last_execution.missing_commands:
            print(f"linux_execution_missing_commands={','.join(network_stack.last_execution.missing_commands)}")
        if network_stack.last_execution.cleanup_incomplete:
            print("linux_execution_cleanup_incomplete=true")
        if network_stack.last_execution.failed_commands:
            print(f"linux_execution_failed_commands={len(network_stack.last_execution.failed_commands)}")
    if report.attempts:
        print("attempts:")
        for attempt in report.attempts:
            print(
                f"  - endpoint={attempt.endpoint_id} "
                f"transport={attempt.transport} "
                f"success={attempt.success} "
                f"failure={attempt.failure_class}"
            )
    if report.state in {SessionState.DEGRADED, SessionState.FAILED}:
        print("incident_summary:")
        print(f"  - severity={incident_summary['severity']}")
        print(f"  - headline={incident_summary['headline']}")
        print(f"  - failure_class={incident_summary['failure_class']}")
        print(f"  - recommended_action={incident_summary['recommended_action']}")
        if incident_summary["primary_transport_issue"] is not None:
            primary = incident_summary["primary_transport_issue"]
            print(
                "  - primary_transport_issue="
                f"{primary['transport']}"
                f" disabled={primary['disabled']}"
                f" pending_reenable={primary['pending_reenable']}"
                f" crash_bucket={primary['crash_bucket']}"
                f" soft_fail_bucket={primary['soft_fail_bucket']}"
            )

    if args.support_bundle:
        backend_state_record = backend_state_store.load()
        telemetry.export_support_bundle(
            args.support_bundle,
            extra={
                "manifest_version": manifest.version,
                "local_incident_guidance_overrides_present": local_incident_guidance_overrides is not None,
                "local_incident_guidance_source": (
                    str(local_incident_guidance_source)
                    if local_incident_guidance_source is not None
                    else None
                ),
                "incident_summary": incident_summary,
                "startup_recovery": {
                    "cleanup_enabled": recovery_cleanup_enabled,
                    "stale_marker_found": recovery_report.stale_marker_found,
                    "actions": recovery_report.actions,
                    "simulated_endpoint_id": simulated_stale_runtime_endpoint_id,
                },
                "startup_recovery_actions": recovery_report.actions,
                "selected_endpoint_id": report.selected_endpoint_id,
                "selected_transport": report.selected_transport,
                "endpoint_selection": report.selection_summary,
                "runtime_marker_present": runtime_state.load_marker() is not None,
                "last_connected_endpoint_id": state_manager.state.last_connected_endpoint_id,
                "session_health_checks": effective_health_checks,
                "session_health_auto_reconnect": effective_auto_reconnect,
                "session_health_failure_threshold": effective_session_health_policy.failure_threshold,
                "runtime_support": {
                    "tier": runtime_support.tier,
                    "summary": runtime_support.summary,
                    "in_mvp_scope": runtime_support.in_mvp_scope,
                    "caveats": runtime_support.caveats,
                    "client_platform": client_platform.value,
                    "dataplane": args.dataplane,
                    "platform_adapter": getattr(network_stack, "platform_name", args.platform),
                    "declared_platform_capability": (
                        {
                            "status": manifest.platform_capabilities[client_platform.value].status,
                            "supported_dataplanes": manifest.platform_capabilities[client_platform.value].supported_dataplanes,
                            "network_adapter": manifest.platform_capabilities[client_platform.value].network_adapter,
                        }
                        if client_platform.value in manifest.platform_capabilities
                        else None
                    ),
                },
                "runtime_support_policy_resolved": {
                    "enforce_contract_match": resolved_runtime_support_policy.enforce_contract_match,
                    "allow_contract_mismatch": args.allow_runtime_contract_mismatch,
                    "gate_blocked": runtime_support_gate_blocked,
                },
                "runtime_tick_policy_resolved": {
                    "reevaluate_pending_transports_limit": runtime_tick_limit,
                },
                "session_health_policy_resolved": {
                    "checks": effective_health_checks,
                    "auto_reconnect": effective_auto_reconnect,
                    "failure_threshold": effective_session_health_policy.failure_threshold,
                },
                "transport_reenable_policy_resolved": resolved_transport_reenable_policy,
                "transport_failure_policy_resolved": resolved_transport_failure_policy,
                "incident_flags": state_manager.state.incident_flags,
                "incident_flag_expires_at": state_manager.state.incident_flag_expires_at,
                "transport_recovery": {
                    transport: {
                        "crash_streak": state_manager.state.transport_crash_streaks.get(transport, 0),
                        "crash_bucket": state_manager.state.transport_crash_buckets.get(transport),
                        "crash_reason": state_manager.state.transport_crash_reasons.get(transport),
                        "soft_fail_streak": state_manager.state.transport_soft_fail_streaks.get(transport, 0),
                        "soft_fail_bucket": state_manager.state.transport_soft_fail_buckets.get(transport),
                        "disable_flag_active": bool(state_manager.state.incident_flags.get(f"disable_transport_{transport}", False)),
                        "disable_flag_expires_at": state_manager.state.incident_flag_expires_at.get(f"disable_transport_{transport}"),
                        "reenable_pending": bool(state_manager.state.transport_reenable_pending.get(transport, False)),
                        "reenable_not_before": state_manager.state.transport_reenable_not_before.get(transport),
                        "reenable_fail_streak": state_manager.state.transport_reenable_fail_streaks.get(transport, 0),
                    }
                    for transport in sorted(
                        {
                            *state_manager.state.transport_crash_streaks.keys(),
                            *state_manager.state.transport_crash_buckets.keys(),
                            *state_manager.state.transport_crash_reasons.keys(),
                            *state_manager.state.transport_soft_fail_streaks.keys(),
                            *state_manager.state.transport_soft_fail_buckets.keys(),
                            *state_manager.state.transport_reenable_pending.keys(),
                            *state_manager.state.transport_reenable_not_before.keys(),
                            *state_manager.state.transport_reenable_fail_streaks.keys(),
                        }
                    )
                },
                "transport_crash_streaks": state_manager.state.transport_crash_streaks,
                "transport_crash_buckets": state_manager.state.transport_crash_buckets,
                "transport_crash_reasons": state_manager.state.transport_crash_reasons,
                "transport_soft_fail_streaks": state_manager.state.transport_soft_fail_streaks,
                "transport_soft_fail_buckets": state_manager.state.transport_soft_fail_buckets,
                "transport_reenable_pending": state_manager.state.transport_reenable_pending,
                "transport_reenable_not_before": state_manager.state.transport_reenable_not_before,
                "transport_reenable_fail_streaks": state_manager.state.transport_reenable_fail_streaks,
                "session_health_fail_streak": state_manager.state.session_health_fail_streak,
                "session_health_fail_bucket": state_manager.state.session_health_fail_bucket,
                "reenabled_transports": reenabled_transports,
                "runtime_tick_reports": runtime_tick_reports,
                "supervisor_cycles": supervisor_cycles,
                "retry_budget": manifest.transport_policy.retry_budget,
                "dataplane_runtime": dataplane.runtime_snapshot(),
                "backend_state_record": asdict(backend_state_record) if backend_state_record is not None else None,
                "linux_reconciliation": (
                    {
                        "dry_run": network_stack.last_reconciliation.dry_run,
                        "executed": network_stack.last_reconciliation.executed,
                        "commands": network_stack.last_reconciliation.commands,
                        "missing_commands": network_stack.last_reconciliation.missing_commands,
                        "partial_failure": network_stack.last_reconciliation.partial_failure,
                        "failure_reason_code": network_stack.last_reconciliation.failure_reason_code,
                        "failure_detail": network_stack.last_reconciliation.failure_detail,
                        "applied_commands": network_stack.last_reconciliation.applied_commands,
                        "failed_commands": network_stack.last_reconciliation.failed_commands,
                    }
                    if isinstance(network_stack, LinuxPlatformAdapter) and network_stack.last_reconciliation
                    else None
                ),
                "linux_execution": (
                    {
                        "action": network_stack.last_execution.action,
                        "applied_commands": network_stack.last_execution.applied_commands,
                        "rollback_commands": network_stack.last_execution.rollback_commands,
                        "rolled_back": network_stack.last_execution.rolled_back,
                        "failure_reason_code": network_stack.last_execution.failure_reason_code,
                        "failure_detail": network_stack.last_execution.failure_detail,
                        "missing_commands": network_stack.last_execution.missing_commands,
                        "cleanup_incomplete": network_stack.last_execution.cleanup_incomplete,
                        "failed_commands": network_stack.last_execution.failed_commands,
                    }
                    if isinstance(network_stack, LinuxPlatformAdapter) and network_stack.last_execution
                    else None
                ),
                "endpoint_health": {
                    endpoint_id: {
                        "score": health.score,
                        "consecutive_failures": health.consecutive_failures,
                        "cooldown_until": health.cooldown_until,
                        "last_failure_class": health.last_failure_class,
                        "last_reason_code": health.last_reason_code,
                    }
                    for endpoint_id, health in state_manager.state.endpoint_health.items()
                },
            },
        )
        print(f"support_bundle={args.support_bundle}")

    if runtime_support_gate_blocked:
        return 2
    return 0 if report.state is SessionState.CONNECTED else 1


if __name__ == "__main__":
    raise SystemExit(main())
