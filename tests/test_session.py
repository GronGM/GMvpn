from __future__ import annotations

import unittest
import tempfile
from pathlib import Path

from vpn_client.client_platform import ClientPlatform
from vpn_client.dataplane import LinuxUserspaceDataPlane, RoutedDataPlane
from vpn_client.models import DnsMode, Endpoint, FailureClass, Manifest, NetworkPolicy, SessionState, TransportPolicy, TunnelMode
from vpn_client.platform import SimulatedNetworkStack
from vpn_client.policy import PolicyEngine
from vpn_client.probe import ProbeEngine
from vpn_client.runtime import RuntimeState
from vpn_client.runtime_tick import RuntimeTickPolicy
from vpn_client.scheduler import EndpointScheduler
from vpn_client.recovery import RecoveryReport
from vpn_client.session import SessionOrchestrator
from vpn_client.supervisor import RuntimeSupervisor
from vpn_client.state import StateManager, StateStore
from vpn_client.telemetry import TelemetryRecorder
from vpn_client.transport import default_transport_registry
from vpn_client.xray import XrayCoreDataPlane


class SessionOrchestratorTests(unittest.TestCase):
    def test_orchestrator_falls_back_to_next_transport(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["wireguard", "https", "quic"]),
            network_policy=NetworkPolicy(
                tunnel_mode=TunnelMode.FULL,
                dns_mode=DnsMode.VPN_ONLY,
                kill_switch_enabled=True,
            ),
            endpoints=[
                Endpoint(
                    id="wg-1",
                    host="198.51.100.10",
                    port=51820,
                    transport="wireguard",
                    region="eu-central",
                    metadata={"simulated_failure": "udp"},
                ),
                Endpoint(
                    id="https-1",
                    host="198.51.100.20",
                    port=443,
                    transport="https",
                    region="eu-central",
                    metadata={},
                ),
            ],
        )

        orchestrator = SessionOrchestrator(default_transport_registry(), ProbeEngine())
        report = orchestrator.connect(manifest)

        self.assertEqual(report.state, SessionState.CONNECTED)
        self.assertEqual(report.selected_transport, "https")
        self.assertEqual(report.selected_endpoint_id, "https-1")
        self.assertEqual(report.applied_tunnel_mode, "full")
        self.assertTrue(report.kill_switch_active)
        self.assertEqual(len(report.attempts), 2)

    def test_orchestrator_prefers_last_known_good_endpoint(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["https", "wireguard"]),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="https-2",
                    host="198.51.100.21",
                    port=443,
                    transport="https",
                    region="eu-central",
                    metadata={},
                ),
                Endpoint(
                    id="https-1",
                    host="198.51.100.20",
                    port=443,
                    transport="https",
                    region="eu-central",
                    metadata={},
                ),
            ],
        )

        orchestrator = SessionOrchestrator(default_transport_registry(), ProbeEngine())
        orchestrator.last_known_good_endpoint_id = "https-2"
        report = orchestrator.connect(manifest)

        self.assertEqual(report.state, SessionState.CONNECTED)
        self.assertEqual(report.selected_endpoint_id, "https-2")

    def test_orchestrator_records_network_policy_failure(self) -> None:
        telemetry = TelemetryRecorder()
        network_stack = SimulatedNetworkStack()
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["https"]),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="https-1",
                    host="198.51.100.20",
                    port=443,
                    transport="https",
                    region="eu-central",
                    metadata={"network_stack_failure": "dns"},
                ),
            ],
        )

        orchestrator = SessionOrchestrator(
            default_transport_registry(),
            ProbeEngine(),
            policy_engine=PolicyEngine(),
            network_stack=network_stack,
            telemetry=telemetry,
        )
        report = orchestrator.connect(manifest)

        self.assertEqual(report.state, SessionState.DEGRADED)
        self.assertTrue(report.kill_switch_active)
        self.assertEqual(telemetry.events[-1].kind, "session_degraded")

    def test_orchestrator_deprioritizes_endpoint_in_cooldown(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.mark_failure("https-1", FailureClass.TLS_INTERFERENCE, "tls blocked")

            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"]),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                    Endpoint(
                        id="https-2",
                        host="198.51.100.21",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                policy_engine=PolicyEngine(state_manager=state_manager),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                state_manager=state_manager,
            )
            report = orchestrator.connect(manifest)

            self.assertEqual(report.selected_endpoint_id, "https-2")

    def test_scheduler_respects_retry_budget(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=2),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(id="a", host="198.51.100.1", port=443, transport="https", region="eu-central"),
                Endpoint(id="b", host="198.51.100.2", port=443, transport="https", region="eu-central"),
                Endpoint(id="c", host="198.51.100.3", port=443, transport="https", region="eu-central"),
            ],
        )

        scheduled = EndpointScheduler().schedule(manifest)

        self.assertEqual([item.endpoint.id for item in scheduled], ["a", "b"])

    def test_orchestrator_reconnects_cleanly(self) -> None:
        orchestrator = SessionOrchestrator(default_transport_registry(), ProbeEngine())
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["https"]),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="https-1",
                    host="198.51.100.20",
                    port=443,
                    transport="https",
                    region="eu-central",
                ),
            ],
        )

        first = orchestrator.connect(manifest)
        second = orchestrator.reconnect(manifest)

        self.assertEqual(first.state, SessionState.CONNECTED)
        self.assertEqual(second.state, SessionState.CONNECTED)
        self.assertEqual(second.selected_endpoint_id, "https-1")

    def test_orchestrator_handles_dataplane_health_failure(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="https-1",
                    host="198.51.100.20",
                    port=443,
                    transport="https",
                    region="eu-central",
                    metadata={"dataplane_failure": "health"},
                ),
            ],
        )

        orchestrator = SessionOrchestrator(
            default_transport_registry(),
            ProbeEngine(),
            network_stack=SimulatedNetworkStack(),
            telemetry=TelemetryRecorder(),
            dataplane=LinuxUserspaceDataPlane(dry_run=True),
        )
        report = orchestrator.connect(manifest)

        self.assertEqual(report.state, SessionState.DEGRADED)
        self.assertEqual(report.failure_class, FailureClass.NETWORK_DOWN)

    def test_health_failure_does_not_mark_connection_as_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_state = RuntimeState(Path(tmp) / "marker.json")
            telemetry = TelemetryRecorder()
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=telemetry,
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                runtime_state=runtime_state,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={"dataplane_failure": "health"},
                    ),
                ],
            )

            report = orchestrator.connect(manifest)

            self.assertEqual(report.state, SessionState.DEGRADED)
            self.assertIsNone(orchestrator.last_known_good_endpoint_id)
            self.assertIsNone(runtime_state.load_marker())
            self.assertFalse(any(event.kind == "connect_succeeded" for event in telemetry.events))
            self.assertEqual(report.attempts[-1].success, False)

    def test_orchestrator_supports_mixed_dataplane_manifest(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={},
            transport_policy=TransportPolicy(preferred_order=["wireguard", "https"], retry_budget=2),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="wg-1",
                    host="198.51.100.10",
                    port=51820,
                    transport="wireguard",
                    region="eu-central",
                    metadata={"connect_failure": "endpoint_down"},
                ),
                Endpoint(
                    id="https-1",
                    host="198.51.100.20",
                    port=443,
                    transport="https",
                    region="eu-central",
                    metadata={
                        "dataplane": "xray-core",
                        "xray_protocol": "vless",
                        "xray_user_id": "11111111-1111-1111-1111-111111111111",
                        "xray_stream_network": "tcp",
                        "xray_security": "tls",
                        "xray_server_name": "cdn.example.net",
                    },
                ),
            ],
        )

        with tempfile.TemporaryDirectory() as tmp:
            dataplane = RoutedDataPlane(
                backends={
                    "linux-userspace": LinuxUserspaceDataPlane(dry_run=True),
                    "xray-core": XrayCoreDataPlane(dry_run=True, config_dir=Path(tmp) / "xray"),
                },
                default_backend_name="linux-userspace",
            )
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                dataplane=dataplane,
            )

            report = orchestrator.connect(manifest)

            self.assertEqual(report.state, SessionState.CONNECTED)
            self.assertEqual(report.selected_endpoint_id, "https-1")
            self.assertEqual(dataplane.session.backend_name, "xray-core")

    def test_orchestrator_filters_provider_profile_by_client_platform(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={"profile_kind": "provider-profile"},
            transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=2),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="spb-main-desktop",
                    host="198.51.100.40",
                    port=443,
                    transport="https",
                    region="ru-spb",
                    metadata={
                        "supported_client_platforms": ["linux", "windows", "macos", "android"],
                        "android_policy": {"rank_priority": 10},
                    },
                ),
                Endpoint(
                    id="spb-main-ios",
                    host="198.51.100.40",
                    port=443,
                    transport="https",
                    region="ru-spb",
                    metadata={
                        "supported_client_platforms": ["ios"],
                        "dataplane": "ios-bridge",
                        "xray_protocol": "vless",
                        "xray_user_id": "44444444-4444-4444-4444-444444444444",
                        "xray_stream_network": "ws",
                        "xray_security": "tls",
                        "xray_server_name": "edge-spb.example.net",
                        "xray_ws_path": "/ios",
                        "xray_ws_host": "edge-spb.example.net",
                        "ios_provider_kind": "packet-tunnel",
                    },
                ),
            ],
        )

        orchestrator = SessionOrchestrator(
            default_transport_registry(),
            ProbeEngine(),
            network_stack=SimulatedNetworkStack(),
            telemetry=TelemetryRecorder(),
            dataplane=LinuxUserspaceDataPlane(dry_run=True),
            client_platform=ClientPlatform.LINUX,
        )
        report = orchestrator.connect(manifest)

        self.assertEqual(report.state, SessionState.CONNECTED)
        self.assertEqual(report.selected_endpoint_id, "spb-main-desktop")

    def test_orchestrator_prefers_lower_android_rank_priority(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={"profile_kind": "provider-profile"},
            transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=2),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="android-primary",
                    host="198.51.100.40",
                    port=443,
                    transport="https",
                    region="ru-spb",
                    metadata={
                        "supported_client_platforms": ["android"],
                        "android_policy": {"rank_priority": 10},
                    },
                ),
                Endpoint(
                    id="android-secondary",
                    host="198.51.100.41",
                    port=443,
                    transport="https",
                    region="ru-spb",
                    metadata={
                        "supported_client_platforms": ["android"],
                        "android_policy": {"rank_priority": 80},
                    },
                ),
            ],
        )

        orchestrator = SessionOrchestrator(
            default_transport_registry(),
            ProbeEngine(),
            network_stack=SimulatedNetworkStack(),
            telemetry=TelemetryRecorder(),
            dataplane=LinuxUserspaceDataPlane(dry_run=True),
            client_platform=ClientPlatform.ANDROID,
        )
        report = orchestrator.connect(manifest)

        self.assertEqual(report.selected_endpoint_id, "android-primary")

    def test_orchestrator_prefers_lower_desktop_rank_priority_for_windows(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            features={"profile_kind": "provider-profile"},
            transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=2),
            network_policy=NetworkPolicy(),
            endpoints=[
                Endpoint(
                    id="desktop-primary",
                    host="198.51.100.40",
                    port=443,
                    transport="https",
                    region="ru-spb",
                    metadata={
                        "supported_client_platforms": ["windows", "linux", "macos"],
                        "desktop_policy": {"platform_rank_priority": {"windows": 10, "linux": 50}},
                    },
                ),
                Endpoint(
                    id="desktop-secondary",
                    host="198.51.100.41",
                    port=443,
                    transport="https",
                    region="ru-spb",
                    metadata={
                        "supported_client_platforms": ["windows", "linux", "macos"],
                        "desktop_policy": {"platform_rank_priority": {"windows": 80, "linux": 20}},
                    },
                ),
            ],
        )

        orchestrator = SessionOrchestrator(
            default_transport_registry(),
            ProbeEngine(),
            network_stack=SimulatedNetworkStack(),
            telemetry=TelemetryRecorder(),
            dataplane=LinuxUserspaceDataPlane(dry_run=True),
            client_platform=ClientPlatform.WINDOWS,
        )
        report = orchestrator.connect(manifest)

        self.assertEqual(report.selected_endpoint_id, "desktop-primary")

    def test_orchestrator_builds_and_emits_incident_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            telemetry = TelemetryRecorder()
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                policy_engine=PolicyEngine(state_manager=state_manager),
                network_stack=SimulatedNetworkStack(),
                telemetry=telemetry,
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["quic"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="quic-1",
                        host="198.51.100.30",
                        port=443,
                        transport="quic",
                        region="eu-central",
                        metadata={"simulated_failure": "tls"},
                    ),
                ],
            )

            report = orchestrator.connect(manifest)
            summary = orchestrator.build_incident_summary(
                manifest=manifest,
                report=report,
                recovery_report=RecoveryReport(stale_marker_found=False, actions=[]),
                recovery_cleanup_enabled=False,
            )
            orchestrator.emit_incident_summary(report, summary)

            self.assertEqual(summary["failure_class"], "tls_interference")
            self.assertEqual(summary["severity"], "warning")
            self.assertEqual(telemetry.events[-1].kind, "incident_summary")

    def test_monitor_connection_degrades_session_without_auto_reconnect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_state = RuntimeState(Path(tmp) / "marker.json")
            telemetry = TelemetryRecorder()
            dataplane = LinuxUserspaceDataPlane(dry_run=True)
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=telemetry,
                dataplane=dataplane,
                runtime_state=runtime_state,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            connected = orchestrator.connect(manifest)
            self.assertEqual(connected.state, SessionState.CONNECTED)
            self.assertIsNotNone(runtime_state.load_marker())
            manifest.endpoints[0].metadata["dataplane_failure"] = "health"

            monitored = orchestrator.monitor_connection(manifest, checks=1, auto_reconnect=False)

            self.assertEqual(monitored.state, SessionState.DEGRADED)
            self.assertEqual(monitored.failure_class, FailureClass.NETWORK_DOWN)
            self.assertIsNone(runtime_state.load_marker())
            self.assertIsNone(dataplane.session)
            self.assertTrue(any(event.kind == "session_degraded" for event in telemetry.events))

    def test_monitor_connection_auto_reconnects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime_state = RuntimeState(Path(tmp) / "marker.json")
            telemetry = TelemetryRecorder()
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=telemetry,
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                runtime_state=runtime_state,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            connected = orchestrator.connect(manifest)
            self.assertEqual(connected.state, SessionState.CONNECTED)
            manifest.endpoints[0].metadata["dataplane_failure"] = "health"
            manifest.endpoints[0].metadata["dataplane_failure"] = "health"
            degraded = orchestrator.monitor_connection(manifest, checks=1, auto_reconnect=True)
            self.assertEqual(degraded.state, SessionState.DEGRADED)

            manifest.endpoints[0].metadata.pop("dataplane_failure")
            recovered = orchestrator.reconnect(manifest)

            self.assertEqual(recovered.state, SessionState.CONNECTED)
            self.assertTrue(any(event.kind == "session_reconnect_requested" for event in telemetry.events))

    def test_repeated_backend_crashes_disable_transport_locally(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https", "wireguard"], retry_budget=2),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={"dataplane_failure": "crash"},
                    ),
                    Endpoint(
                        id="wg-1",
                        host="198.51.100.21",
                        port=51820,
                        transport="wireguard",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            first = orchestrator.connect(manifest)
            self.assertEqual(first.selected_endpoint_id, "wg-1")
            self.assertEqual(state_manager.transport_crash_streak("https"), 1)
            self.assertTrue(state_manager.incident_flag("disable_transport_https"))

    def test_soft_failures_disable_transport_after_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={"dataplane_failure": "health"},
                    ),
                ],
            )

            first = orchestrator.connect(manifest)
            second = orchestrator.reconnect(manifest)
            third = orchestrator.reconnect(manifest)

            self.assertEqual(first.state, SessionState.DEGRADED)
            self.assertEqual(second.state, SessionState.DEGRADED)
            self.assertEqual(third.state, SessionState.DEGRADED)
            self.assertEqual(state_manager.transport_soft_fail_streak("https"), 3)
            self.assertTrue(state_manager.incident_flag("disable_transport_https"))

    def test_transport_reenters_as_pending_after_ttl_expiry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)
            state_manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"

            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            scheduled = EndpointScheduler(state_manager).schedule(manifest)

            self.assertFalse(state_manager.incident_flag("disable_transport_https"))
            self.assertTrue(scheduled[0].pending_reenable)

    def test_failed_reenable_reapplies_short_disable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)
            state_manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={"simulated_failure": "tls"},
                    ),
                ],
            )

            report = orchestrator.connect(manifest)

            self.assertEqual(report.state, SessionState.DEGRADED)
            self.assertTrue(state_manager.incident_flag("disable_transport_https"))
            self.assertFalse(state_manager.transport_reenable_pending("https"))

    def test_background_reevaluation_reenables_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)
            state_manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"
            self.assertFalse(state_manager.incident_flag("disable_transport_https"))
            state_manager.state.transport_reenable_not_before["https"] = "2020-01-01T00:00:00+00:00"
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            reenabled = orchestrator.reevaluate_pending_transports(manifest, limit=1)

            self.assertEqual(reenabled, ["https"])
            self.assertFalse(state_manager.transport_reenable_pending("https"))

    def test_background_reevaluation_reapplies_ban_on_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)
            state_manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"
            self.assertFalse(state_manager.incident_flag("disable_transport_https"))
            state_manager.state.transport_reenable_not_before["https"] = "2020-01-01T00:00:00+00:00"
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=TelemetryRecorder(),
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={"simulated_failure": "tls"},
                    ),
                ],
            )

            reenabled = orchestrator.reevaluate_pending_transports(manifest, limit=1)

            self.assertEqual(reenabled, [])
            self.assertTrue(state_manager.incident_flag("disable_transport_https"))
            self.assertFalse(state_manager.transport_reenable_pending("https"))

    def test_runtime_tick_reports_pending_and_reenabled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)
            state_manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"
            self.assertFalse(state_manager.incident_flag("disable_transport_https"))
            state_manager.state.transport_reenable_not_before["https"] = "2020-01-01T00:00:00+00:00"

            telemetry = TelemetryRecorder()
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=telemetry,
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            report = orchestrator.runtime_tick(
                manifest,
                policy=RuntimeTickPolicy(reevaluate_pending_transports_limit=1),
            )

            self.assertEqual(report.pending_ready_transports, ["https"])
            self.assertEqual(report.reenabled_transports, ["https"])
            self.assertTrue(any(event.kind == "runtime_tick" for event in telemetry.events))

    def test_supervisor_cycles_wrap_runtime_ticks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag_with_ttl("disable_transport_https", True, ttl_seconds=1)
            state_manager.state.incident_flag_expires_at["disable_transport_https"] = "2020-01-01T00:00:00+00:00"
            self.assertFalse(state_manager.incident_flag("disable_transport_https"))
            state_manager.state.transport_reenable_not_before["https"] = "2020-01-01T00:00:00+00:00"
            telemetry = TelemetryRecorder()
            orchestrator = SessionOrchestrator(
                default_transport_registry(),
                ProbeEngine(),
                network_stack=SimulatedNetworkStack(),
                telemetry=telemetry,
                dataplane=LinuxUserspaceDataPlane(dry_run=True),
                state_manager=state_manager,
            )
            supervisor = RuntimeSupervisor(orchestrator, telemetry)
            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                features={},
                transport_policy=TransportPolicy(preferred_order=["https"], retry_budget=1),
                network_policy=NetworkPolicy(),
                endpoints=[
                    Endpoint(
                        id="https-1",
                        host="198.51.100.20",
                        port=443,
                        transport="https",
                        region="eu-central",
                        metadata={},
                    ),
                ],
            )

            report = supervisor.run_cycles(
                manifest,
                num_cycles=1,
                tick_policy=RuntimeTickPolicy(reevaluate_pending_transports_limit=1),
            )

            self.assertEqual(len(report.cycles), 1)
            self.assertEqual(report.cycles[0].reenabled_transports, ["https"])
            self.assertTrue(any(event.kind == "supervisor_cycle_started" for event in telemetry.events))


if __name__ == "__main__":
    unittest.main()
