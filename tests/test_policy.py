from __future__ import annotations

import unittest

from vpn_client.models import DnsMode, FailureClass, Manifest, NetworkPolicy, TransportPolicy, TunnelMode
from vpn_client.policy import PolicyEngine
from vpn_client.state import StateManager, StateStore

import tempfile
from pathlib import Path


class PolicyEngineTests(unittest.TestCase):
    def test_policy_engine_applies_bounded_feature_flags(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            endpoints=[],
            transport_policy=TransportPolicy(preferred_order=["https"]),
            network_policy=NetworkPolicy(
                tunnel_mode=TunnelMode.FULL,
                dns_mode=DnsMode.VPN_ONLY,
                kill_switch_enabled=True,
                ipv6_enabled=True,
            ),
            features={
                "force_split_tunnel": True,
                "allow_system_dns_fallback": True,
                "disable_ipv6": True,
            },
        )

        resolved = PolicyEngine().resolve_network_policy(manifest)

        self.assertEqual(resolved.tunnel_mode, TunnelMode.SPLIT)
        self.assertEqual(resolved.dns_mode, DnsMode.SYSTEM_FALLBACK)
        self.assertTrue(resolved.kill_switch_enabled)
        self.assertFalse(resolved.ipv6_enabled)

    def test_policy_engine_respects_local_incident_flags(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state_manager = StateManager(StateStore(Path(tmp) / "state.json"))
            state_manager.set_incident_flag("force_system_dns_fallback", True)
            state_manager.set_incident_flag("disable_kill_switch", True)

            manifest = Manifest(
                version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                endpoints=[],
                transport_policy=TransportPolicy(preferred_order=["https"]),
                network_policy=NetworkPolicy(
                    tunnel_mode=TunnelMode.FULL,
                    dns_mode=DnsMode.VPN_ONLY,
                    kill_switch_enabled=True,
                ),
                features={},
            )

            resolved = PolicyEngine(state_manager=state_manager).resolve_network_policy(manifest)

            self.assertEqual(resolved.dns_mode, DnsMode.SYSTEM_FALLBACK)
            self.assertFalse(resolved.kill_switch_enabled)

    def test_policy_engine_provides_failure_guidance(self) -> None:
        guidance = PolicyEngine().incident_guidance_for_failure(FailureClass.NETWORK_DOWN)

        self.assertEqual(guidance.severity, "critical")
        self.assertEqual(
            guidance.recommended_action,
            "Check local network reachability and dataplane backend health before attempting another connection.",
        )

    def test_policy_engine_allows_manifest_guidance_override(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            endpoints=[],
            transport_policy=TransportPolicy(preferred_order=["https"]),
            network_policy=NetworkPolicy(),
            features={
                "incident_guidance_overrides": {
                    "tls_interference": {
                        "severity": "critical",
                        "recommended_action": "Escalate to the provider edge check before retrying this transport.",
                    }
                }
            },
        )

        guidance = PolicyEngine().incident_guidance_for_failure(FailureClass.TLS_INTERFERENCE, manifest=manifest)

        self.assertEqual(guidance.severity, "critical")
        self.assertEqual(
            guidance.recommended_action,
            "Escalate to the provider edge check before retrying this transport.",
        )

    def test_local_incident_guidance_override_takes_priority_over_manifest(self) -> None:
        manifest = Manifest(
            version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            endpoints=[],
            transport_policy=TransportPolicy(preferred_order=["https"]),
            network_policy=NetworkPolicy(),
            features={
                "incident_guidance_overrides": {
                    "tls_interference": {
                        "severity": "warning",
                        "recommended_action": "Manifest guidance.",
                    }
                }
            },
        )

        guidance = PolicyEngine(
            local_incident_guidance_overrides={
                "tls_interference": {
                    "severity": "critical",
                    "recommended_action": "Local operator guidance.",
                }
            }
        ).incident_guidance_for_failure(FailureClass.TLS_INTERFERENCE, manifest=manifest)

        self.assertEqual(guidance.severity, "critical")
        self.assertEqual(guidance.recommended_action, "Local operator guidance.")


if __name__ == "__main__":
    unittest.main()
