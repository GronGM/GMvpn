from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from vpn_client.config import ManifestStore, SignedManifestLoader, canonical_manifest_bytes
from vpn_client.security import Ed25519Verifier, generate_keypair, sign_payload


def signed_manifest(private_pem: bytes) -> dict:
    manifest = {
        "version": 1,
        "schema_version": 1,
        "generated_at": "2026-04-23T00:00:00Z",
        "expires_at": "2026-04-30T00:00:00Z",
        "platform_capabilities": {
            "linux": {
                "platform": "linux",
                "supported_dataplanes": ["linux-userspace", "routed"],
                "network_adapter": "linux",
                "startup_reconciliation": True,
                "status": "mvp-supported",
                "notes": "Linux dry-run adapter.",
            },
            "ios": {
                "platform": "ios",
                "supported_dataplanes": ["ios-bridge", "routed"],
                "network_adapter": "ios",
                "status": "bridge-only",
                "notes": "Future Network Extension path.",
            },
        },
        "features": {"support_bundle_enabled": True},
        "transport_policy": {
            "preferred_order": ["wireguard", "https"],
            "connect_timeout_ms": 2500,
            "retry_budget": 3,
            "probe_timeout_ms": 1000,
        },
        "endpoints": [
            {
                "id": "edge-1",
                "host": "203.0.113.10",
                "port": 443,
                "transport": "https",
                "region": "eu-central",
                "tags": [],
                "metadata": {},
            }
        ],
    }
    manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
    return manifest


class SignedManifestLoaderTests(unittest.TestCase):
    def test_loader_verifies_and_caches_manifest(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)
            manifest = loader.load_dict(signed_manifest(private_pem))

            self.assertEqual(manifest.version, 1)
            self.assertTrue(store.last_known_good_path.exists())
            self.assertIn("linux", manifest.platform_capabilities)
            self.assertEqual(manifest.schema_version, 1)

    def test_loader_uses_cached_copy_when_primary_fails(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = ManifestStore(root / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            good = signed_manifest(private_pem)
            loader.load_dict(good)

            broken_path = root / "broken.json"
            broken = signed_manifest(private_pem)
            broken["signature"] = "corrupted"
            broken_path.write_text(__import__("json").dumps(broken), encoding="utf-8")

            manifest = loader.load_with_fallback(broken_path)
            self.assertEqual(manifest.endpoints[0].id, "edge-1")

    def test_loader_rejects_expired_manifest(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            expired = signed_manifest(private_pem)
            expired["expires_at"] = "2020-01-01T00:00:00Z"
            expired["signature"] = sign_payload(private_pem, canonical_manifest_bytes(expired))

            with self.assertRaises(Exception):
                loader.load_dict(expired)

    def test_loader_rejects_generated_at_not_earlier_than_expires_at(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["generated_at"] = "2026-04-30T00:00:00Z"
            manifest["expires_at"] = "2026-04-30T00:00:00Z"
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("generated_at must be earlier than expires_at", str(ctx.exception))

    def test_loader_rejects_duplicate_endpoint_ids(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"].append(
                {
                    "id": "edge-1",
                    "host": "203.0.113.11",
                    "port": 443,
                    "transport": "https",
                    "region": "eu-central",
                    "tags": [],
                    "metadata": {},
                }
            )
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("duplicate endpoint id 'edge-1'", str(ctx.exception))

    def test_loader_accepts_missing_schema_version_as_current_default(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest.pop("schema_version")
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertEqual(loaded.schema_version, 1)

    def test_loader_rejects_unsupported_manifest_schema_version(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["schema_version"] = 2
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("unsupported manifest schema_version", str(ctx.exception))

    def test_loader_accepts_provider_profile_schema_version_for_provider_profile(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["profile_kind"] = "provider-profile"
            manifest["provider_profile_schema_version"] = 1
            manifest["endpoints"][0]["metadata"] = {
                "logical_server": "edge",
                "supported_client_platforms": ["linux"],
                "provider_profile_schema_version": 1,
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertEqual(loaded.provider_profile_schema_version, 1)

    def test_loader_accepts_missing_provider_profile_schema_version_as_current_default(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["profile_kind"] = "provider-profile"
            manifest.pop("provider_profile_schema_version", None)
            manifest["endpoints"][0]["metadata"] = {
                "logical_server": "edge",
                "supported_client_platforms": ["linux"],
                "provider_profile_schema_version": 1,
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertIsNone(loaded.provider_profile_schema_version)

    def test_loader_rejects_unsupported_provider_profile_schema_version(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["profile_kind"] = "provider-profile"
            manifest["provider_profile_schema_version"] = 2
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("unsupported provider_profile_schema_version", str(ctx.exception))

    def test_loader_rejects_provider_profile_schema_version_without_provider_profile_kind(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["provider_profile_schema_version"] = 1
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("profile_kind='provider-profile'", str(ctx.exception))

    def test_loader_rejects_provider_profile_endpoint_schema_mismatch(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["profile_kind"] = "provider-profile"
            manifest["provider_profile_schema_version"] = 1
            manifest["endpoints"][0]["metadata"] = {
                "logical_server": "spb-main",
                "supported_client_platforms": ["linux"],
                "provider_profile_schema_version": 2,
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("expected '1'", str(ctx.exception))

    def test_loader_accepts_valid_incident_guidance_overrides(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["incident_guidance_overrides"] = {
                "tls_interference": {
                    "severity": "critical",
                    "recommended_action": "Use emergency fallback transport before retrying.",
                }
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertIn("incident_guidance_overrides", loaded.features)

    def test_loader_rejects_invalid_incident_guidance_override_key(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["incident_guidance_overrides"] = {
                "made_up_failure": {
                    "severity": "warning",
                    "recommended_action": "noop",
                }
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception):
                loader.load_dict(manifest)

    def test_loader_rejects_invalid_incident_guidance_override_shape(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["incident_guidance_overrides"] = {
                "tls_interference": {
                    "severity": "loud",
                    "recommended_action": "",
                }
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception):
                loader.load_dict(manifest)

    def test_loader_rejects_invalid_xray_endpoint_contract(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "dataplane": "xray-core",
                "xray_protocol": "vless",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("missing xray_user_id", str(ctx.exception))

    def test_loader_accepts_valid_xray_endpoint_contract(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "dataplane": "xray-core",
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "ws",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
                "xray_ws_path": "/edge",
                "xray_ws_host": "cdn.example.net",
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertEqual(loaded.endpoints[0].metadata["dataplane"], "xray-core")

    def test_loader_accepts_valid_ios_bridge_contract(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "dataplane": "ios-bridge",
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "ws",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
                "xray_ws_path": "/edge",
                "xray_ws_host": "cdn.example.net",
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertEqual(loaded.endpoints[0].metadata["dataplane"], "ios-bridge")

    def test_loader_rejects_invalid_ios_bridge_contract(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "dataplane": "ios-bridge",
                "xray_protocol": "trojan",
                "xray_stream_network": "grpc",
                "xray_security": "reality",
                "xray_server_name": "cdn.example.net",
                "xray_password": "secret",
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("xray_reality_public_key", str(ctx.exception))

    def test_loader_rejects_invalid_platform_capability(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["platform_capabilities"]["android"] = {
                "platform": "android",
                "supported_dataplanes": ["warp-drive"],
                "network_adapter": "android",
                "status": "planned",
                "notes": "broken test payload",
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("unsupported dataplane", str(ctx.exception))

    def test_loader_rejects_invalid_platform_capability_status(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["platform_capabilities"]["linux"]["status"] = "ga-soon"
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("unsupported status", str(ctx.exception))

    def test_loader_rejects_invalid_transport_reenable_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["transport_reenable_policy"] = {
                "default": {
                    "retry_delay_seconds": 600,
                    "max_retry_delay_seconds": 300,
                }
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("max_retry_delay_seconds", str(ctx.exception))

    def test_loader_rejects_invalid_transport_failure_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["transport_failure_policy"] = {
                "default": {
                    "crash_threshold": 1,
                    "soft_fail_threshold": 8,
                }
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("soft_fail_threshold", str(ctx.exception))

    def test_loader_rejects_invalid_endpoint_supported_client_platforms(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "supported_client_platforms": ["linux", "beos"],
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("unsupported client platform", str(ctx.exception))

    def test_loader_rejects_invalid_android_runtime_contract(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "dataplane": "xray-core",
                "supported_client_platforms": ["linux", "android"],
                "xray_protocol": "vless",
                "xray_user_id": "11111111-1111-1111-1111-111111111111",
                "xray_stream_network": "ws",
                "xray_security": "tls",
                "xray_server_name": "cdn.example.net",
                "xray_ws_path": "/edge",
                "xray_ws_host": "cdn.example.net",
                "android_policy": {
                    "meter_handling": "warp",
                    "session_name": "Main",
                },
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("android_meter_handling", str(ctx.exception))

    def test_loader_rejects_invalid_desktop_policy_contract(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["endpoints"][0]["metadata"] = {
                "supported_client_platforms": ["windows", "linux"],
                "desktop_policy": {
                    "platform_rank_priority": {
                        "windows": "high",
                    }
                },
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("non-integer desktop rank", str(ctx.exception))

    def test_loader_accepts_valid_session_health_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["session_health_policy"] = {
                "default": {"checks": 1, "auto_reconnect": False, "failure_threshold": 2},
                "by_client_platform": {"android": {"checks": 2}},
                "by_transport": {"https": {"auto_reconnect": True}},
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertIn("session_health_policy", loaded.features)

    def test_loader_rejects_invalid_session_health_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["session_health_policy"] = {
                "default": {"failure_threshold": 99},
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("session_health_policy.default.failure_threshold", str(ctx.exception))

    def test_loader_accepts_valid_runtime_support_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["runtime_support_policy"] = {
                "default": {"enforce_contract_match": True},
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertIn("runtime_support_policy", loaded.features)

    def test_loader_rejects_invalid_runtime_support_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["runtime_support_policy"] = {
                "default": {"enforce_contract_match": "strict"},
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("runtime_support_policy.default.enforce_contract_match", str(ctx.exception))

    def test_loader_accepts_valid_runtime_tick_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["runtime_tick_policy"] = {
                "default": {"reevaluate_pending_transports_limit": 2},
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            loaded = loader.load_dict(manifest)

            self.assertIn("runtime_tick_policy", loaded.features)

    def test_loader_rejects_invalid_runtime_tick_policy(self) -> None:
        private_pem, public_pem = generate_keypair()
        verifier = Ed25519Verifier.from_public_key_pem(public_pem)

        with tempfile.TemporaryDirectory() as tmp:
            store = ManifestStore(Path(tmp) / "cache")
            loader = SignedManifestLoader(verifier=verifier, store=store)

            manifest = signed_manifest(private_pem)
            manifest["features"]["runtime_tick_policy"] = {
                "default": {"reevaluate_pending_transports_limit": 0},
            }
            manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

            with self.assertRaises(Exception) as ctx:
                loader.load_dict(manifest)

            self.assertIn("runtime_tick_policy.default.reevaluate_pending_transports_limit", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
