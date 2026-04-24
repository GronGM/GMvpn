from __future__ import annotations

import unittest

from vpn_client.provider_compiler import (
    ProviderCompileError,
    build_provider_profile_manifest,
    compile_logical_server_variants,
    validate_compiled_variants,
)


class ProviderCompilerTests(unittest.TestCase):
    def test_compile_logical_server_variants(self) -> None:
        server = {
            "logical_server": "spb-main",
            "host": "198.51.100.40",
            "port": 443,
            "region": "ru-spb",
            "transport": "https",
            "variants": [
                {
                    "name": "desktop",
                    "tags": ["desktop"],
                    "metadata": {"dataplane": "xray-core"},
                },
                {
                    "name": "ios",
                    "tags": ["ios"],
                    "metadata": {"dataplane": "ios-bridge"},
                },
            ],
        }

        compiled = compile_logical_server_variants(server)

        self.assertEqual(compiled[0]["id"], "spb-main-desktop")
        self.assertEqual(compiled[1]["id"], "spb-main-ios")
        self.assertEqual(compiled[0]["metadata"]["logical_server"], "spb-main")
        self.assertEqual(compiled[0]["metadata"]["provider_profile_schema_version"], 1)

    def test_build_provider_profile_manifest_sets_profile_contract(self) -> None:
        manifest = build_provider_profile_manifest(
            version=1,
            schema_version=1,
            provider_profile_schema_version=1,
            generated_at="2026-04-23T00:00:00Z",
            expires_at="2026-04-30T00:00:00Z",
            platform_capabilities={},
            features={"support_bundle_enabled": True},
            network_policy={},
            transport_policy={"preferred_order": ["https"]},
            logical_servers=[
                {
                    "logical_server": "spb-main",
                    "host": "198.51.100.40",
                    "port": 443,
                    "region": "ru-spb",
                    "variants": [
                        {
                            "name": "desktop",
                            "metadata": {"supported_client_platforms": ["linux"]},
                        }
                    ],
                }
            ],
        )

        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["provider_profile_schema_version"], 1)
        self.assertEqual(manifest["features"]["profile_kind"], "provider-profile")
        self.assertEqual(
            manifest["endpoints"][0]["metadata"]["provider_profile_schema_version"],
            1,
        )

    def test_build_provider_profile_manifest_rejects_mismatched_server_schema_version(self) -> None:
        with self.assertRaises(ProviderCompileError):
            build_provider_profile_manifest(
                version=1,
                schema_version=1,
                provider_profile_schema_version=1,
                generated_at="2026-04-23T00:00:00Z",
                expires_at="2026-04-30T00:00:00Z",
                platform_capabilities={},
                features={},
                network_policy={},
                transport_policy={"preferred_order": ["https"]},
                logical_servers=[
                    {
                        "logical_server": "spb-main",
                        "host": "198.51.100.40",
                        "port": 443,
                        "region": "ru-spb",
                        "provider_profile_schema_version": 2,
                        "variants": [{"name": "desktop", "metadata": {"supported_client_platforms": ["linux"]}}],
                    }
                ],
            )

    def test_validate_compiled_variants_rejects_duplicate_ids(self) -> None:
        endpoints = [
            {
                "id": "dup",
                "host": "198.51.100.40",
                "port": 443,
                "transport": "https",
                "region": "ru-spb",
                "tags": [],
                "metadata": {
                    "logical_server": "spb-main",
                    "supported_client_platforms": ["linux"],
                    "provider_profile_schema_version": 1,
                },
            },
            {
                "id": "dup",
                "host": "198.51.100.41",
                "port": 443,
                "transport": "https",
                "region": "ru-spb",
                "tags": [],
                "metadata": {
                    "logical_server": "spb-main",
                    "supported_client_platforms": ["windows"],
                    "provider_profile_schema_version": 1,
                },
            },
        ]

        with self.assertRaises(ProviderCompileError):
            validate_compiled_variants(endpoints)

    def test_validate_compiled_variants_requires_logical_server(self) -> None:
        endpoints = [
            {
                "id": "spb-main-desktop",
                "host": "198.51.100.40",
                "port": 443,
                "transport": "https",
                "region": "ru-spb",
                "tags": [],
                "metadata": {"supported_client_platforms": ["linux"], "provider_profile_schema_version": 1},
            }
        ]

        with self.assertRaises(ProviderCompileError):
            validate_compiled_variants(endpoints)
