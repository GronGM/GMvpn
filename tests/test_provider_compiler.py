from __future__ import annotations

import unittest

from vpn_client.provider_compiler import ProviderCompileError, compile_logical_server_variants, validate_compiled_variants


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

    def test_validate_compiled_variants_rejects_duplicate_ids(self) -> None:
        endpoints = [
            {
                "id": "dup",
                "host": "198.51.100.40",
                "port": 443,
                "transport": "https",
                "region": "ru-spb",
                "tags": [],
                "metadata": {"logical_server": "spb-main", "supported_client_platforms": ["linux"]},
            },
            {
                "id": "dup",
                "host": "198.51.100.41",
                "port": 443,
                "transport": "https",
                "region": "ru-spb",
                "tags": [],
                "metadata": {"logical_server": "spb-main", "supported_client_platforms": ["windows"]},
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
                "metadata": {"supported_client_platforms": ["linux"]},
            }
        ]

        with self.assertRaises(ProviderCompileError):
            validate_compiled_variants(endpoints)
