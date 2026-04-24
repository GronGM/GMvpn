from __future__ import annotations

import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"
SRC = ROOT / "src"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vpn_client.config import canonical_manifest_bytes
from vpn_client.provider_compiler import compile_logical_server_variants
from vpn_client.security import generate_keypair, sign_payload


def main() -> None:
    EXAMPLES.mkdir(parents=True, exist_ok=True)

    private_pem, public_pem = generate_keypair()
    (EXAMPLES / "demo_private_key.pem").write_bytes(private_pem)
    (EXAMPLES / "demo_public_key.pem").write_bytes(public_pem)

    manifest = {
        "version": 1,
        "schema_version": 1,
        "generated_at": "2026-04-23T00:00:00Z",
        "expires_at": "2026-04-30T00:00:00Z",
        "platform_capabilities": {
            "linux": {
                "platform": "linux",
                "supported_dataplanes": ["linux-userspace", "xray-core", "routed"],
                "network_adapter": "linux",
                "startup_reconciliation": True,
                "status": "prototype",
                "notes": "Linux keeps the real command-planning network adapter in this repository.",
            },
            "windows": {
                "platform": "windows",
                "supported_dataplanes": ["xray-core", "routed"],
                "network_adapter": "windows",
                "status": "planned",
                "notes": "Desktop Windows path is expected to use xray-core with a native route and DNS adapter.",
            },
            "macos": {
                "platform": "macos",
                "supported_dataplanes": ["xray-core", "routed"],
                "network_adapter": "macos",
                "status": "planned",
                "notes": "macOS path needs a platform adapter that can evolve toward Network Extension integration.",
            },
            "android": {
                "platform": "android",
                "supported_dataplanes": ["xray-core", "routed"],
                "network_adapter": "android",
                "status": "planned",
                "notes": "Android path is intended to sit on top of the VpnService lifecycle.",
            },
            "ios": {
                "platform": "ios",
                "supported_dataplanes": ["ios-bridge", "routed"],
                "network_adapter": "ios",
                "status": "planned",
                "notes": "iOS path uses the ios-bridge contract and a future Network Extension runtime.",
            },
        },
        "features": {
            "remote_disable_quic": False,
            "support_bundle_enabled": True,
        },
        "network_policy": {
            "tunnel_mode": "full",
            "dns_mode": "vpn_only",
            "kill_switch_enabled": True,
            "ipv6_enabled": False,
            "allow_lan_while_connected": False,
        },
        "transport_policy": {
            "preferred_order": ["wireguard", "https", "quic"],
            "connect_timeout_ms": 2500,
            "retry_budget": 3,
            "probe_timeout_ms": 1000,
        },
        "endpoints": [
            {
                "id": "ru-mow-1",
                "host": "198.51.100.10",
                "port": 51820,
                "transport": "wireguard",
                "region": "eu-central",
                "tags": ["primary"],
                "metadata": {
                    "simulated_failure": "udp",
                },
            },
            {
                "id": "ru-spb-https-1",
                "host": "198.51.100.20",
                "port": 443,
                "transport": "https",
                "region": "eu-central",
                "tags": ["fallback"],
                "metadata": {
                    "latency_ms": 130,
                    "dataplane": "xray-core",
                    "xray_protocol": "vless",
                    "xray_user_id": "11111111-1111-1111-1111-111111111111",
                    "xray_stream_network": "ws",
                    "xray_security": "tls",
                    "xray_server_name": "cdn.example.net",
                    "xray_ws_path": "/edge",
                    "xray_ws_host": "cdn.example.net",
                },
            },
            {
                "id": "ru-spb-quic-1",
                "host": "198.51.100.30",
                "port": 443,
                "transport": "quic",
                "region": "eu-central",
                "tags": ["fast-path"],
                "metadata": {
                    "simulated_failure": "tls",
                    "dataplane": "xray-core",
                    "xray_protocol": "vless",
                    "xray_user_id": "22222222-2222-2222-2222-222222222222",
                    "xray_stream_network": "tcp",
                    "xray_security": "reality",
                    "xray_server_name": "cdn-fast.example.net",
                    "xray_fingerprint": "chrome",
                    "xray_reality_public_key": "PUBLIC_KEY_HERE",
                    "xray_reality_short_id": "0123456789abcdef",
                },
            },
        ],
    }

    manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
    (EXAMPLES / "demo_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    logical_server = {
        "logical_server": "spb-main",
        "host": "198.51.100.40",
        "port": 443,
        "region": "ru-spb",
        "transport": "https",
        "variants": [
            {
                "name": "desktop",
                "tags": ["provider-profile", "desktop", "android", "spb-main"],
                "metadata": {
                    "platform_family": "desktop-android",
                    "supported_client_platforms": ["linux", "windows", "macos", "android", "simulated"],
                    "dataplane": "xray-core",
                    "desktop_policy": {
                        "rank_priority": 20,
                        "platform_rank_priority": {
                            "linux": 10,
                            "windows": 20,
                            "macos": 30,
                            "simulated": 5,
                        },
                    },
                    "android_policy": {
                        "session_name": "SPB Main",
                        "protect_socket_api": True,
                        "meter_handling": "allow_metered",
                        "on_boot_reconnect": True,
                        "respect_doze": True,
                        "reassert_on_network_change": True,
                        "rank_priority": 40,
                    },
                    "xray_protocol": "vless",
                    "xray_user_id": "33333333-3333-3333-3333-333333333333",
                    "xray_stream_network": "ws",
                    "xray_security": "tls",
                    "xray_server_name": "edge-spb.example.net",
                    "xray_ws_path": "/desktop",
                    "xray_ws_host": "edge-spb.example.net",
                },
            },
            {
                "name": "ios",
                "tags": ["provider-profile", "ios", "spb-main"],
                "metadata": {
                    "platform_family": "ios",
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
            },
            {
                "name": "android-alt",
                "host": "198.51.100.41",
                "tags": ["provider-profile", "android", "spb-main", "alt"],
                "metadata": {
                    "platform_family": "android",
                    "supported_client_platforms": ["android"],
                    "dataplane": "xray-core",
                    "android_policy": {
                        "session_name": "SPB Main Alt",
                        "protect_socket_api": True,
                        "meter_handling": "prefer_unmetered",
                        "on_boot_reconnect": True,
                        "respect_doze": True,
                        "reassert_on_network_change": True,
                        "rank_priority": 90,
                    },
                    "xray_protocol": "vless",
                    "xray_user_id": "55555555-5555-5555-5555-555555555555",
                    "xray_stream_network": "ws",
                    "xray_security": "tls",
                    "xray_server_name": "edge-spb-alt.example.net",
                    "xray_ws_path": "/android-alt",
                    "xray_ws_host": "edge-spb-alt.example.net",
                },
            },
        ],
    }

    provider_profile_manifest = {
        "version": 1,
        "schema_version": 1,
        "provider_profile_schema_version": 1,
        "generated_at": "2026-04-23T00:00:00Z",
        "expires_at": "2026-04-30T00:00:00Z",
        "platform_capabilities": manifest["platform_capabilities"],
        "features": {
            "support_bundle_enabled": True,
            "profile_kind": "provider-profile",
        },
        "network_policy": manifest["network_policy"],
        "transport_policy": {
            "preferred_order": ["https"],
            "connect_timeout_ms": 2500,
            "retry_budget": 3,
            "probe_timeout_ms": 1000,
        },
        "endpoints": compile_logical_server_variants(logical_server),
    }
    provider_profile_manifest["signature"] = sign_payload(
        private_pem,
        canonical_manifest_bytes(provider_profile_manifest),
    )
    (EXAMPLES / "provider_profile_manifest.json").write_text(
        json.dumps(provider_profile_manifest, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
