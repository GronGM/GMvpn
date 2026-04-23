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
from vpn_client.security import generate_keypair, sign_payload


def main() -> None:
    EXAMPLES.mkdir(parents=True, exist_ok=True)

    private_pem, public_pem = generate_keypair()
    (EXAMPLES / "demo_private_key.pem").write_bytes(private_pem)
    (EXAMPLES / "demo_public_key.pem").write_bytes(public_pem)

    manifest = {
        "version": 1,
        "generated_at": "2026-04-23T00:00:00Z",
        "expires_at": "2026-04-30T00:00:00Z",
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
                },
            },
        ],
    }

    manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))
    (EXAMPLES / "demo_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
