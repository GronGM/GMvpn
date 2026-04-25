from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES_DIR = ROOT / "examples"

from vpn_client.models import Endpoint
from vpn_client.xray import XrayConfigRenderer


@dataclass(slots=True)
class SmokeConfigResult:
    endpoint_id: str
    source: str
    config_path: Path


def _deterministic_reality_public_key() -> str:
    private_key = x25519.X25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(public_key).decode("ascii").rstrip("=")


def _load_xray_endpoints_from_manifest(path: Path) -> list[Endpoint]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    endpoints: list[Endpoint] = []
    for item in payload.get("endpoints", []):
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata", {})
        if not isinstance(metadata, dict) or metadata.get("dataplane") != "xray-core":
            continue
        endpoints.append(
            Endpoint(
                id=str(item["id"]),
                host=str(item["host"]),
                port=int(item["port"]),
                transport=str(item["transport"]),
                region=str(item["region"]),
                tags=[str(tag) for tag in item.get("tags", [])],
                metadata=dict(metadata),
            )
        )
    return endpoints


def _prepare_endpoint_for_xray_validation(endpoint: Endpoint) -> Endpoint:
    metadata = dict(endpoint.metadata)
    if metadata.get("xray_security") == "reality" and metadata.get("xray_reality_public_key") == "PUBLIC_KEY_HERE":
        metadata["xray_reality_public_key"] = _deterministic_reality_public_key()
    return Endpoint(
        id=endpoint.id,
        host=endpoint.host,
        port=endpoint.port,
        transport=endpoint.transport,
        region=endpoint.region,
        tags=list(endpoint.tags),
        metadata=metadata,
    )


def build_smoke_endpoint_suite() -> list[tuple[str, Endpoint]]:
    endpoints: list[tuple[str, Endpoint]] = []
    for manifest_name in ("demo_manifest.json", "provider_profile_manifest.json"):
        manifest_path = EXAMPLES_DIR / manifest_name
        for endpoint in _load_xray_endpoints_from_manifest(manifest_path):
            endpoints.append((manifest_name, endpoint))

    inline_endpoints = (
        Endpoint(
            id="smoke-vmess-grpc",
            host="198.51.100.60",
            port=443,
            transport="https",
            region="smoke",
            metadata={
                "dataplane": "xray-core",
                "xray_protocol": "vmess",
                "xray_user_id": "66666666-6666-6666-6666-666666666666",
                "xray_stream_network": "grpc",
                "xray_security": "tls",
                "xray_server_name": "grpc-smoke.example.net",
                "xray_grpc_service_name": "edge",
                "xray_tun_user_level": 1,
            },
        ),
        Endpoint(
            id="smoke-trojan-tls",
            host="198.51.100.61",
            port=443,
            transport="https",
            region="smoke",
            metadata={
                "dataplane": "xray-core",
                "xray_protocol": "trojan",
                "xray_password": "smoke-secret",
                "xray_stream_network": "tcp",
                "xray_security": "tls",
                "xray_server_name": "trojan-smoke.example.net",
            },
        ),
    )
    endpoints.extend(("inline", endpoint) for endpoint in inline_endpoints)
    return endpoints


def render_smoke_configs(
    output_dir: Path,
    interface_name: str = "tun42",
    validation_inbound_mode: str = "tun",
) -> list[SmokeConfigResult]:
    renderer = XrayConfigRenderer(interface_name=interface_name)
    output_dir.mkdir(parents=True, exist_ok=True)
    results: list[SmokeConfigResult] = []
    for source, endpoint in build_smoke_endpoint_suite():
        prepared_endpoint = _prepare_endpoint_for_xray_validation(endpoint)
        config_path = output_dir / f"{endpoint.id}.json"
        config = renderer.render(prepared_endpoint)
        if validation_inbound_mode == "socks":
            config["inbounds"] = [
                {
                    "tag": "smoke-in",
                    "listen": "127.0.0.1",
                    "port": 0,
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ]
            config["routing"]["rules"] = [
                {"type": "field", "inboundTag": ["smoke-in"], "outboundTag": "proxy"},
            ]
        config_path.write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
        results.append(
            SmokeConfigResult(
                endpoint_id=endpoint.id,
                source=source,
                config_path=config_path,
            )
        )
    return results


def validate_with_xray(
    configs: list[SmokeConfigResult],
    *,
    xray_binary: str,
    runner=subprocess.run,
) -> list[str]:
    failures: list[str] = []
    for item in configs:
        command = [xray_binary, "run", "-test", "-config", str(item.config_path)]
        result = runner(
            command,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            failures.append(
                f"{item.endpoint_id} ({item.source}) failed xray validation"
                + (f": {' '.join(detail.split())}" if detail else "")
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Render representative xray-core configs and optionally validate them with a real Xray binary."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        help="directory for rendered smoke configs; defaults to a temporary directory",
    )
    parser.add_argument(
        "--xray-binary",
        default="xray",
        help="xray executable to use for real config validation",
    )
    parser.add_argument(
        "--validation-inbound-mode",
        choices=("tun", "socks"),
        default="tun",
        help="override the inbound used in rendered smoke configs; use socks for hosted validation where TUN devices are unavailable",
    )
    parser.add_argument(
        "--validate-with-xray",
        action="store_true",
        help="run `xray run -test -config` against every rendered config",
    )
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = args.output_dir or Path(tmp)
        rendered = render_smoke_configs(output_dir, validation_inbound_mode=args.validation_inbound_mode)
        print(f"rendered_xray_configs={len(rendered)}")
        for item in rendered:
            print(f"rendered_config={item.endpoint_id} source={item.source} path={item.config_path}")

        if not args.validate_with_xray:
            return 0

        resolved_binary = shutil.which(args.xray_binary) if "/" not in args.xray_binary else args.xray_binary
        if not resolved_binary or not Path(resolved_binary).exists():
            print(f"xray_config_smoke: missing xray binary '{args.xray_binary}'")
            return 1

        failures = validate_with_xray(rendered, xray_binary=resolved_binary)
        if failures:
            print("xray_config_smoke: FAILED")
            for failure in failures:
                print(f"- {failure}")
            return 1

        print("xray_config_smoke: OK")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
