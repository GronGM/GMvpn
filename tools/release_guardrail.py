from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from vpn_client.linux import LinuxNetworkStack
from vpn_client.models import DnsMode, Endpoint, NetworkPolicy, PlatformCapability, TunnelMode
from vpn_client.runtime_support import assess_runtime_support
from vpn_client.client_platform import ClientPlatform
from vpn_client.config import canonical_manifest_bytes
from vpn_client.xray import XrayCoreDataPlane
from vpn_client.security import generate_keypair, sign_payload


CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_CHECKLIST = ROOT / "docs" / "release-checklist.md"
README = ROOT / "README.md"
DEMO_MANIFEST = ROOT / "examples" / "demo_manifest.json"

REQUIRED_CI_SNIPPETS = (
    "python -m compileall src tests",
    "PYTHONPATH=src python -m unittest discover -s tests -v",
)

REQUIRED_RELEASE_CHECKLIST_SNIPPETS = (
    "Confirm GitHub Actions `CI` is green for the release candidate.",
    "Run `python -m compileall src tests`.",
    "Run `PYTHONPATH=src python -m unittest discover -s tests -v`.",
    "Confirm the support bundle still exports at least:",
    "Do Not Release If",
)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _git(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=check,
    )


def _check_required_snippets(path: Path, snippets: tuple[str, ...]) -> list[str]:
    text = _read_text(path)
    missing = [snippet for snippet in snippets if snippet not in text]
    return [f"{path.relative_to(ROOT)} is missing: {snippet}" for snippet in missing]


def _check_git_clean() -> list[str]:
    status = _git("status", "--porcelain", check=False)
    lines = [line for line in status.stdout.splitlines() if line.strip()]
    if not lines:
        return []
    return ["working tree is not clean"] + [f"dirty: {line}" for line in lines]


def _check_cache_not_tracked() -> list[str]:
    tracked = _git("ls-files", ".cache", check=False).stdout.strip().splitlines()
    tracked = [line for line in tracked if line.strip()]
    if not tracked:
        return []
    return [f".cache artefact tracked in git: {path}" for path in tracked]


def _run_local_checks() -> list[str]:
    commands = (
        ["python", "-m", "compileall", "src", "tests"],
        ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
    )
    failures: list[str] = []
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    for command in commands:
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            failures.append(
                f"command failed: {' '.join(command)}\n"
                f"stdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}"
            )
    return failures


def _run_cli_and_collect(*args: str, state_payload: dict | None = None) -> tuple[int, str, dict[str, object]]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        private_pem, public_pem = generate_keypair()
        manifest = json.loads(_read_text(DEMO_MANIFEST))
        manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

        manifest_path = tmp_path / "manifest.json"
        public_key_path = tmp_path / "public.pem"
        support_bundle_path = tmp_path / "bundle.json"
        state_path = tmp_path / "state.json"
        backend_state_path = tmp_path / "backend-state.json"
        runtime_marker_path = tmp_path / "runtime-marker.json"

        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        public_key_path.write_bytes(public_pem)
        if state_payload is not None:
            state_path.write_text(json.dumps(state_payload), encoding="utf-8")

        command = [
            sys.executable,
            "-m",
            "vpn_client.cli",
            "--manifest",
            str(manifest_path),
            "--public-key",
            str(public_key_path),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--state-file",
            str(state_path),
            "--runtime-marker",
            str(runtime_marker_path),
            "--backend-state-file",
            str(backend_state_path),
            "--support-bundle",
            str(support_bundle_path),
            *args,
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            check=False,
        )
        bundle = json.loads(support_bundle_path.read_text(encoding="utf-8"))
        return result.returncode, result.stdout, bundle


def _parse_cli_output(stdout: str) -> dict[str, object]:
    parsed: dict[str, object] = {}
    incident_summary: dict[str, object] = {}
    in_incident_summary = False
    for raw_line in stdout.splitlines():
        line = raw_line.rstrip()
        if line == "incident_summary:":
            in_incident_summary = True
            continue
        if in_incident_summary:
            if not line.startswith("  - "):
                in_incident_summary = False
            else:
                key, _, value = line[4:].partition("=")
                if key == "primary_transport_issue":
                    incident_summary[key] = _parse_primary_transport_issue(value)
                else:
                    incident_summary[key] = value
                continue
        if "=" in line and not line.startswith("  - "):
            key, value = line.split("=", 1)
            parsed[key] = value
    if incident_summary:
        parsed["incident_summary"] = incident_summary
    return parsed


def _parse_primary_transport_issue(value: str) -> dict[str, object]:
    tokens = value.split()
    issue = {"transport": tokens[0] if tokens else ""}
    for token in tokens[1:]:
        key, _, item_value = token.partition("=")
        issue[key] = item_value
    return issue


def _parse_incident_telemetry_detail(detail: str) -> dict[str, str] | None:
    severity, separator, remainder = detail.partition(": ")
    if not separator:
        return None
    headline, separator, recommended_action = remainder.partition("; ")
    if not separator:
        return None
    return {
        "severity": severity,
        "headline": headline,
        "recommended_action": recommended_action,
    }


def _check_release_artifact_policy() -> list[str]:
    failures: list[str] = []

    connected_state = {
        "endpoint_health": {},
        "last_connected_endpoint_id": None,
        "incident_flags": {"disable_transport_https": False},
        "incident_flag_expires_at": {"disable_transport_https": "2020-01-01T00:00:00+00:00"},
        "transport_crash_streaks": {},
        "transport_crash_buckets": {},
        "transport_crash_reasons": {},
        "transport_soft_fail_streaks": {},
        "transport_soft_fail_buckets": {},
        "transport_reenable_pending": {"https": True},
        "transport_reenable_not_before": {"https": "2020-01-01T00:00:00+00:00"},
        "transport_reenable_fail_streaks": {},
        "session_health_fail_streak": 0,
        "session_health_fail_bucket": "",
    }
    returncode, stdout, bundle = _run_cli_and_collect(
        "--platform",
        "simulated",
        "--dataplane",
        "null",
        "--runtime-ticks",
        "1",
        state_payload=connected_state,
    )
    if returncode != 0:
        return [f"artifact policy parity: connected CLI scenario failed with exit code {returncode}"]
    parsed = _parse_cli_output(stdout)
    extra = bundle["extra"]

    connected_pairs = (
        ("session_health_checks", str(extra["session_health_checks"])),
        ("session_health_auto_reconnect", str(extra["session_health_auto_reconnect"])),
        ("session_health_failure_threshold", str(extra["session_health_failure_threshold"])),
        (
            "runtime_tick_reevaluate_pending_transports_limit",
            str(extra["runtime_tick_policy_resolved"]["reevaluate_pending_transports_limit"]),
        ),
        ("runtime_support_tier", str(extra["runtime_support"]["tier"])),
        ("runtime_support_in_mvp_scope", str(extra["runtime_support"]["in_mvp_scope"])),
    )
    for key, expected in connected_pairs:
        actual = parsed.get(key)
        if actual != expected:
            failures.append(
                f"artifact policy parity: CLI field '{key}' was '{actual}', expected '{expected}' from support bundle"
            )

    if bool(extra["runtime_support_policy_resolved"]["gate_blocked"]):
        failures.append("artifact policy parity: connected CLI scenario unexpectedly reported runtime_support gate blocked")

    degraded_manifest = {
        "version": 1,
        "generated_at": "2026-04-23T00:00:00Z",
        "expires_at": "2026-04-30T00:00:00Z",
        "schema_version": 1,
        "features": {
            "support_bundle_enabled": True,
            "runtime_support_policy": {
                "default": {"enforce_contract_match": False},
            },
            "runtime_tick_policy": {
                "default": {"reevaluate_pending_transports_limit": 2},
            },
            "session_health_policy": {
                "default": {"checks": 0, "auto_reconnect": False, "failure_threshold": 2},
            },
        },
        "transport_policy": {
            "preferred_order": ["quic"],
            "connect_timeout_ms": 2500,
            "retry_budget": 1,
            "probe_timeout_ms": 1000,
        },
        "network_policy": {
            "tunnel_mode": "full",
            "dns_mode": "vpn_only",
            "kill_switch_enabled": True,
            "ipv6_enabled": False,
            "allow_lan_while_connected": False,
        },
        "endpoints": [
            {
                "id": "quic-1",
                "host": "198.51.100.30",
                "port": 443,
                "transport": "quic",
                "region": "eu-central",
                "tags": [],
                "metadata": {"simulated_failure": "tls"},
            }
        ],
    }
    degraded_state = {
        "endpoint_health": {},
        "last_connected_endpoint_id": None,
        "incident_flags": {},
        "incident_flag_expires_at": {},
        "transport_crash_streaks": {},
        "transport_crash_buckets": {},
        "transport_crash_reasons": {},
        "transport_soft_fail_streaks": {"quic": 1},
        "transport_soft_fail_buckets": {"quic": "tls_interference:tls_handshake_failed"},
        "transport_reenable_pending": {},
        "transport_reenable_not_before": {},
        "transport_reenable_fail_streaks": {},
        "session_health_fail_streak": 0,
        "session_health_fail_bucket": "",
    }
    returncode, stdout, bundle = _run_custom_cli_and_collect(
        degraded_manifest,
        state_payload=degraded_state,
        args=("--platform", "simulated", "--dataplane", "null"),
    )
    if returncode != 1:
        failures.append(f"artifact policy parity: degraded CLI scenario returned {returncode}, expected 1")
        return failures
    parsed = _parse_cli_output(stdout)
    extra = bundle["extra"]
    incident_summary = parsed.get("incident_summary")
    if not isinstance(incident_summary, dict):
        failures.append("artifact policy parity: degraded CLI scenario did not print incident_summary block")
        return failures

    incident_pairs = (
        ("severity", str(extra["incident_summary"]["severity"])),
        ("failure_class", str(extra["incident_summary"]["failure_class"])),
    )
    for key, expected in incident_pairs:
        actual = incident_summary.get(key)
        if actual != expected:
            failures.append(
                f"artifact policy parity: CLI incident field '{key}' was '{actual}', expected '{expected}' from support bundle"
            )

    primary_issue = incident_summary.get("primary_transport_issue")
    bundle_primary_issue = extra["incident_summary"]["primary_transport_issue"]
    if not isinstance(primary_issue, dict) or not isinstance(bundle_primary_issue, dict):
        failures.append("artifact policy parity: degraded CLI scenario did not preserve primary_transport_issue")
    else:
        for key in ("transport", "soft_fail_bucket"):
            actual = str(primary_issue.get(key))
            expected = str(bundle_primary_issue.get(key))
            if actual != expected:
                failures.append(
                    "artifact policy parity: CLI incident primary_transport_issue "
                    f"'{key}' was '{actual}', expected '{expected}' from support bundle"
                )

    return failures


def _check_incident_narrative_consistency() -> list[str]:
    failures: list[str] = []
    degraded_manifest = {
        "version": 1,
        "generated_at": "2026-04-23T00:00:00Z",
        "expires_at": "2026-04-30T00:00:00Z",
        "schema_version": 1,
        "features": {
            "support_bundle_enabled": True,
            "runtime_support_policy": {
                "default": {"enforce_contract_match": False},
            },
            "session_health_policy": {
                "default": {"checks": 0, "auto_reconnect": False, "failure_threshold": 2},
            },
        },
        "transport_policy": {
            "preferred_order": ["quic"],
            "connect_timeout_ms": 2500,
            "retry_budget": 1,
            "probe_timeout_ms": 1000,
        },
        "network_policy": {
            "tunnel_mode": "full",
            "dns_mode": "vpn_only",
            "kill_switch_enabled": True,
            "ipv6_enabled": False,
            "allow_lan_while_connected": False,
        },
        "endpoints": [
            {
                "id": "quic-1",
                "host": "198.51.100.30",
                "port": 443,
                "transport": "quic",
                "region": "eu-central",
                "tags": [],
                "metadata": {"simulated_failure": "tls"},
            }
        ],
    }
    degraded_state = {
        "endpoint_health": {},
        "last_connected_endpoint_id": None,
        "incident_flags": {},
        "incident_flag_expires_at": {},
        "transport_crash_streaks": {},
        "transport_crash_buckets": {},
        "transport_crash_reasons": {},
        "transport_soft_fail_streaks": {"quic": 1},
        "transport_soft_fail_buckets": {"quic": "tls_interference:tls_handshake_failed"},
        "transport_reenable_pending": {},
        "transport_reenable_not_before": {},
        "transport_reenable_fail_streaks": {},
        "session_health_fail_streak": 0,
        "session_health_fail_bucket": "",
    }
    returncode, stdout, bundle = _run_custom_cli_and_collect(
        degraded_manifest,
        state_payload=degraded_state,
        args=("--platform", "simulated", "--dataplane", "null"),
    )
    if returncode != 1:
        return [f"incident narrative consistency: degraded CLI scenario returned {returncode}, expected 1"]

    parsed = _parse_cli_output(stdout)
    cli_incident = parsed.get("incident_summary")
    if not isinstance(cli_incident, dict):
        return ["incident narrative consistency: degraded CLI scenario did not print incident_summary block"]

    bundle_incident = bundle["extra"]["incident_summary"]
    telemetry_event = next(
        (event for event in reversed(bundle["events"]) if event.get("kind") == "incident_summary"),
        None,
    )
    if telemetry_event is None:
        return ["incident narrative consistency: support bundle is missing incident_summary telemetry event"]

    telemetry_narrative = _parse_incident_telemetry_detail(str(telemetry_event.get("detail", "")))
    if telemetry_narrative is None:
        return ["incident narrative consistency: telemetry incident_summary detail is not parseable"]

    narrative_pairs = (
        ("severity", str(bundle_incident["severity"]), str(cli_incident.get("severity")), telemetry_narrative["severity"]),
        ("headline", str(bundle_incident["headline"]), str(cli_incident.get("headline")), telemetry_narrative["headline"]),
        (
            "recommended_action",
            str(bundle_incident["recommended_action"]),
            str(cli_incident.get("recommended_action")),
            telemetry_narrative["recommended_action"],
        ),
    )
    for field, bundle_value, cli_value, telemetry_value in narrative_pairs:
        if cli_value != bundle_value:
            failures.append(
                f"incident narrative consistency: CLI field '{field}' was '{cli_value}', expected '{bundle_value}'"
            )
        if telemetry_value != bundle_value:
            failures.append(
                f"incident narrative consistency: telemetry field '{field}' was '{telemetry_value}', expected '{bundle_value}'"
            )

    return failures


def _run_custom_cli_and_collect(
    manifest: dict[str, object],
    *,
    args: tuple[str, ...],
    state_payload: dict | None = None,
) -> tuple[int, str, dict[str, object]]:
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        private_pem, public_pem = generate_keypair()
        manifest["signature"] = sign_payload(private_pem, canonical_manifest_bytes(manifest))

        manifest_path = tmp_path / "manifest.json"
        public_key_path = tmp_path / "public.pem"
        support_bundle_path = tmp_path / "bundle.json"
        state_path = tmp_path / "state.json"
        backend_state_path = tmp_path / "backend-state.json"
        runtime_marker_path = tmp_path / "runtime-marker.json"

        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        public_key_path.write_bytes(public_pem)
        if state_payload is not None:
            state_path.write_text(json.dumps(state_payload), encoding="utf-8")

        command = [
            sys.executable,
            "-m",
            "vpn_client.cli",
            "--manifest",
            str(manifest_path),
            "--public-key",
            str(public_key_path),
            "--cache-dir",
            str(tmp_path / "cache"),
            "--state-file",
            str(state_path),
            "--runtime-marker",
            str(runtime_marker_path),
            "--backend-state-file",
            str(backend_state_path),
            "--support-bundle",
            str(support_bundle_path),
            *args,
        ]
        result = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            capture_output=True,
            env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            check=False,
        )
        bundle = json.loads(support_bundle_path.read_text(encoding="utf-8"))
        return result.returncode, result.stdout, bundle


def _check_linux_xray_smoke_gate() -> list[str]:
    if not DEMO_MANIFEST.exists():
        return [f"missing required file: {DEMO_MANIFEST.relative_to(ROOT)}"]

    payload = json.loads(_read_text(DEMO_MANIFEST))
    platform_payload = payload.get("platform_capabilities", {}).get("linux")
    if not isinstance(platform_payload, dict):
        return ["linux+xray smoke gate: demo manifest is missing linux platform capability"]

    capability = PlatformCapability(
        platform=str(platform_payload.get("platform", "linux")),
        supported_dataplanes=[str(item) for item in platform_payload.get("supported_dataplanes", [])],
        network_adapter=str(platform_payload.get("network_adapter", "")),
        startup_reconciliation=bool(platform_payload.get("startup_reconciliation", False)),
        status=str(platform_payload.get("status", "planned")),
        notes=str(platform_payload.get("notes", "")),
    )
    assessment = assess_runtime_support(
        client_platform=ClientPlatform.LINUX,
        dataplane_name="xray-core",
        platform_adapter_name="linux",
        platform_capability=capability,
    )
    if not assessment.in_mvp_scope or assessment.tier != "mvp-supported":
        return [
            "linux+xray smoke gate: runtime support no longer assesses linux + xray-core + linux adapter as mvp-supported"
        ]

    endpoint_payload = next(
        (
            item for item in payload.get("endpoints", [])
            if isinstance(item, dict) and item.get("metadata", {}).get("dataplane") == "xray-core"
        ),
        None,
    )
    if endpoint_payload is None:
        return ["linux+xray smoke gate: demo manifest is missing an xray-core endpoint"]

    endpoint = Endpoint(
        id=str(endpoint_payload["id"]),
        host=str(endpoint_payload["host"]),
        port=int(endpoint_payload["port"]),
        transport=str(endpoint_payload["transport"]),
        region=str(endpoint_payload["region"]),
        tags=[str(item) for item in endpoint_payload.get("tags", [])],
        metadata=dict(endpoint_payload.get("metadata", {})),
    )
    policy_payload = payload.get("network_policy", {})
    policy = NetworkPolicy(
        tunnel_mode=TunnelMode(str(policy_payload.get("tunnel_mode", "full"))),
        dns_mode=DnsMode(str(policy_payload.get("dns_mode", "vpn_only"))),
        kill_switch_enabled=bool(policy_payload.get("kill_switch_enabled", True)),
        ipv6_enabled=bool(policy_payload.get("ipv6_enabled", False)),
        allow_lan_while_connected=bool(policy_payload.get("allow_lan_while_connected", False)),
    )

    stack = LinuxNetworkStack(interface_name="tun42", dry_run=True)
    applied = stack.apply(endpoint, policy)
    if stack.last_plan is None or not stack.last_plan.commands:
        return ["linux+xray smoke gate: linux adapter did not produce a command plan"]
    if applied.endpoint_id != endpoint.id:
        return ["linux+xray smoke gate: linux adapter did not apply the expected endpoint"]

    with tempfile.TemporaryDirectory() as tmp:
        backend = XrayCoreDataPlane(
            interface_name="tun42",
            dry_run=True,
            config_dir=Path(tmp) / "xray",
            binary_path="xray-test",
        )
        session = backend.connect(endpoint)
        snapshot = backend.runtime_snapshot()
        config_path = snapshot.get("config_path")

        failures: list[str] = []
        if session.backend_name != "xray-core":
            failures.append("linux+xray smoke gate: xray backend did not report xray-core as the active backend")
        if not snapshot.get("active"):
            failures.append("linux+xray smoke gate: xray runtime snapshot did not stay active in dry-run mode")
        if not config_path or not Path(str(config_path)).exists():
            failures.append("linux+xray smoke gate: xray runtime did not render a config file")
        command = snapshot.get("command") or []
        if not command or command[0] != "xray-test":
            failures.append("linux+xray smoke gate: xray runtime command did not use the expected binary path")
        backend.disconnect()
        return failures


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run compact release guardrails before opening or shipping a candidate."
    )
    parser.add_argument(
        "--run-local-checks",
        action="store_true",
        help="also run local compileall and unittest checks",
    )
    parser.add_argument(
        "--allow-dirty-tree",
        action="store_true",
        help="skip the clean working tree check while keeping the other guardrails",
    )
    args = parser.parse_args()

    failures: list[str] = []
    for path in (CI_WORKFLOW, RELEASE_CHECKLIST, README):
        if not path.exists():
            failures.append(f"missing required file: {path.relative_to(ROOT)}")

    if not failures:
        failures.extend(_check_required_snippets(CI_WORKFLOW, REQUIRED_CI_SNIPPETS))
        failures.extend(_check_required_snippets(RELEASE_CHECKLIST, REQUIRED_RELEASE_CHECKLIST_SNIPPETS))
        if not args.allow_dirty_tree:
            failures.extend(_check_git_clean())
        failures.extend(_check_cache_not_tracked())
        failures.extend(_check_linux_xray_smoke_gate())
        failures.extend(_check_release_artifact_policy())
        failures.extend(_check_incident_narrative_consistency())
        if args.run_local_checks:
            failures.extend(_run_local_checks())

    if failures:
        print("release guardrail: FAILED")
        for failure in failures:
            print(f"- {failure}")
        return 1

    print("release guardrail: OK")
    print("- CI workflow includes the baseline compile and test commands")
    print("- release checklist still documents the same local gates")
    print("- working tree is clean and .cache is not tracked")
    print("- linux+xray MVP contour smoke gate passed")
    print("- CLI and support bundle stay aligned on release-facing policy and incident facts")
    print("- incident narrative stays aligned across CLI, telemetry, and support bundle")
    if args.run_local_checks:
        print("- local compileall and unittest checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
