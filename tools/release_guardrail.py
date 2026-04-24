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
from vpn_client.xray import XrayCoreDataPlane


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
    if args.run_local_checks:
        print("- local compileall and unittest checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
