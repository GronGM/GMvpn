from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE_CHECKLIST = ROOT / "docs" / "release-checklist.md"
README = ROOT / "README.md"

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
    if args.run_local_checks:
        print("- local compileall and unittest checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
