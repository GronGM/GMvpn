from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "release_guardrail.py"
SPEC = importlib.util.spec_from_file_location("release_guardrail", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
release_guardrail = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release_guardrail)


class ReleaseGuardrailTests(unittest.TestCase):
    def test_check_required_snippets_reports_missing_entries(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            sample = root / "checklist.md"
            sample.write_text("alpha\nbeta\n", encoding="utf-8")

            original_root = release_guardrail.ROOT
            try:
                release_guardrail.ROOT = root
                failures = release_guardrail._check_required_snippets(sample, ("alpha", "gamma"))
            finally:
                release_guardrail.ROOT = original_root

        self.assertEqual(failures, ["checklist.md is missing: gamma"])


if __name__ == "__main__":
    unittest.main()
