from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path


TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "generate_demo_assets.py"
SPEC = importlib.util.spec_from_file_location("generate_demo_assets", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
generate_demo_assets = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = generate_demo_assets
SPEC.loader.exec_module(generate_demo_assets)

ROOT = Path(__file__).resolve().parents[1]


def _without_signature(payload: dict[str, object]) -> dict[str, object]:
    cleaned = json.loads(json.dumps(payload))
    cleaned.pop("signature", None)
    return cleaned


class GenerateDemoAssetsTests(unittest.TestCase):
    def test_build_demo_manifest_matches_checked_in_example_shape(self) -> None:
        private_pem, _public_pem = generate_demo_assets.generate_keypair()

        generated = generate_demo_assets.build_demo_manifest(private_pem)
        checked_in = json.loads((ROOT / "examples" / "demo_manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(_without_signature(generated), _without_signature(checked_in))

    def test_build_provider_profile_example_matches_checked_in_example_shape(self) -> None:
        private_pem, _public_pem = generate_demo_assets.generate_keypair()

        generated = generate_demo_assets.build_provider_profile_example(
            private_pem,
            generate_demo_assets._platform_capabilities(),
        )
        checked_in = json.loads((ROOT / "examples" / "provider_profile_manifest.json").read_text(encoding="utf-8"))

        self.assertEqual(_without_signature(generated), _without_signature(checked_in))


if __name__ == "__main__":
    unittest.main()
