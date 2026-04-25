from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


TOOL_PATH = Path(__file__).resolve().parents[1] / "tools" / "xray_config_smoke.py"
SPEC = importlib.util.spec_from_file_location("xray_config_smoke", TOOL_PATH)
assert SPEC is not None and SPEC.loader is not None
xray_config_smoke = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = xray_config_smoke
SPEC.loader.exec_module(xray_config_smoke)


class XrayConfigSmokeTests(unittest.TestCase):
    def test_build_smoke_endpoint_suite_covers_example_and_inline_cases(self) -> None:
        suite = xray_config_smoke.build_smoke_endpoint_suite()

        self.assertGreaterEqual(len(suite), 5)
        sources = {source for source, _endpoint in suite}
        endpoint_ids = {endpoint.id for _source, endpoint in suite}

        self.assertIn("demo_manifest.json", sources)
        self.assertIn("provider_profile_manifest.json", sources)
        self.assertIn("inline", sources)
        self.assertIn("smoke-vmess-grpc", endpoint_ids)
        self.assertIn("smoke-trojan-tls", endpoint_ids)

    def test_render_smoke_configs_writes_conservative_tun_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rendered = xray_config_smoke.render_smoke_configs(Path(tmp), interface_name="tun77")

            self.assertGreaterEqual(len(rendered), 5)
            payload = rendered[0].config_path.read_text(encoding="utf-8")
            self.assertIn('"name": "tun77"', payload)
            self.assertIn('"MTU": 1380', payload)
            self.assertNotIn('"autoRoute"', payload)
            self.assertNotIn('"strictRoute"', payload)
            self.assertNotIn('"stack"', payload)

    def test_render_smoke_configs_can_switch_to_socks_validation_inbound(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rendered = xray_config_smoke.render_smoke_configs(
                Path(tmp),
                validation_inbound_mode="socks",
            )

            payload = rendered[0].config_path.read_text(encoding="utf-8")
            self.assertIn('"protocol": "socks"', payload)
            self.assertIn('"tag": "smoke-in"', payload)
            self.assertNotIn('"protocol": "tun"', payload)

    def test_validate_with_xray_reports_failing_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rendered = xray_config_smoke.render_smoke_configs(Path(tmp))
            failing = rendered[0].config_path

            def fake_runner(command: list[str], **_kwargs):
                if command[-1] == str(failing):
                    return SimpleNamespace(returncode=1, stdout="", stderr="bad field")
                return SimpleNamespace(returncode=0, stdout="Configuration OK", stderr="")

            failures = xray_config_smoke.validate_with_xray(
                rendered,
                xray_binary="xray",
                runner=fake_runner,
            )

            self.assertEqual(len(failures), 1)
            self.assertIn(rendered[0].endpoint_id, failures[0])
            self.assertIn("bad field", failures[0])

    def test_prepare_endpoint_for_xray_validation_replaces_demo_reality_placeholder(self) -> None:
        endpoint = xray_config_smoke.Endpoint(
            id="edge",
            host="198.51.100.1",
            port=443,
            transport="https",
            region="smoke",
            metadata={
                "dataplane": "xray-core",
                "xray_security": "reality",
                "xray_reality_public_key": "PUBLIC_KEY_HERE",
            },
        )

        prepared = xray_config_smoke._prepare_endpoint_for_xray_validation(endpoint)

        self.assertNotEqual(prepared.metadata["xray_reality_public_key"], "PUBLIC_KEY_HERE")


if __name__ == "__main__":
    unittest.main()
