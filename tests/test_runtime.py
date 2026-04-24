from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from vpn_client.runtime import RuntimeState


class RuntimeStateTests(unittest.TestCase):
    def test_runtime_marker_can_be_written_and_cleared(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            runtime = RuntimeState(Path(tmp) / "marker.json")
            runtime.mark_active("edge-1", "https")

            marker = runtime.load_marker()
            self.assertEqual(marker.endpoint_id, "edge-1")

            runtime.clear()
            self.assertIsNone(runtime.load_marker())

    def test_runtime_marker_recovers_from_corrupted_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "marker.json"
            path.write_text("{bad json", encoding="utf-8")
            runtime = RuntimeState(path)

            self.assertIsNone(runtime.load_marker())
            self.assertFalse(path.exists())

    def test_runtime_marker_recovers_from_invalid_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "marker.json"
            path.write_text(json.dumps({"endpoint_id": "edge-1"}), encoding="utf-8")
            runtime = RuntimeState(path)

            self.assertIsNone(runtime.load_marker())
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
