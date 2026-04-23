from __future__ import annotations

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


if __name__ == "__main__":
    unittest.main()
