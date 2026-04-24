from __future__ import annotations

import unittest

from vpn_client.client_platform import ClientPlatform
from vpn_client.runtime_support import assess_runtime_support


class RuntimeSupportTests(unittest.TestCase):
    def test_linux_xray_contour_is_marked_as_first_mvp_target(self) -> None:
        assessment = assess_runtime_support(
            client_platform=ClientPlatform.LINUX,
            dataplane_name="xray-core",
            platform_adapter_name="linux",
        )

        self.assertEqual(assessment.tier, "mvp-supported")
        self.assertTrue(assessment.in_mvp_scope)

    def test_ios_bridge_is_marked_as_bridge_only(self) -> None:
        assessment = assess_runtime_support(
            client_platform=ClientPlatform.IOS,
            dataplane_name="ios-bridge",
            platform_adapter_name="ios",
        )

        self.assertEqual(assessment.tier, "bridge-only")
        self.assertFalse(assessment.in_mvp_scope)
        self.assertIn("the Apple Network Extension runtime is not implemented yet", assessment.caveats)

    def test_windows_path_is_marked_as_planned(self) -> None:
        assessment = assess_runtime_support(
            client_platform=ClientPlatform.WINDOWS,
            dataplane_name="xray-core",
            platform_adapter_name="windows",
        )

        self.assertEqual(assessment.tier, "planned")
        self.assertFalse(assessment.in_mvp_scope)
