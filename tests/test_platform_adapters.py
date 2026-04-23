from __future__ import annotations

import unittest

from vpn_client.platform import NetworkStackError
from vpn_client.platform_adapters import (
    AndroidNetworkAdapter,
    BasePlatformAdapter,
    IOSNetworkAdapter,
    LinuxPlatformAdapter,
    MacOSNetworkAdapter,
    WindowsNetworkAdapter,
    create_platform_adapter,
)


class PlatformAdapterFactoryTests(unittest.TestCase):
    def test_factory_returns_linux_adapter(self) -> None:
        adapter = create_platform_adapter("linux", dry_run=True)

        self.assertIsInstance(adapter, LinuxPlatformAdapter)
        self.assertEqual(adapter.platform_name, "linux")
        self.assertTrue(adapter.supports_startup_reconciliation())

    def test_factory_returns_placeholder_adapters_for_other_platforms(self) -> None:
        self.assertIsInstance(create_platform_adapter("simulated"), BasePlatformAdapter)
        self.assertIsInstance(create_platform_adapter("windows"), WindowsNetworkAdapter)
        self.assertIsInstance(create_platform_adapter("macos"), MacOSNetworkAdapter)
        self.assertIsInstance(create_platform_adapter("android"), AndroidNetworkAdapter)
        self.assertIsInstance(create_platform_adapter("ios"), IOSNetworkAdapter)

    def test_factory_rejects_unknown_platform(self) -> None:
        with self.assertRaises(NetworkStackError):
            create_platform_adapter("plan9")
