from __future__ import annotations

import unittest

from vpn_client.linux import LinuxNetworkStack
from vpn_client.models import DnsMode, Endpoint, NetworkPolicy, TunnelMode


class LinuxNetworkStackTests(unittest.TestCase):
    def test_linux_stack_builds_dry_run_command_plan(self) -> None:
        stack = LinuxNetworkStack(interface_name="tun42", dry_run=True)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
        )
        policy = NetworkPolicy(
            tunnel_mode=TunnelMode.FULL,
            dns_mode=DnsMode.VPN_ONLY,
            kill_switch_enabled=True,
            ipv6_enabled=False,
        )

        state = stack.apply(endpoint, policy)

        self.assertEqual(state.endpoint_id, "edge-1")
        self.assertTrue(stack.kill_switch_active)
        self.assertEqual(stack.last_plan.commands[0], ["ip", "link", "set", "tun42", "up"])

    def test_linux_stack_rolls_back_on_runner_failure(self) -> None:
        seen: list[list[str]] = []

        def runner(command: list[str]) -> None:
            seen.append(command)
            if command[:3] == ["ip", "route", "replace"]:
                raise RuntimeError("boom")

        stack = LinuxNetworkStack(interface_name="tun42", dry_run=False, command_runner=runner)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
        )
        policy = NetworkPolicy(
            tunnel_mode=TunnelMode.FULL,
            dns_mode=DnsMode.VPN_ONLY,
            kill_switch_enabled=True,
            ipv6_enabled=False,
        )

        with self.assertRaises(Exception):
            stack.apply(endpoint, policy)

        self.assertTrue(stack.last_execution.rolled_back)
        self.assertIn(["ip", "link", "set", "tun42", "down"], seen)

    def test_linux_stack_disconnect_executes_rollback_plan(self) -> None:
        seen: list[list[str]] = []

        def runner(command: list[str]) -> None:
            seen.append(command)

        stack = LinuxNetworkStack(interface_name="tun42", dry_run=False, command_runner=runner)
        endpoint = Endpoint(
            id="edge-1",
            host="198.51.100.20",
            port=443,
            transport="https",
            region="eu-central",
        )
        policy = NetworkPolicy(
            tunnel_mode=TunnelMode.FULL,
            dns_mode=DnsMode.VPN_ONLY,
            kill_switch_enabled=True,
            ipv6_enabled=False,
        )

        stack.apply(endpoint, policy)
        stack.disconnect()

        self.assertEqual(stack.last_execution.action, "disconnect")
        self.assertIn(["ip", "link", "set", "tun42", "down"], seen)

    def test_linux_stack_builds_startup_reconciliation_plan(self) -> None:
        stack = LinuxNetworkStack(interface_name="tun42", dry_run=True)

        report = stack.reconcile_startup()

        self.assertTrue(report.dry_run)
        self.assertFalse(report.executed)
        self.assertEqual(report.commands[0], ["resolvectl", "revert", "tun42"])


if __name__ == "__main__":
    unittest.main()
