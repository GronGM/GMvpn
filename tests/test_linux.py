from __future__ import annotations

import unittest

from vpn_client.linux import LinuxNetworkStack
from vpn_client.models import DnsMode, Endpoint, FailureReasonCode, NetworkPolicy, TunnelMode
from vpn_client.platform import NetworkStackError


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

        stack = LinuxNetworkStack(
            interface_name="tun42",
            dry_run=False,
            command_runner=runner,
            command_exists=lambda _name: "/usr/bin/fake",
        )
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

        stack = LinuxNetworkStack(
            interface_name="tun42",
            dry_run=False,
            command_runner=runner,
            command_exists=lambda _name: "/usr/bin/fake",
        )
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

    def test_linux_stack_reports_missing_real_mode_tools_before_apply(self) -> None:
        stack = LinuxNetworkStack(
            interface_name="tun42",
            dry_run=False,
            command_exists=lambda name: "/usr/bin/ip" if name == "ip" else None,
        )
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

        with self.assertRaises(NetworkStackError) as ctx:
            stack.apply(endpoint, policy)

        self.assertEqual(ctx.exception.reason_code, FailureReasonCode.PLATFORM_TOOL_MISSING)
        self.assertEqual(stack.last_execution.failure_reason_code, FailureReasonCode.PLATFORM_TOOL_MISSING.value)
        self.assertEqual(stack.last_execution.missing_commands, ["nft", "resolvectl"])

    def test_linux_stack_reports_missing_real_mode_tools_before_reconciliation(self) -> None:
        stack = LinuxNetworkStack(
            interface_name="tun42",
            dry_run=False,
            command_exists=lambda _name: None,
        )

        report = stack.reconcile_startup()

        self.assertFalse(report.executed)
        self.assertTrue(report.partial_failure)
        self.assertEqual(report.failure_reason_code, FailureReasonCode.PLATFORM_TOOL_MISSING.value)
        self.assertEqual(stack.last_reconciliation.missing_commands, ["ip", "nft", "resolvectl"])

    def test_linux_stack_disconnect_reports_partial_cleanup_without_raising(self) -> None:
        seen: list[list[str]] = []

        def runner(command: list[str]) -> None:
            seen.append(command)
            if command[:3] == ["ip", "route", "del"]:
                raise RuntimeError("route still busy")

        stack = LinuxNetworkStack(
            interface_name="tun42",
            dry_run=False,
            command_runner=runner,
            command_exists=lambda _name: "/usr/bin/fake",
        )
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

        self.assertTrue(stack.last_execution.cleanup_incomplete)
        self.assertEqual(stack.last_execution.failure_reason_code, FailureReasonCode.ROUTE_PROGRAMMING_FAILED.value)
        self.assertIn(["ip", "link", "set", "tun42", "down"], seen)
        self.assertEqual(stack.last_execution.failed_commands[0][:3], ["ip", "route", "del"])


if __name__ == "__main__":
    unittest.main()
