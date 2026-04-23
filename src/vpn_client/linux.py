from __future__ import annotations

from dataclasses import dataclass
import subprocess

from vpn_client.models import Endpoint, NetworkPolicy
from vpn_client.platform import AppliedNetworkState, NetworkStackError, SimulatedNetworkStack
from vpn_client.models import FailureClass


@dataclass(slots=True)
class LinuxCommandPlan:
    commands: list[list[str]]
    rollback_commands: list[list[str]]
    dry_run: bool


@dataclass(slots=True)
class LinuxExecutionReport:
    applied_commands: list[list[str]]
    rollback_commands: list[list[str]]
    rolled_back: bool
    action: str


@dataclass(slots=True)
class LinuxReconciliationReport:
    commands: list[list[str]]
    dry_run: bool
    executed: bool


class LinuxNetworkStack(SimulatedNetworkStack):
    """
    Linux-first command planner. By default it stays in dry-run mode and only
    produces the commands that a real executor would apply.
    """

    def __init__(
        self,
        interface_name: str = "tun0",
        dry_run: bool = True,
        command_runner=None,
    ) -> None:
        super().__init__()
        self.interface_name = interface_name
        self.dry_run = dry_run
        self.command_runner = command_runner or self._default_command_runner
        self.last_plan: LinuxCommandPlan | None = None
        self.last_execution: LinuxExecutionReport | None = None
        self.last_reconciliation: LinuxReconciliationReport | None = None

    def apply(self, endpoint: Endpoint, policy: NetworkPolicy) -> AppliedNetworkState:
        simulated = str(endpoint.metadata.get("network_stack_failure", ""))
        if simulated in {"routes", "dns"}:
            return super().apply(endpoint, policy)

        if self.applied_state is not None:
            self.disconnect()

        commands = self._build_plan(endpoint, policy)
        self.last_plan = LinuxCommandPlan(
            commands=commands,
            rollback_commands=self._build_rollback_plan(endpoint, policy),
            dry_run=self.dry_run,
        )
        if not self.dry_run:
            self._execute_plan(self.last_plan, action="apply")
        self.kill_switch_active = policy.kill_switch_enabled
        self.applied_state = AppliedNetworkState(
            endpoint_id=endpoint.id,
            tunnel_mode=policy.tunnel_mode.value,
            dns_mode=policy.dns_mode.value,
            kill_switch_enabled=policy.kill_switch_enabled,
            ipv6_enabled=policy.ipv6_enabled,
        )
        return self.applied_state

    def _build_plan(self, endpoint: Endpoint, policy: NetworkPolicy) -> list[list[str]]:
        commands: list[list[str]] = [
            ["ip", "link", "set", self.interface_name, "up"],
            ["ip", "route", "replace", endpoint.host, "dev", self.interface_name],
        ]
        if policy.tunnel_mode.value == "full":
            commands.append(["ip", "route", "replace", "default", "dev", self.interface_name])
        if policy.kill_switch_enabled:
            commands.append(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "filter",
                    "output",
                    "oifname",
                    "!=",
                    self.interface_name,
                    "drop",
                ]
            )
        if policy.dns_mode.value == "vpn_only":
            commands.append(["resolvectl", "dns", self.interface_name, endpoint.host])
        return commands

    def _build_rollback_plan(self, endpoint: Endpoint, policy: NetworkPolicy) -> list[list[str]]:
        rollback_commands: list[list[str]] = []
        if policy.dns_mode.value == "vpn_only":
            rollback_commands.append(["resolvectl", "revert", self.interface_name])
        if policy.kill_switch_enabled:
            rollback_commands.append(
                [
                    "nft",
                    "delete",
                    "rule",
                    "inet",
                    "filter",
                    "output",
                    "oifname",
                    "!=",
                    self.interface_name,
                    "drop",
                ]
            )
        if policy.tunnel_mode.value == "full":
            rollback_commands.append(["ip", "route", "del", "default", "dev", self.interface_name])
        rollback_commands.append(["ip", "route", "del", endpoint.host, "dev", self.interface_name])
        rollback_commands.append(["ip", "link", "set", self.interface_name, "down"])
        return rollback_commands

    def reconcile_startup(self) -> LinuxReconciliationReport:
        commands = [
            ["resolvectl", "revert", self.interface_name],
            ["ip", "route", "del", "default", "dev", self.interface_name],
            ["ip", "link", "set", self.interface_name, "down"],
            ["nft", "delete", "rule", "inet", "filter", "output", "oifname", "!=", self.interface_name, "drop"],
        ]
        executed = False
        if not self.dry_run:
            for command in commands:
                try:
                    self.command_runner(command)
                except Exception:
                    continue
            executed = True
        self.last_reconciliation = LinuxReconciliationReport(commands=commands, dry_run=self.dry_run, executed=executed)
        return self.last_reconciliation

    def disconnect(self) -> None:
        if self.last_plan is None:
            self.teardown()
            return
        if not self.dry_run:
            self._execute_disconnect(self.last_plan)
        self.teardown()

    def reconnect(self, endpoint: Endpoint, policy: NetworkPolicy) -> AppliedNetworkState:
        self.disconnect()
        return self.apply(endpoint, policy)

    def _execute_plan(self, plan: LinuxCommandPlan, action: str) -> None:
        applied_commands: list[list[str]] = []
        rollback_attempts: list[list[str]] = []
        try:
            for command in plan.commands:
                self.command_runner(command)
                applied_commands.append(command)
            self.last_execution = LinuxExecutionReport(
                applied_commands=applied_commands,
                rollback_commands=[],
                rolled_back=False,
                action=action,
            )
        except Exception as exc:
            for command in plan.rollback_commands:
                try:
                    self.command_runner(command)
                    rollback_attempts.append(command)
                except Exception:
                    continue
            self.kill_switch_active = False
            self.applied_state = None
            self.last_execution = LinuxExecutionReport(
                applied_commands=applied_commands,
                rollback_commands=rollback_attempts,
                rolled_back=True,
                action=action,
            )
            raise NetworkStackError(FailureClass.NETWORK_DOWN, f"linux plan execution failed: {exc}") from exc

    def _execute_disconnect(self, plan: LinuxCommandPlan) -> None:
        executed: list[list[str]] = []
        try:
            for command in plan.rollback_commands:
                self.command_runner(command)
                executed.append(command)
            self.last_execution = LinuxExecutionReport(
                applied_commands=[],
                rollback_commands=executed,
                rolled_back=True,
                action="disconnect",
            )
        except Exception as exc:
            self.last_execution = LinuxExecutionReport(
                applied_commands=[],
                rollback_commands=executed,
                rolled_back=True,
                action="disconnect",
            )
            raise NetworkStackError(FailureClass.NETWORK_DOWN, f"linux disconnect failed: {exc}") from exc

    def _default_command_runner(self, command: list[str]) -> None:
        subprocess.run(command, check=True, capture_output=True, text=True)

    def require_real_mode(self) -> None:
        if self.dry_run:
            raise NetworkStackError(FailureClass.UNKNOWN, "linux stack is configured in dry-run mode")
