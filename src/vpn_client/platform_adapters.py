from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from vpn_client.linux import LinuxNetworkStack, LinuxReconciliationReport
from vpn_client.models import Endpoint, FailureClass, NetworkPolicy
from vpn_client.platform import AppliedNetworkState, NetworkStackError, SimulatedNetworkStack


class PlatformNetworkAdapter(Protocol):
    platform_name: str
    kill_switch_active: bool
    applied_state: AppliedNetworkState | None

    def apply(self, endpoint: Endpoint, policy: NetworkPolicy) -> AppliedNetworkState: ...

    def disconnect(self) -> None: ...

    def reconnect(self, endpoint: Endpoint, policy: NetworkPolicy) -> AppliedNetworkState: ...

    def supports_startup_reconciliation(self) -> bool: ...

    def reconcile_startup(self) -> LinuxReconciliationReport | None: ...


@dataclass(slots=True)
class PlaceholderReconciliationReport:
    commands: list[list[str]]
    dry_run: bool
    executed: bool


class BasePlatformAdapter(SimulatedNetworkStack):
    platform_name = "simulated"

    def supports_startup_reconciliation(self) -> bool:
        return False

    def reconcile_startup(self) -> PlaceholderReconciliationReport | None:
        return None


class WindowsNetworkAdapter(BasePlatformAdapter):
    platform_name = "windows"


class MacOSNetworkAdapter(BasePlatformAdapter):
    platform_name = "macos"


class AndroidNetworkAdapter(BasePlatformAdapter):
    platform_name = "android"


class IOSNetworkAdapter(BasePlatformAdapter):
    platform_name = "ios"


class LinuxPlatformAdapter(LinuxNetworkStack):
    platform_name = "linux"

    def supports_startup_reconciliation(self) -> bool:
        return True


def create_platform_adapter(platform_name: str, *, dry_run: bool = True) -> PlatformNetworkAdapter:
    normalized = platform_name.lower()
    if normalized == "linux":
        return LinuxPlatformAdapter(dry_run=dry_run)
    if normalized == "simulated":
        return BasePlatformAdapter()
    if normalized == "windows":
        return WindowsNetworkAdapter()
    if normalized == "macos":
        return MacOSNetworkAdapter()
    if normalized == "android":
        return AndroidNetworkAdapter()
    if normalized == "ios":
        return IOSNetworkAdapter()
    raise NetworkStackError(FailureClass.UNKNOWN, f"platform adapter '{platform_name}' is not registered")
