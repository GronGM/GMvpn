from __future__ import annotations

from dataclasses import dataclass

from vpn_client.models import Endpoint, FailureClass, FailureReasonCode, NetworkPolicy, default_reason_code_for_failure


class NetworkStackError(Exception):
    def __init__(
        self,
        failure_class: FailureClass,
        detail: str,
        reason_code: FailureReasonCode | None = None,
    ):
        super().__init__(detail)
        self.failure_class = failure_class
        self.reason_code = reason_code or default_reason_code_for_failure(failure_class)
        self.detail = detail


@dataclass(slots=True)
class AppliedNetworkState:
    endpoint_id: str
    tunnel_mode: str
    dns_mode: str
    kill_switch_enabled: bool
    ipv6_enabled: bool


class SimulatedNetworkStack:
    """
    Minimal platform-network layer that models what the real client must do:
    apply routes, DNS policy, and kill switch semantics after transport connect.
    """

    def __init__(self) -> None:
        self.platform_name = "simulated"
        self.kill_switch_active = False
        self.applied_state: AppliedNetworkState | None = None

    def apply(self, endpoint: Endpoint, policy: NetworkPolicy) -> AppliedNetworkState:
        simulated = str(endpoint.metadata.get("network_stack_failure", ""))
        if simulated == "routes":
            self.kill_switch_active = policy.kill_switch_enabled
            raise NetworkStackError(
                FailureClass.NETWORK_DOWN,
                "route programming failed",
                reason_code=FailureReasonCode.ROUTE_PROGRAMMING_FAILED,
            )
        if simulated == "dns":
            self.kill_switch_active = policy.kill_switch_enabled
            raise NetworkStackError(
                FailureClass.DNS_INTERFERENCE,
                "secure DNS policy could not be applied",
                reason_code=FailureReasonCode.SECURE_DNS_POLICY_FAILED,
            )

        self.kill_switch_active = policy.kill_switch_enabled
        self.applied_state = AppliedNetworkState(
            endpoint_id=endpoint.id,
            tunnel_mode=policy.tunnel_mode.value,
            dns_mode=policy.dns_mode.value,
            kill_switch_enabled=policy.kill_switch_enabled,
            ipv6_enabled=policy.ipv6_enabled,
        )
        return self.applied_state

    def disconnect(self) -> None:
        self.teardown()

    def reconnect(self, endpoint: Endpoint, policy: NetworkPolicy) -> AppliedNetworkState:
        self.disconnect()
        return self.apply(endpoint, policy)

    def supports_startup_reconciliation(self) -> bool:
        return False

    def reconcile_startup(self):
        return None

    def teardown(self) -> None:
        self.applied_state = None
        self.kill_switch_active = False
