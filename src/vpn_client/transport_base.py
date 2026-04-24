from __future__ import annotations

from vpn_client.models import Endpoint, FailureClass, FailureReasonCode, default_reason_code_for_failure


class TransportError(Exception):
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


class Transport:
    name: str

    def connect(self, endpoint: Endpoint) -> None:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError
