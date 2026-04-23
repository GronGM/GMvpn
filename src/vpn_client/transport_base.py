from __future__ import annotations

from vpn_client.models import Endpoint, FailureClass


class TransportError(Exception):
    def __init__(self, failure_class: FailureClass, detail: str):
        super().__init__(detail)
        self.failure_class = failure_class
        self.detail = detail


class Transport:
    name: str

    def connect(self, endpoint: Endpoint) -> None:
        raise NotImplementedError

    def disconnect(self) -> None:
        raise NotImplementedError
