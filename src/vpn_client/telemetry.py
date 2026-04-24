from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from vpn_client.models import FailureClass, FailureReasonCode, SessionState, default_reason_code_for_failure


@dataclass(slots=True)
class TelemetryEvent:
    ts: str
    kind: str
    session_state: str
    failure_class: str
    reason_code: str
    endpoint_id: str | None = None
    transport: str | None = None
    detail: str = ""


class TelemetryRecorder:
    def __init__(self, max_events: int = 128):
        self.max_events = max_events
        self.events: list[TelemetryEvent] = []

    def record(
        self,
        kind: str,
        session_state: SessionState,
        failure_class: FailureClass = FailureClass.NONE,
        reason_code: FailureReasonCode | None = None,
        endpoint_id: str | None = None,
        transport: str | None = None,
        detail: str = "",
    ) -> None:
        event = TelemetryEvent(
            ts=datetime.now(timezone.utc).isoformat(),
            kind=kind,
            session_state=session_state.value,
            failure_class=failure_class.value,
            reason_code=(reason_code or default_reason_code_for_failure(failure_class)).value,
            endpoint_id=endpoint_id,
            transport=transport,
            detail=detail[:160],
        )
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events :]

    def export_support_bundle(self, path: Path, extra: dict | None = None) -> Path:
        bundle = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "events": [asdict(event) for event in self.events],
            "extra": extra or {},
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
        return path
