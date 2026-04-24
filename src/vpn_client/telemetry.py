from __future__ import annotations

import json
import re
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
    incident_severity: str | None = None
    primary_transport_issue: dict[str, object] | None = None


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
        incident_severity: str | None = None,
        primary_transport_issue: dict[str, object] | None = None,
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
            incident_severity=incident_severity,
            primary_transport_issue=primary_transport_issue,
        )
        self.events.append(event)
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events :]

    def export_support_bundle(self, path: Path, extra: dict | None = None) -> Path:
        bundle = _sanitize_support_bundle(
            {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "events": [asdict(event) for event in self.events],
            "extra": extra or {},
            }
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bundle, indent=2, sort_keys=True), encoding="utf-8")
        return path


_SENSITIVE_KEY_PATTERN = re.compile(r"(password|secret|token|private[_-]?key|authorization)", re.IGNORECASE)
_INLINE_SECRET_PATTERN = re.compile(
    r"(?i)\b(password|secret|token|authorization)\b(\s*[:=]\s*)([^\s,;]+)"
)
_BEARER_PATTERN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+")
_UUID_PATTERN = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_PEM_PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)
_TAIL_KEY_NAMES = {"stdout_tail", "stderr_tail"}
_MAX_TAIL_CHARS = 200
_TAIL_SEGMENT_CHARS = 90
_REDACTED = "[redacted]"


def _sanitize_support_bundle(value, key: str | None = None):
    if isinstance(value, dict):
        sanitized: dict[object, object] = {}
        for item_key, item_value in value.items():
            text_key = str(item_key)
            if _SENSITIVE_KEY_PATTERN.search(text_key):
                sanitized[item_key] = _REDACTED
            else:
                sanitized[item_key] = _sanitize_support_bundle(item_value, key=text_key)
        return sanitized
    if isinstance(value, list):
        return [_sanitize_support_bundle(item, key=key) for item in value]
    if isinstance(value, str):
        return _sanitize_bundle_string(value, key=key)
    return value


def _sanitize_bundle_string(text: str, key: str | None = None) -> str:
    sanitized = text
    sanitized = _PEM_PRIVATE_KEY_PATTERN.sub(_REDACTED, sanitized)
    sanitized = _BEARER_PATTERN.sub("Bearer [redacted]", sanitized)
    sanitized = _INLINE_SECRET_PATTERN.sub(r"\1\2[redacted]", sanitized)
    if key in _TAIL_KEY_NAMES:
        sanitized = _UUID_PATTERN.sub("[redacted-uuid]", sanitized)
        sanitized = _clip_tail_string(sanitized)
    return sanitized


def _clip_tail_string(text: str) -> str:
    if len(text) <= _MAX_TAIL_CHARS:
        return text
    prefix = text[:_TAIL_SEGMENT_CHARS]
    suffix = text[-_TAIL_SEGMENT_CHARS:]
    return f"{prefix} ... {suffix}"
