from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

ISO_TS_RE = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
)
LEVEL_RE = re.compile(r"\b(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b", re.IGNORECASE)


@dataclass
class ParsedEvent:
    """Normalized parsed event used for analysis and DB persistence."""

    event_ts: datetime | None
    severity: str | None
    component: str | None
    service: str | None
    host: str | None
    request_id: str | None
    message: str
    raw_line: str
    structured: dict[str, Any]


def _parse_ts(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str):
        return None
    s = value.strip()
    # Accept Z suffix
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _normalize_level(level: str | None) -> str | None:
    if not level:
        return None
    l = level.strip().upper()
    if l == "WARN":
        return "WARNING"
    if l == "FATAL":
        return "CRITICAL"
    return l


def _infer_level_from_text(line: str) -> str | None:
    m = LEVEL_RE.search(line)
    return _normalize_level(m.group("level")) if m else None


def _infer_ts_from_text(line: str) -> datetime | None:
    m = ISO_TS_RE.search(line)
    return _parse_ts(m.group("ts")) if m else None


# PUBLIC_INTERFACE
def parse_log_lines(raw_text: str) -> list[ParsedEvent]:
    """
    Parse raw log text (JSON-per-line or unstructured) into normalized events.

    Strategy:
    - First try JSON decode for each non-empty line (common structured logs).
    - Fallback to heuristic extraction of ISO timestamps + severity keywords.
    """
    events: list[ParsedEvent] = []
    for i, raw_line in enumerate(raw_text.splitlines()):
        line = raw_line.strip("\n")
        if not line.strip():
            continue

        structured: dict[str, Any] = {}
        message = line
        event_ts: datetime | None = None
        severity: str | None = None
        component: str | None = None
        service: str | None = None
        host: str | None = None
        request_id: str | None = None

        # JSON log line
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                structured = obj
                # Common field names (best-effort, non-destructive)
                event_ts = _parse_ts(obj.get("timestamp") or obj.get("ts") or obj.get("@timestamp"))
                severity = _normalize_level(obj.get("level") or obj.get("severity"))
                component = obj.get("component") or obj.get("logger") or obj.get("module")
                service = obj.get("service") or obj.get("app") or obj.get("application")
                host = obj.get("host") or obj.get("hostname")
                request_id = obj.get("request_id") or obj.get("trace_id") or obj.get("correlation_id")

                message = str(obj.get("message") or obj.get("msg") or obj.get("event") or line)
        except json.JSONDecodeError:
            # Unstructured line
            event_ts = _infer_ts_from_text(line)
            severity = _infer_level_from_text(line)

        events.append(
            ParsedEvent(
                event_ts=event_ts,
                severity=severity,
                component=component,
                service=service,
                host=host,
                request_id=request_id,
                message=message,
                raw_line=raw_line,
                structured=structured,
            )
        )

    return events
