"""Small, deterministic parsers for common log inputs."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .model import LogEvent

_LEVELS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "WARNING", "ERROR", "CRITICAL", "FATAL"}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_json_line(line: str, *, source: str | None = None) -> LogEvent:
    """Parse one JSON object into a normalized event.

    Unknown keys are preserved in ``fields`` so analysis never silently loses
    useful context.
    """
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("JSON log record must be an object")

    message = str(value.get("message", value.get("msg", "")))
    raw_level = str(value.get("level", value.get("severity", "UNKNOWN"))).upper()
    level = raw_level if raw_level in _LEVELS else "UNKNOWN"
    timestamp = _timestamp(value.get("timestamp", value.get("time")))
    reserved = {"message", "msg", "level", "severity", "timestamp", "time"}
    fields = {key: item for key, item in value.items() if key not in reserved}
    return LogEvent(message=message, level=level, timestamp=timestamp, source=source, fields=fields)


def parse_text_line(line: str, *, source: str | None = None) -> LogEvent:
    """Normalize an unstructured text line and infer an explicit level token."""
    message = line.rstrip("\r\n")
    tokens = message.replace("[", " ").replace("]", " ").replace(":", " ").split()
    level = "UNKNOWN"
    for token in tokens:
        candidate = token.upper()
        if candidate in _LEVELS:
            level = candidate
            break
    return LogEvent(message=message, level=level, source=source)


def parse_line(line: str, *, source: str | None = None, format: str = "auto") -> LogEvent:
    """Parse a line as JSON, text, or automatically detect JSON objects."""
    if format not in {"auto", "json", "text"}:
        raise ValueError("format must be one of: auto, json, text")
    if format == "json":
        return parse_json_line(line, source=source)
    if format == "text":
        return parse_text_line(line, source=source)
    if line.lstrip().startswith("{"):
        try:
            return parse_json_line(line, source=source)
        except (json.JSONDecodeError, ValueError):
            pass
    return parse_text_line(line, source=source)
