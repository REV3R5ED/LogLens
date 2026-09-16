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


def _leading_text_timestamp(message: str) -> datetime | None:
    """Parse a leading ISO timestamp without guessing at dates later in a message."""
    parts = message.lstrip().split(maxsplit=2)
    if not parts:
        return None

    # Bracketed timestamps are common in application logs. Normalize brackets
    # only on the leading timestamp tokens so arbitrary dates later in a message
    # are never interpreted as event time.
    first = parts[0].strip("[]")
    if len(parts) >= 2:
        second = parts[1].strip("[]")
        combined = _timestamp(f"{first}T{second}")
        if combined is not None:
            return combined
    return _timestamp(first)


def parse_text_line(line: str, *, source: str | None = None) -> LogEvent:
    """Normalize text and infer an explicit level plus a leading ISO timestamp."""
    message = line.rstrip("\r\n")
    tokens = message.replace("[", " ").replace("]", " ").replace(":", " ").split()
    level = "UNKNOWN"
    for token in tokens:
        candidate = token.upper()
        if candidate in _LEVELS:
            level = candidate
            break

    timestamp = _leading_text_timestamp(message)
    return LogEvent(message=message, level=level, timestamp=timestamp, source=source)


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
