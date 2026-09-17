"""Small, deterministic parsers for common log inputs."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from .model import LogEvent

_LEVELS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "CRITICAL"}
_LEVEL_ALIASES = {
    "WARNING": "WARN",
    "ERR": "ERROR",
    "FATAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "ALERT": "CRITICAL",
    "EMERG": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "INFORMATION": "INFO",
    "INFORMATIONAL": "INFO",
}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _level(value: Any) -> str:
    candidate = str(value).strip().upper()
    return _LEVEL_ALIASES.get(candidate, candidate if candidate in _LEVELS else "UNKNOWN")


def _first_present(record: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    """Return the first explicitly present alias, preserving falsey values."""
    for key in keys:
        if key in record:
            return record[key]
    return default


def _nested_present(record: dict[str, Any], path: tuple[str, ...], default: Any = None) -> Any:
    """Return a nested value only when every path component is explicitly present."""
    value: Any = record
    for key in path:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value


def parse_json_line(line: str, *, source: str | None = None) -> LogEvent:
    """Parse one JSON object into a normalized event.

    Unknown keys are preserved in ``fields`` so analysis never silently loses
    useful context. Common ECS, OpenTelemetry, and logging aliases are normalized
    explicitly.
    """
    value = json.loads(line)
    if not isinstance(value, dict):
        raise ValueError("JSON log record must be an object")

    message = str(_first_present(value, ("message", "msg", "body"), ""))
    raw_level = _first_present(value, ("level", "severity", "log.level", "severity_text"))
    if raw_level is None:
        raw_level = _nested_present(value, ("log", "level"), "UNKNOWN")
    level = _level(raw_level)
    timestamp = _timestamp(_first_present(value, ("timestamp", "time", "@timestamp", "ts", "observed_timestamp")))
    reserved = {
        "message", "msg", "body", "level", "severity", "log.level", "severity_text",
        "timestamp", "time", "@timestamp", "ts", "observed_timestamp",
    }
    fields = {key: item for key, item in value.items() if key not in reserved}
    return LogEvent(message=message, level=level, timestamp=timestamp, source=source, fields=fields)


def _leading_text_timestamp(message: str) -> datetime | None:
    """Parse a leading ISO timestamp without guessing at dates later in a message."""
    parts = message.lstrip().split(maxsplit=2)
    if not parts:
        return None

    first = parts[0].strip("[]")
    if len(parts) >= 2:
        second = parts[1].strip("[]")
        combined = _timestamp(f"{first}T{second}")
        if combined is not None:
            return combined
    return _timestamp(first)


def _text_level(token: str) -> str:
    """Normalize a bare severity token or an explicit level/severity key-value token."""
    candidate = _level(token)
    if candidate != "UNKNOWN":
        return candidate

    key, separator, value = token.partition("=")
    if separator and key.strip().lower() in {"level", "severity"}:
        return _level(value.strip("[],'\""))
    return "UNKNOWN"


def _logfmt_timestamp(tokens: list[str]) -> datetime | None:
    """Parse an explicit logfmt timestamp field without guessing unrelated values."""
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator and key.strip().lower() in {"ts", "timestamp", "time"}:
            parsed = _timestamp(value.strip("[],'\""))
            if parsed is not None:
                return parsed
    return None


def parse_text_line(line: str, *, source: str | None = None) -> LogEvent:
    """Normalize text and infer explicit severity and ISO timestamp metadata."""
    message = line.rstrip("\r\n")
    raw_tokens = message.split()
    level_tokens = message.replace("[", " ").replace("]", " ").replace(":", " ").split()
    level = "UNKNOWN"
    for token in level_tokens:
        candidate = _text_level(token)
        if candidate != "UNKNOWN":
            level = candidate
            break

    timestamp = _leading_text_timestamp(message) or _logfmt_timestamp(raw_tokens)
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
