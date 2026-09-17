"""Small, deterministic parsers for common log inputs."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from .model import LogEvent

_LEVELS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "CRITICAL"}
_LEVEL_ALIASES = {
    "WARNING": "WARN", "ERR": "ERROR", "FATAL": "CRITICAL", "CRIT": "CRITICAL",
    "ALERT": "CRITICAL", "EMERG": "CRITICAL", "EMERGENCY": "CRITICAL",
    "INFORMATION": "INFO", "INFORMATIONAL": "INFO",
}


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str): return None
    try: return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError: return None


def _unix_nano_timestamp(value: Any) -> datetime | None:
    """Convert an OpenTelemetry Unix-nanosecond timestamp to UTC safely."""
    if isinstance(value, bool) or not isinstance(value, (str, int)): return None
    try: nanoseconds = int(value)
    except ValueError: return None
    if nanoseconds < 0 or (isinstance(value, str) and str(nanoseconds) != value.strip()): return None
    try: return datetime.fromtimestamp(nanoseconds / 1_000_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError): return None


def _level(value: Any) -> str:
    candidate = str(value).strip().upper()
    return _LEVEL_ALIASES.get(candidate, candidate if candidate in _LEVELS else "UNKNOWN")


def _otel_severity_number(value: Any) -> str:
    """Normalize the OpenTelemetry SeverityNumber ranges to LogLens levels."""
    if isinstance(value, bool) or not isinstance(value, (str, int)): return "UNKNOWN"
    try: number = int(value)
    except ValueError: return "UNKNOWN"
    if isinstance(value, str) and str(number) != value.strip(): return "UNKNOWN"
    if 1 <= number <= 4: return "TRACE"
    if 5 <= number <= 8: return "DEBUG"
    if 9 <= number <= 12: return "INFO"
    if 13 <= number <= 16: return "WARN"
    if 17 <= number <= 20: return "ERROR"
    if 21 <= number <= 24: return "CRITICAL"
    return "UNKNOWN"


def _message(value: Any) -> str:
    """Normalize plain messages and scalar OpenTelemetry AnyValue bodies."""
    if not isinstance(value, dict): return str(value)
    scalar_keys = ("stringValue", "intValue", "doubleValue", "boolValue")
    present = [key for key in scalar_keys if key in value]
    if len(present) == 1:
        scalar = value[present[0]]
        if scalar is None: return ""
        if isinstance(scalar, bool): return "true" if scalar else "false"
        if isinstance(scalar, (str, int, float)): return str(scalar)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _first_present(record: dict[str, Any], keys: tuple[str, ...], default: Any = None) -> Any:
    for key in keys:
        if key in record: return record[key]
    return default


def _nested_present(record: dict[str, Any], path: tuple[str, ...], default: Any = None) -> Any:
    value: Any = record
    for key in path:
        if not isinstance(value, dict) or key not in value: return default
        value = value[key]
    return value


def _source(record: dict[str, Any], fallback: str | None) -> str | None:
    """Return a conservative logical source name, falling back to provenance."""
    value = _first_present(record, ("source", "service", "component", "logger"))
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def parse_json_line(line: str, *, source: str | None = None) -> LogEvent:
    """Parse one JSON object into a normalized event."""
    value = json.loads(line)
    if not isinstance(value, dict): raise ValueError("JSON log record must be an object")
    message = _message(_first_present(value, ("message", "msg", "body"), ""))
    raw_level = _first_present(value, ("level", "severity", "log.level", "severity_text", "severityText"))
    if raw_level is None: raw_level = _nested_present(value, ("log", "level"), None)
    level = _level(raw_level) if raw_level is not None else _otel_severity_number(value.get("severityNumber"))
    timestamp = _timestamp(_first_present(value, ("timestamp", "time", "@timestamp", "ts")))
    if timestamp is None: timestamp = _unix_nano_timestamp(value.get("timeUnixNano"))
    if timestamp is None: timestamp = _timestamp(_first_present(value, ("observed_timestamp", "observedTimestamp")))
    if timestamp is None: timestamp = _unix_nano_timestamp(value.get("observedTimeUnixNano"))
    reserved = {"message", "msg", "body", "level", "severity", "log.level", "severity_text", "severityText", "severityNumber", "timestamp", "time", "@timestamp", "ts", "timeUnixNano", "observed_timestamp", "observedTimestamp", "observedTimeUnixNano", "source", "service", "component", "logger"}
    fields = {key: item for key, item in value.items() if key not in reserved}
    return LogEvent(message=message, level=level, timestamp=timestamp, source=_source(value, source), fields=fields)


def _leading_text_timestamp(message: str) -> datetime | None:
    parts = message.lstrip().split(maxsplit=2)
    if not parts: return None
    first = parts[0].strip("[]")
    if len(parts) >= 2:
        second = parts[1].strip("[]")
        combined = _timestamp(f"{first}T{second}")
        if combined is not None: return combined
    return _timestamp(first)


def _text_level(token: str) -> str:
    candidate = _level(token)
    if candidate != "UNKNOWN": return candidate
    key, separator, value = token.partition("=")
    if separator and key.strip().lower() in {"level", "severity"}: return _level(value.strip("[],'\""))
    return "UNKNOWN"


def _logfmt_timestamp(tokens: list[str]) -> datetime | None:
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator and key.strip().lower() in {"ts", "timestamp", "time"}:
            parsed = _timestamp(value.strip("[],'\""))
            if parsed is not None: return parsed
    return None


def parse_text_line(line: str, *, source: str | None = None) -> LogEvent:
    message = line.rstrip("\r\n")
    raw_tokens = message.split()
    level_tokens = message.replace("[", " ").replace("]", " ").replace(":", " ").split()
    level = "UNKNOWN"
    for token in level_tokens:
        candidate = _text_level(token)
        if candidate != "UNKNOWN": level = candidate; break
    timestamp = _leading_text_timestamp(message) or _logfmt_timestamp(raw_tokens)
    return LogEvent(message=message, level=level, timestamp=timestamp, source=source)


def parse_line(line: str, *, source: str | None = None, format: str = "auto") -> LogEvent:
    if format not in {"auto", "json", "text"}: raise ValueError("format must be one of: auto, json, text")
    if format == "json": return parse_json_line(line, source=source)
    if format == "text": return parse_text_line(line, source=source)
    if line.lstrip().startswith("{"):
        try: return parse_json_line(line, source=source)
        except (json.JSONDecodeError, ValueError): pass
    return parse_text_line(line, source=source)
