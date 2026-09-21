"""Small, deterministic parsers for common log inputs."""

from __future__ import annotations

import json
import unicodedata
from datetime import datetime, timezone
from typing import Any

from .model import LogEvent

_LEVELS = {"TRACE", "DEBUG", "INFO", "NOTICE", "WARN", "ERROR", "CRITICAL"}
_LEVEL_ALIASES = {
    "WARNING": "WARN", "ERR": "ERROR", "FATAL": "CRITICAL", "CRIT": "CRITICAL",
    "ALERT": "CRITICAL", "EMERG": "CRITICAL", "EMERGENCY": "CRITICAL",
    "INFORMATION": "INFO", "INFORMATIONAL": "INFO",
}
_JOURNAL_PRIORITY_LEVELS = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR",
    4: "WARN", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
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


def _unix_micro_timestamp(value: Any) -> datetime | None:
    """Convert systemd journal microseconds-since-epoch to UTC safely."""
    if isinstance(value, bool) or not isinstance(value, (str, int)): return None
    try: microseconds = int(value)
    except ValueError: return None
    if microseconds < 0 or (isinstance(value, str) and str(microseconds) != value.strip()): return None
    try: return datetime.fromtimestamp(microseconds / 1_000_000, tz=timezone.utc)
    except (OverflowError, OSError, ValueError): return None


def _level(value: Any) -> str:
    candidate = unicodedata.normalize("NFKC", str(value)).strip().upper()
    return _LEVEL_ALIASES.get(candidate, candidate if candidate in _LEVELS else "UNKNOWN")


def _journal_priority(value: Any) -> str:
    """Normalize syslog PRIORITY values used by journalctl JSON output."""
    if isinstance(value, bool) or not isinstance(value, (str, int)): return "UNKNOWN"
    try: priority = int(value)
    except ValueError: return "UNKNOWN"
    if isinstance(value, str) and str(priority) != value.strip(): return "UNKNOWN"
    return _JOURNAL_PRIORITY_LEVELS.get(priority, "UNKNOWN")


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


def _otel_anyvalue(value: Any) -> Any:
    """Decode an unambiguous OpenTelemetry JSON AnyValue recursively."""
    if not isinstance(value, dict): return value
    keys = ("stringValue", "intValue", "doubleValue", "boolValue", "bytesValue", "arrayValue", "kvlistValue")
    present = [key for key in keys if key in value]
    if len(present) != 1: return value
    key = present[0]
    item = value[key]
    if key in {"stringValue", "intValue", "doubleValue", "boolValue", "bytesValue"}: return item
    if key == "arrayValue" and isinstance(item, dict) and isinstance(item.get("values"), list):
        return [_otel_anyvalue(entry) for entry in item["values"]]
    if key == "kvlistValue" and isinstance(item, dict) and isinstance(item.get("values"), list):
        decoded: dict[str, Any] = {}
        for entry in item["values"]:
            if not isinstance(entry, dict) or not isinstance(entry.get("key"), str) or "value" not in entry: return value
            if entry["key"] in decoded: return value
            decoded[entry["key"]] = _otel_anyvalue(entry["value"])
        return decoded
    return value


def _message(value: Any) -> str:
    """Normalize plain messages and OpenTelemetry AnyValue bodies."""
    decoded = _otel_anyvalue(value)
    if decoded is not value:
        if decoded is None: return ""
        if isinstance(decoded, bool): return "true" if decoded else "false"
        if isinstance(decoded, (str, int, float)): return str(decoded)
        return json.dumps(decoded, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    if not isinstance(value, dict): return str(value)
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


def _otel_resource_service_name(record: dict[str, Any]) -> str | None:
    """Read service.name from an OTLP JSON resource attribute list."""
    attributes = _nested_present(record, ("resource", "attributes"), [])
    if not isinstance(attributes, list): return None
    for attribute in attributes:
        if not isinstance(attribute, dict) or attribute.get("key") != "service.name": continue
        value = attribute.get("value")
        if isinstance(value, dict): value = value.get("stringValue")
        if isinstance(value, str) and value.strip(): return value.strip()
    return None


def _source(record: dict[str, Any], fallback: str | None) -> str | None:
    """Return the first non-blank logical source name, falling back to provenance."""
    for key in ("source", "service", "component", "logger"):
        value = record.get(key)
        if isinstance(value, str) and value.strip(): return value.strip()
    value = record.get("service.name")
    if isinstance(value, str) and value.strip(): return value.strip()
    value = _nested_present(record, ("service", "name"), None)
    if isinstance(value, str) and value.strip(): return value.strip()
    value = _otel_resource_service_name(record)
    if value is not None: return value
    for key in ("_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER", "_COMM"):
        value = record.get(key)
        if isinstance(value, str) and value.strip(): return value.strip()
    return fallback


def parse_json_line(line: str, *, source: str | None = None) -> LogEvent:
    """Parse one JSON object into a normalized event."""
    value = json.loads(line)
    if not isinstance(value, dict): raise ValueError("JSON log record must be an object")
    message = _message(_first_present(value, ("message", "msg", "body", "MESSAGE"), ""))
    raw_level = _first_present(value, ("level", "severity", "log.level", "severity_text", "severityText"))
    if raw_level is None: raw_level = _nested_present(value, ("log", "level"), None)
    if raw_level is not None:
        level = _level(raw_level)
    elif "severityNumber" in value:
        level = _otel_severity_number(value.get("severityNumber"))
    else:
        level = _journal_priority(value.get("PRIORITY"))
    timestamp = _timestamp(_first_present(value, ("timestamp", "time", "@timestamp", "ts")))
    if timestamp is None: timestamp = _unix_nano_timestamp(value.get("timeUnixNano"))
    if timestamp is None: timestamp = _timestamp(_first_present(value, ("observed_timestamp", "observedTimestamp")))
    if timestamp is None: timestamp = _unix_nano_timestamp(value.get("observedTimeUnixNano"))
    if timestamp is None: timestamp = _unix_micro_timestamp(value.get("__REALTIME_TIMESTAMP"))
    reserved = {"message", "msg", "body", "MESSAGE", "level", "severity", "log.level", "severity_text", "severityText", "severityNumber", "PRIORITY", "timestamp", "time", "@timestamp", "ts", "timeUnixNano", "observed_timestamp", "observedTimestamp", "observedTimeUnixNano", "__REALTIME_TIMESTAMP", "source", "service", "component", "logger"}
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


def _logfmt_source(tokens: list[str]) -> str | None:
    """Read a conservative logical source from common logfmt keys."""
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator and key.strip().lower() in {"source", "service", "component", "logger"}:
            candidate = value.strip("[],'\"").strip()
            if candidate: return candidate
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
    logical_source = _logfmt_source(raw_tokens) or source
    return LogEvent(message=message, level=level, timestamp=timestamp, source=logical_source)


def parse_line(line: str, *, source: str | None = None, format: str = "auto") -> LogEvent:
    if format not in {"auto", "json", "text"}: raise ValueError("format must be one of: auto, json, text")
    if format == "json": return parse_json_line(line, source=source)
    if format == "text": return parse_text_line(line, source=source)
    if line.lstrip().startswith("{"):
        try: return parse_json_line(line, source=source)
        except (json.JSONDecodeError, ValueError): pass
    return parse_text_line(line, source=source)
