"""Defensive parsing helpers for RFC 5424 syslog records."""

from __future__ import annotations

import re
from datetime import datetime

from .model import LogEvent

_PRI_LEVELS = {
    0: "CRITICAL", 1: "CRITICAL", 2: "CRITICAL", 3: "ERROR",
    4: "WARN", 5: "NOTICE", 6: "INFO", 7: "DEBUG",
}
_HEADER = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d{1,3}) "
    r"(?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<body>.*)$"
)
_RFC5424_TIMESTAMP = re.compile(
    r"^\d{4}-\d{2}-\d{2}T"
    r"\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)
_HEADER_LIMITS = {
    "hostname": 255,
    "app": 48,
    "procid": 128,
    "msgid": 32,
}


def _structured_data_end(body: str) -> int | None:
    """Return the end of RFC5424 STRUCTURED-DATA without trusting delimiters in quotes."""
    if body.startswith("-"):
        return 1
    if not body.startswith("["):
        return None
    quoted = escaped = False
    depth = 0
    for index, char in enumerate(body):
        if escaped:
            escaped = False
            continue
        if quoted and char == "\\":
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0 and (index + 1 == len(body) or body[index + 1] != "["):
                return index + 1
        if depth < 0:
            return None
    return None


def _parse_timestamp(value: str) -> datetime | None:
    """Parse an RFC5424 TIMESTAMP, rejecting permissive ISO-8601 variants."""
    if value == "-":
        return None
    if _RFC5424_TIMESTAMP.fullmatch(value) is None:
        raise ValueError("invalid RFC5424 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid RFC5424 timestamp") from exc
    if parsed.utcoffset() is None:
        raise ValueError("invalid RFC5424 timestamp")
    return parsed


def _validate_header_field(name: str, value: str) -> None:
    """Enforce RFC5424 PRINTUSASCII and field-length limits."""
    if value == "-":
        return
    if len(value) > _HEADER_LIMITS[name]:
        raise ValueError(f"RFC5424 {name.upper()} exceeds maximum length")
    if any(ord(char) < 33 or ord(char) > 126 for char in value):
        raise ValueError(f"RFC5424 {name.upper()} must contain printable ASCII only")


def parse_rfc5424_line(line: str, *, source: str | None = None) -> LogEvent:
    """Parse one RFC5424 syslog record into a normalized LogEvent.

    The parser is deliberately strict about PRI, version, timestamp and
    structured-data framing so malformed input fails closed instead of being
    assigned misleading severity or provenance.
    """
    raw = line.rstrip("\r\n")
    match = _HEADER.match(raw)
    if match is None:
        raise ValueError("invalid RFC5424 syslog header")

    pri = int(match.group("pri"))
    if not 0 <= pri <= 191:
        raise ValueError("RFC5424 PRI must be between 0 and 191")
    if int(match.group("version")) < 1:
        raise ValueError("RFC5424 VERSION must be positive")

    timestamp = _parse_timestamp(match.group("timestamp"))
    for name in _HEADER_LIMITS:
        _validate_header_field(name, match.group(name))

    body = match.group("body")
    sd_end = _structured_data_end(body)
    if sd_end is None:
        raise ValueError("invalid RFC5424 structured data")
    message = body[sd_end:]
    if message.startswith(" "):
        message = message[1:]

    app = match.group("app")
    hostname = match.group("hostname")
    logical_source = app if app != "-" else (hostname if hostname != "-" else source)
    fields = {
        "syslog_facility": pri // 8,
        "syslog_priority": pri,
        "syslog_version": int(match.group("version")),
    }
    for key in ("hostname", "procid", "msgid"):
        value = match.group(key)
        if value != "-":
            fields[f"syslog_{key}"] = value

    return LogEvent(
        message=message,
        level=_PRI_LEVELS[pri % 8],
        timestamp=timestamp,
        source=logical_source,
        fields=fields,
    )
