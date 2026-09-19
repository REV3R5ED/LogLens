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

    timestamp_text = match.group("timestamp")
    timestamp = None
    if timestamp_text != "-":
        try:
            timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid RFC5424 timestamp") from exc

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
