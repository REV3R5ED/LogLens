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
    r"^<(?P<pri>[0-9]{1,3})>(?P<version>[0-9]{1,3}) "
    r"(?P<timestamp>\S+) (?P<hostname>\S+) (?P<app>\S+) "
    r"(?P<procid>\S+) (?P<msgid>\S+) (?P<body>.*)$"
)
_RFC5424_TIMESTAMP = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?"
    r"(?:Z|[+-][0-9]{2}:[0-9]{2})$"
)
_RFC5424_VERSION = re.compile(r"^[1-9][0-9]{0,2}$")
_HEADER_LIMITS = {
    "hostname": 255,
    "app": 48,
    "procid": 128,
    "msgid": 32,
}
_SD_NAME_FORBIDDEN = {' ', '=', ']', '"'}
_UTF8_BOM = "\ufeff"


def _valid_sd_name(value: str) -> bool:
    """Return whether a structured-data name satisfies RFC 5424 SD-NAME."""
    return (
        1 <= len(value) <= 32
        and all(33 <= ord(char) <= 126 and char not in _SD_NAME_FORBIDDEN for char in value)
    )


def _valid_sd_element(element: str) -> bool:
    """Validate one RFC5424 SD-ELEMENT, including PARAM framing and escaping."""
    sd_id, separator, params = element.partition(" ")
    if not _valid_sd_name(sd_id):
        return False
    if not separator:
        return True

    position = 0
    while position < len(params):
        equals = params.find("=", position)
        if equals < 0:
            return False
        name = params[position:equals]
        if not _valid_sd_name(name):
            return False
        value_start = equals + 1
        if value_start >= len(params) or params[value_start] != '"':
            return False

        position = value_start + 1
        while position < len(params):
            char = params[position]
            if char == "\\":
                position += 1
                if position >= len(params) or params[position] not in {'"', "\\", "]"}:
                    return False
            elif char == '"':
                position += 1
                if position == len(params):
                    return True
                if params[position] != " ":
                    return False
                position += 1
                break
            elif char == "]":
                return False
            position += 1
        else:
            return False

    return False


def _structured_data_end(body: str) -> int | None:
    """Return the end of RFC5424 STRUCTURED-DATA without trusting delimiters in quotes."""
    if body.startswith("-"):
        return 1
    if not body.startswith("["):
        return None
    quoted = escaped = False
    depth = 0
    element_start = 0
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
            if depth != 0:
                return None
            depth = 1
            element_start = index + 1
        elif char == "]":
            if depth != 1:
                return None
            element = body[element_start:index]
            if not _valid_sd_element(element):
                return None
            depth = 0
            if index + 1 == len(body) or body[index + 1] != "[":
                return index + 1
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
    severity = pri % 8

    version_text = match.group("version")
    if _RFC5424_VERSION.fullmatch(version_text) is None:
        raise ValueError("RFC5424 VERSION must be 1-999 without leading zeros")
    version = int(version_text)

    timestamp_text = match.group("timestamp")
    timestamp = _parse_timestamp(timestamp_text)
    for name in _HEADER_LIMITS:
        _validate_header_field(name, match.group(name))

    body = match.group("body")
    sd_end = _structured_data_end(body)
    if sd_end is None:
        raise ValueError("invalid RFC5424 structured data")
    structured_data = body[:sd_end]
    remainder = body[sd_end:]
    if remainder and not remainder.startswith(" "):
        raise ValueError("RFC5424 message must be separated from structured data by a space")
    message = remainder[1:] if remainder else ""
    has_utf8_bom = message.startswith(_UTF8_BOM)
    if has_utf8_bom:
        message = message[len(_UTF8_BOM):]

    app = match.group("app")
    hostname = match.group("hostname")
    logical_source = app if app != "-" else (hostname if hostname != "-" else source)
    fields = {
        "syslog_facility": pri // 8,
        "syslog_severity": severity,
        "syslog_priority": pri,
        "syslog_version": version,
    }
    if timestamp_text != "-":
        fields["syslog_timestamp"] = timestamp_text
    if has_utf8_bom:
        fields["syslog_utf8_bom"] = True
    if structured_data != "-":
        fields["syslog_structured_data"] = structured_data
    for key in ("hostname", "app", "procid", "msgid"):
        value = match.group(key)
        if value != "-":
            fields[f"syslog_{key}"] = value

    return LogEvent(
        message=message,
        level=_PRI_LEVELS[severity],
        timestamp=timestamp,
        source=logical_source,
        fields=fields,
    )
