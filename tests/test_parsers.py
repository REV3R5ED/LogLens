import json

import pytest

from loglens.parsers import parse_json_line, parse_line, parse_text_line


def test_json_parser_normalizes_common_fields():
    event = parse_json_line('{"timestamp":"2026-09-15T10:00:00Z","level":"error","message":"disk full","host":"web-1"}')
    assert event.level == "ERROR"
    assert event.message == "disk full"
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"
    assert event.fields == {"host": "web-1"}


def test_json_parser_supports_aliases():
    event = parse_json_line('{"time":"2026-09-15T10:00:00","severity":"warn","msg":"slow response"}')
    assert event.level == "WARN"
    assert event.message == "slow response"


def test_json_parser_canonicalizes_common_severity_aliases():
    aliases = {
        "warning": "WARN",
        "err": "ERROR",
        "fatal": "CRITICAL",
        "crit": "CRITICAL",
        "alert": "CRITICAL",
        "emerg": "CRITICAL",
        "emergency": "CRITICAL",
        "information": "INFO",
        "informational": "INFO",
    }
    for raw, expected in aliases.items():
        assert parse_json_line(json.dumps({"level": raw, "message": "event"})).level == expected


def test_json_parser_trims_severity_whitespace():
    assert parse_json_line('{"level":"  warning  ","message":"slow"}').level == "WARN"


def test_json_parser_rejects_non_object():
    with pytest.raises(ValueError):
        parse_json_line('["not", "an", "event"]')


def test_text_parser_detects_explicit_level():
    event = parse_text_line("2026-09-15 [ERROR] database unavailable\n")
    assert event.level == "ERROR"
    assert event.message.endswith("database unavailable")


def test_text_parser_canonicalizes_common_severity_aliases():
    assert parse_text_line("WARNING response degraded").level == "WARN"
    assert parse_text_line("ERR request failed").level == "ERROR"
    assert parse_text_line("CRIT database unavailable").level == "CRITICAL"
    assert parse_text_line("EMERG service unavailable").level == "CRITICAL"
    assert parse_text_line("INFORMATIONAL service ready").level == "INFO"


def test_text_parser_parses_leading_iso_timestamp():
    event = parse_text_line("2026-09-15T10:00:00Z ERROR database unavailable")
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"


def test_text_parser_preserves_time_in_split_iso_timestamp():
    event = parse_text_line("2026-09-15 10:00:00 ERROR database unavailable")
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00"


def test_text_parser_preserves_offset_in_split_iso_timestamp():
    event = parse_text_line("2026-09-15 10:00:00+00:00 WARN slow response")
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"


def test_text_parser_parses_bracketed_iso_timestamp():
    event = parse_text_line("[2026-09-15T10:00:00Z] ERROR database unavailable")
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"


def test_text_parser_parses_bracketed_split_iso_timestamp():
    event = parse_text_line("[2026-09-15 10:00:00+00:00] WARN slow response")
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"


def test_text_parser_does_not_guess_embedded_timestamp():
    event = parse_text_line("INFO maintenance begins at 2026-09-15T10:00:00Z")
    assert event.timestamp is None


def test_auto_parser_falls_back_to_text_for_malformed_json():
    event = parse_line("{broken json ERROR", format="auto")
    assert event.level == "ERROR"


def test_event_is_json_serializable():
    event = parse_json_line('{"level":"info","message":"ready"}')
    json.dumps(event.to_dict())
