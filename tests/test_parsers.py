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


def test_json_parser_rejects_non_object():
    with pytest.raises(ValueError):
        parse_json_line('["not", "an", "event"]')


def test_text_parser_detects_explicit_level():
    event = parse_text_line("2026-09-15 [ERROR] database unavailable\n")
    assert event.level == "ERROR"
    assert event.message.endswith("database unavailable")


def test_auto_parser_falls_back_to_text_for_malformed_json():
    event = parse_line("{broken json ERROR", format="auto")
    assert event.level == "ERROR"


def test_event_is_json_serializable():
    event = parse_json_line('{"level":"info","message":"ready"}')
    json.dumps(event.to_dict())
