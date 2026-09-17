"""Regression coverage for nested Elastic Common Schema fields."""

from loglens.parsers import parse_json_line


def test_json_parser_supports_nested_ecs_log_level():
    event = parse_json_line(
        '{"@timestamp":"2026-09-15T10:00:00Z","log":{"level":"warning","logger":"api"},"message":"slow response"}'
    )

    assert event.level == "WARN"
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"
    assert event.fields == {"log": {"level": "warning", "logger": "api"}}


def test_flat_ecs_log_level_precedes_nested_alias():
    event = parse_json_line(
        '{"log.level":"error","log":{"level":"info"},"message":"request failed"}'
    )

    assert event.level == "ERROR"


def test_canonical_level_precedes_flat_and_nested_ecs_aliases():
    event = parse_json_line(
        '{"level":"critical","log.level":"error","log":{"level":"info"},"message":"database unavailable"}'
    )

    assert event.level == "CRITICAL"


def test_non_mapping_log_field_does_not_break_json_parsing():
    event = parse_json_line('{"log":"application.log","message":"ready"}')

    assert event.level == "UNKNOWN"
    assert event.fields == {"log": "application.log"}
