import json

import pytest

from loglens.parsers import parse_json_line


@pytest.mark.parametrize(
    ("number", "expected"),
    [(1, "TRACE"), (4, "TRACE"), (5, "DEBUG"), (8, "DEBUG"), (9, "INFO"), (12, "INFO"),
     (13, "WARN"), (16, "WARN"), (17, "ERROR"), (20, "ERROR"), (21, "CRITICAL"), (24, "CRITICAL")],
)
def test_opentelemetry_severity_number_ranges(number, expected):
    event = parse_json_line(json.dumps({"severityNumber": number, "body": "event"}))
    assert event.level == expected
    assert "severityNumber" not in event.fields


def test_opentelemetry_severity_number_accepts_decimal_string():
    assert parse_json_line('{"severityNumber":"17","body":"failed"}').level == "ERROR"


@pytest.mark.parametrize("value", [0, 25, -1, True, 17.0, "17.0", "invalid"])
def test_opentelemetry_invalid_severity_number_is_unknown(value):
    event = parse_json_line(json.dumps({"severityNumber": value, "body": "event"}))
    assert event.level == "UNKNOWN"


def test_text_severity_takes_precedence_over_severity_number():
    event = parse_json_line('{"severityText":"warning","severityNumber":17,"body":"event"}')
    assert event.level == "WARN"


def test_canonical_level_takes_precedence_over_severity_number():
    event = parse_json_line('{"level":"info","severityNumber":21,"message":"event"}')
    assert event.level == "INFO"
