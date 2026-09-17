import json

import pytest

from loglens.parsers import parse_json_line


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"stringValue": "database unavailable"}, "database unavailable"),
        ({"intValue": "42"}, "42"),
        ({"doubleValue": 3.5}, "3.5"),
        ({"boolValue": True}, "true"),
        ({"boolValue": False}, "false"),
    ],
)
def test_normalizes_scalar_otel_anyvalue_body(body, expected):
    event = parse_json_line(json.dumps({"body": body, "severityNumber": 17}))

    assert event.message == expected
    assert event.level == "ERROR"


def test_structured_otel_body_falls_back_to_deterministic_json():
    body = {"kvlistValue": {"values": [{"value": {"stringValue": "timeout"}, "key": "reason"}]}}

    event = parse_json_line(json.dumps({"body": body}))

    assert event.message == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_ambiguous_anyvalue_body_is_not_guessed():
    body = {"stringValue": "one", "intValue": "2"}

    event = parse_json_line(json.dumps({"body": body}))

    assert event.message == '{"intValue":"2","stringValue":"one"}'
