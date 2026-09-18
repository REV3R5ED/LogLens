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


def test_array_otel_body_becomes_compact_json():
    body = {"arrayValue": {"values": [{"stringValue": "timeout"}, {"intValue": "3"}]}}

    event = parse_json_line(json.dumps({"body": body}))

    assert event.message == '["timeout","3"]'


def test_kvlist_otel_body_becomes_compact_json_object():
    body = {
        "kvlistValue": {
            "values": [
                {"key": "reason", "value": {"stringValue": "timeout"}},
                {"key": "attempt", "value": {"intValue": "3"}},
            ]
        }
    }

    event = parse_json_line(json.dumps({"body": body}))

    assert event.message == '{"attempt":"3","reason":"timeout"}'


def test_malformed_composite_otel_body_preserves_raw_shape():
    body = {"kvlistValue": {"values": [{"value": {"stringValue": "timeout"}}]}}

    event = parse_json_line(json.dumps({"body": body}))

    assert event.message == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_ambiguous_anyvalue_body_is_not_guessed():
    body = {"stringValue": "one", "intValue": "2"}

    event = parse_json_line(json.dumps({"body": body}))

    assert event.message == '{"intValue":"2","stringValue":"one"}'
