from loglens.parsers import parse_json_line


def test_json_parser_supports_opentelemetry_time_unix_nano_string():
    event = parse_json_line(
        '{"timeUnixNano":"1789466400000000000","severityText":"info","body":"received"}'
    )
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"
    assert "timeUnixNano" not in event.fields


def test_json_parser_supports_opentelemetry_observed_time_unix_nano_integer():
    event = parse_json_line(
        '{"observedTimeUnixNano":1789466400000000000,"severityText":"info","body":"received"}'
    )
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"
    assert "observedTimeUnixNano" not in event.fields


def test_json_parser_prefers_event_time_over_observed_time():
    event = parse_json_line(
        '{"timeUnixNano":"1789466400000000000","observedTimeUnixNano":"1789552800000000000","body":"event"}'
    )
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"


def test_json_parser_prefers_canonical_iso_timestamp_over_unix_nano():
    event = parse_json_line(
        '{"timestamp":"2026-09-14T10:00:00Z","timeUnixNano":"1789466400000000000","body":"event"}'
    )
    assert event.timestamp is not None
    assert event.timestamp.isoformat() == "2026-09-14T10:00:00+00:00"


def test_json_parser_ignores_invalid_unix_nano_values():
    for value in ('"not-a-number"', '"1.5"', '-1', 'true', '1.5'):
        event = parse_json_line(
            f'{{"timeUnixNano":{value},"observedTimestamp":"2026-09-15T10:00:00Z","body":"event"}}'
        )
        assert event.timestamp is not None
        assert event.timestamp.isoformat() == "2026-09-15T10:00:00+00:00"
