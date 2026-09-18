from datetime import datetime, timezone

from loglens.parsers import parse_json_line


def test_journald_json_normalizes_core_fields():
    event = parse_json_line(
        '{"MESSAGE":"disk pressure","PRIORITY":"3","__REALTIME_TIMESTAMP":"1789768800123456","_SYSTEMD_UNIT":"api.service","_HOSTNAME":"web-1"}',
        source="journal.jsonl",
    )

    assert event.message == "disk pressure"
    assert event.level == "ERROR"
    assert event.timestamp == datetime(2026, 9, 18, 22, 0, 0, 123456, tzinfo=timezone.utc)
    assert event.source == "api.service"
    assert event.fields["_HOSTNAME"] == "web-1"


def test_explicit_normalized_fields_keep_precedence_over_journald_aliases():
    event = parse_json_line(
        '{"message":"canonical","MESSAGE":"journal","level":"WARN","PRIORITY":"3","timestamp":"2026-09-18T20:00:00Z","__REALTIME_TIMESTAMP":"1789768800123456","source":"gateway","_SYSTEMD_UNIT":"api.service"}',
        source="journal.jsonl",
    )

    assert event.message == "canonical"
    assert event.level == "WARN"
    assert event.timestamp == datetime(2026, 9, 18, 20, 0, tzinfo=timezone.utc)
    assert event.source == "gateway"


def test_journald_source_falls_back_to_identifier_then_command():
    identifier = parse_json_line('{"MESSAGE":"x","SYSLOG_IDENTIFIER":"sshd","_COMM":"fallback"}')
    command = parse_json_line('{"MESSAGE":"x","SYSLOG_IDENTIFIER":" ","_COMM":"systemd"}')

    assert identifier.source == "sshd"
    assert command.source == "systemd"


def test_invalid_journald_priority_and_timestamp_are_not_guessed():
    event = parse_json_line(
        '{"MESSAGE":"x","PRIORITY":"8","__REALTIME_TIMESTAMP":"not-a-number"}',
        source="journal.jsonl",
    )

    assert event.level == "UNKNOWN"
    assert event.timestamp is None
    assert event.source == "journal.jsonl"
