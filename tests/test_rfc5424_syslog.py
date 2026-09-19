from datetime import timezone

import pytest

from loglens.syslog import parse_rfc5424_line


def test_rfc5424_normalizes_header_severity_source_and_message():
    event = parse_rfc5424_line(
        '<165>1 2026-09-19T04:10:11Z edge-1 payments 4242 ID47 '
        '[meta trace="abc\\]123"] payment completed'
    )

    assert event.level == "NOTICE"
    assert event.source == "payments"
    assert event.message == "payment completed"
    assert event.timestamp is not None
    assert event.timestamp.tzinfo == timezone.utc
    assert event.fields["syslog_facility"] == 20
    assert event.fields["syslog_severity"] == 5
    assert event.fields["syslog_priority"] == 165
    assert event.fields["syslog_hostname"] == "edge-1"
    assert event.fields["syslog_procid"] == "4242"
    assert event.fields["syslog_msgid"] == "ID47"


@pytest.mark.parametrize(
    ("pri", "severity", "level"),
    [
        (0, 0, "CRITICAL"),
        (3, 3, "ERROR"),
        (4, 4, "WARN"),
        (5, 5, "NOTICE"),
        (6, 6, "INFO"),
        (7, 7, "DEBUG"),
        (191, 7, "DEBUG"),
    ],
)
def test_rfc5424_preserves_numeric_severity_independently_of_normalized_level(
    pri, severity, level
):
    event = parse_rfc5424_line(
        f'<{pri}>1 2026-09-19T04:10:11Z host app - - - message'
    )

    assert event.fields["syslog_severity"] == severity
    assert event.level == level


def test_rfc5424_nil_app_falls_back_to_hostname_then_provenance():
    event = parse_rfc5424_line('<14>1 - host-a - - - - hello', source="input.log")
    assert event.source == "host-a"
    assert event.message == "hello"

    event = parse_rfc5424_line('<14>1 - - - - - - hello', source="input.log")
    assert event.source == "input.log"


def test_rfc5424_allows_structured_data_without_message():
    event = parse_rfc5424_line(
        '<14>1 2026-09-19T04:10:11Z host app - - [meta trace="abc"]'
    )
    assert event.message == ""


@pytest.mark.parametrize(
    "body",
    [
        '-message',
        '[meta trace="abc"]message',
    ],
)
def test_rfc5424_requires_space_before_message(body):
    line = f'<14>1 2026-09-19T04:10:11Z host app - - {body}'
    with pytest.raises(ValueError, match="separated"):
        parse_rfc5424_line(line)


@pytest.mark.parametrize(
    "line",
    [
        '<999>1 2026-09-19T04:10:11Z host app - - - message',
        '<14>0 2026-09-19T04:10:11Z host app - - - message',
        '<14>1 not-a-time host app - - - message',
        '<14>1 2026-09-19T04:10:11Z host app - - [broken message',
    ],
)
def test_rfc5424_rejects_malformed_records(line):
    with pytest.raises(ValueError):
        parse_rfc5424_line(line)
