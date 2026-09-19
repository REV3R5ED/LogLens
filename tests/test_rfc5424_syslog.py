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
    assert event.fields["syslog_priority"] == 165
    assert event.fields["syslog_hostname"] == "edge-1"
    assert event.fields["syslog_procid"] == "4242"
    assert event.fields["syslog_msgid"] == "ID47"


def test_rfc5424_nil_app_falls_back_to_hostname_then_provenance():
    event = parse_rfc5424_line('<14>1 - host-a - - - - hello', source="input.log")
    assert event.source == "host-a"
    assert event.message == "hello"

    event = parse_rfc5424_line('<14>1 - - - - - - hello', source="input.log")
    assert event.source == "input.log"


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
