from datetime import timedelta

import pytest

from loglens.syslog import parse_rfc5424_line


def _line(timestamp: str) -> str:
    return f"<34>1 {timestamp} host app 123 ID47 - message"


def test_rfc5424_timestamp_accepts_timezone_and_microseconds():
    timestamp = "2026-09-19T08:12:34.123456-07:00"
    event = parse_rfc5424_line(_line(timestamp))

    assert event.timestamp is not None
    assert event.timestamp.microsecond == 123456
    assert event.timestamp.utcoffset() == timedelta(hours=-7)
    assert event.fields["syslog_timestamp"] == timestamp


@pytest.mark.parametrize(
    "timestamp",
    [
        "2026-09-19",
        "2026-09-19T08:12:34",
        "2026-09-19T08:12:34.1234567Z",
        "2026-09-19 08:12:34Z",
        "2026-09-19T25:12:34Z",
    ],
)
def test_rfc5424_timestamp_rejects_nonconforming_values(timestamp):
    with pytest.raises(ValueError, match="invalid RFC5424 timestamp"):
        parse_rfc5424_line(_line(timestamp))


def test_rfc5424_nil_timestamp_remains_supported():
    event = parse_rfc5424_line(_line("-"))

    assert event.timestamp is None
    assert "syslog_timestamp" not in event.fields


def test_rfc5424_timestamp_preserves_original_utc_designator():
    timestamp = "2026-09-19T15:12:34Z"
    event = parse_rfc5424_line(_line(timestamp))

    assert event.timestamp is not None
    assert event.fields["syslog_timestamp"] == timestamp
