import pytest

from loglens.syslog import parse_rfc5424_line


def _record(*, hostname="host", app="app", procid="123", msgid="ID1") -> str:
    return f"<34>1 2026-09-19T12:00:00Z {hostname} {app} {procid} {msgid} - hello"


@pytest.mark.parametrize(
    ("field", "limit"),
    [("hostname", 255), ("app", 48), ("procid", 128), ("msgid", 32)],
)
def test_rfc5424_header_fields_accept_spec_maximum(field: str, limit: int) -> None:
    values = {field: "a" * limit}

    event = parse_rfc5424_line(_record(**values))

    if field == "app":
        assert event.source == "a" * limit
    elif field != "hostname":
        assert event.fields[f"syslog_{field}"] == "a" * limit


@pytest.mark.parametrize(
    ("field", "limit"),
    [("hostname", 255), ("app", 48), ("procid", 128), ("msgid", 32)],
)
def test_rfc5424_header_fields_reject_oversized_values(field: str, limit: int) -> None:
    values = {field: "a" * (limit + 1)}

    with pytest.raises(ValueError, match="exceeds maximum length"):
        parse_rfc5424_line(_record(**values))


@pytest.mark.parametrize("field", ["hostname", "app", "procid", "msgid"])
def test_rfc5424_header_fields_reject_non_ascii_values(field: str) -> None:
    values = {field: "service-☃"}

    with pytest.raises(ValueError, match="printable ASCII only"):
        parse_rfc5424_line(_record(**values))


def test_rfc5424_nilvalue_header_fields_remain_supported() -> None:
    event = parse_rfc5424_line(_record(hostname="-", app="-", procid="-", msgid="-"), source="input.log")

    assert event.source == "input.log"
    assert "syslog_hostname" not in event.fields
    assert "syslog_procid" not in event.fields
    assert "syslog_msgid" not in event.fields
