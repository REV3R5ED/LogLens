import pytest

from loglens.syslog import parse_rfc5424_line


def _record(version: str) -> str:
    return f"<34>{version} 2026-09-19T12:00:00Z host app 123 ID47 - message"


@pytest.mark.parametrize("version", ["1", "2", "99", "999"])
def test_rfc5424_accepts_canonical_versions(version: str) -> None:
    event = parse_rfc5424_line(_record(version))

    assert event.fields["syslog_version"] == int(version)


@pytest.mark.parametrize("version", ["0", "00", "001", "01", "000"])
def test_rfc5424_rejects_zero_or_leading_zero_versions(version: str) -> None:
    with pytest.raises(ValueError, match="VERSION"):
        parse_rfc5424_line(_record(version))


def test_rfc5424_rejects_version_longer_than_three_digits() -> None:
    with pytest.raises(ValueError, match="header"):
        parse_rfc5424_line(_record("1000"))
