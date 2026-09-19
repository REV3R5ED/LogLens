import pytest

from loglens.syslog import parse_rfc5424_line


PREFIX = "<34>1 2026-09-19T16:00:00Z host app 123 ID47 "


def test_accepts_valid_structured_data_identifier_and_multiple_elements():
    event = parse_rfc5424_line(
        PREFIX + '[exampleSDID@32473 iut="3"][origin ip="192.0.2.1"] message'
    )

    assert event.message == "message"


@pytest.mark.parametrize(
    "structured_data",
    [
        "[]",
        "[ bad]",
        "[bad=id]",
        "[bad]id]",
        '[bad"id]',
        "[é]",
        f"[{'a' * 33}]",
        "[[nested]]",
    ],
)
def test_rejects_invalid_structured_data_identifiers(structured_data):
    with pytest.raises(ValueError):
        parse_rfc5424_line(PREFIX + structured_data)


def test_accepts_maximum_length_structured_data_identifier():
    event = parse_rfc5424_line(PREFIX + f"[{'a' * 32}] message")

    assert event.message == "message"
