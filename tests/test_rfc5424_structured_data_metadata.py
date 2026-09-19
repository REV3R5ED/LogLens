from loglens.syslog import parse_rfc5424_line


def test_structured_data_is_preserved_for_defensive_analysis():
    event = parse_rfc5424_line(
        '<34>1 2026-09-19T20:00:00Z host app 123 ID47 '
        '[exampleSDID@32473 eventSource="Application" eventID="1011"] message'
    )

    assert event.fields["syslog_structured_data"] == (
        '[exampleSDID@32473 eventSource="Application" eventID="1011"]'
    )


def test_multiple_structured_data_elements_are_preserved_exactly():
    structured_data = '[meta sequence="7"][trace trace_id="abc\\]123"]'
    event = parse_rfc5424_line(
        f'<165>1 2026-09-19T20:00:00+00:00 host app - - {structured_data} payload'
    )

    assert event.fields["syslog_structured_data"] == structured_data


def test_nil_structured_data_is_not_added_to_metadata():
    event = parse_rfc5424_line(
        '<34>1 2026-09-19T20:00:00Z host app - - - message'
    )

    assert "syslog_structured_data" not in event.fields
