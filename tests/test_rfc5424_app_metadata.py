from loglens.syslog import parse_rfc5424_line


def test_app_name_is_preserved_as_syslog_metadata() -> None:
    event = parse_rfc5424_line(
        "<34>1 2026-09-19T21:00:00Z host.example authd 4242 LOGIN - login accepted"
    )

    assert event.source == "authd"
    assert event.fields["syslog_app"] == "authd"
    assert event.fields["syslog_hostname"] == "host.example"
    assert event.fields["syslog_procid"] == "4242"
    assert event.fields["syslog_msgid"] == "LOGIN"


def test_nil_app_name_is_not_invented_in_metadata() -> None:
    event = parse_rfc5424_line(
        "<34>1 2026-09-19T21:00:00Z host.example - - - - fallback source"
    )

    assert event.source == "host.example"
    assert "syslog_app" not in event.fields
