from loglens.syslog import parse_rfc5424_line


def test_rfc5424_exposes_human_readable_facility_and_severity_names():
    event = parse_rfc5424_line(
        '<165>1 2026-09-19T04:10:11Z edge-1 payments 4242 ID47 - payment completed'
    )

    assert event.fields["syslog_facility"] == 20
    assert event.fields["syslog_facility_name"] == "local4"
    assert event.fields["syslog_severity"] == 5
    assert event.fields["syslog_severity_name"] == "notice"


def test_rfc5424_priority_name_boundaries_cover_standard_facilities():
    kernel_emergency = parse_rfc5424_line('<0>1 - host app - - - panic')
    local7_debug = parse_rfc5424_line('<191>1 - host app - - - trace')

    assert kernel_emergency.fields["syslog_facility_name"] == "kernel"
    assert kernel_emergency.fields["syslog_severity_name"] == "emergency"
    assert local7_debug.fields["syslog_facility_name"] == "local7"
    assert local7_debug.fields["syslog_severity_name"] == "debug"
