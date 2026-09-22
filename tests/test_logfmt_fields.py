from loglens.parsers import parse_text_line


def test_text_parser_preserves_non_reserved_logfmt_fields():
    event = parse_text_line(
        'ts=2026-09-15T10:00:00Z level=error service=api request_id=req-42 status=503 msg="upstream timeout"'
    )

    assert event.level == "ERROR"
    assert event.source == "api"
    assert event.fields == {
        "request_id": "req-42",
        "status": "503",
        "msg": "upstream timeout",
    }


def test_text_parser_excludes_normalized_metadata_from_fields():
    event = parse_text_line(
        "timestamp=2026-09-15T10:00:00Z severity=warn component=worker trace_id=abc123"
    )

    assert event.fields == {"trace_id": "abc123"}


def test_text_parser_keeps_first_duplicate_logfmt_field_deterministically():
    event = parse_text_line("level=info service=api request_id=first request_id=second")

    assert event.fields == {"request_id": "first"}


def test_text_parser_does_not_invent_fields_from_plain_text():
    event = parse_text_line("INFO request completed normally")

    assert event.fields == {}
