from loglens.parsers import parse_json_line, parse_text_line


def test_json_parser_normalizes_unicode_compatibility_severity_labels():
    cases = {
        "ＥＲＲＯＲ": "ERROR",
        "ＷＡＲＮＩＮＧ": "WARN",
        "ＦＡＴＡＬ": "CRITICAL",
        "ＩＮＦＯ": "INFO",
    }
    for raw, expected in cases.items():
        event = parse_json_line(f'{{"level":"{raw}","message":"event"}}')
        assert event.level == expected


def test_text_parser_normalizes_unicode_compatibility_severity_labels():
    assert parse_text_line("ＥＲＲＯＲ database unavailable").level == "ERROR"
    assert parse_text_line("level=ＷＡＲＮＩＮＧ msg=slow").level == "WARN"
    assert parse_text_line("severity=ＦＡＴＡＬ service=db").level == "CRITICAL"
