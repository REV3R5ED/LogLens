from loglens.parsers import parse_json_line


def test_json_source_falls_through_blank_aliases():
    event = parse_json_line(
        '{"source":"  ","service":"api","component":"worker","message":"ready"}',
        source="app.log",
    )
    assert event.source == "api"


def test_json_source_falls_through_non_string_aliases():
    event = parse_json_line(
        '{"source":null,"service":{},"component":"worker","message":"ready"}',
        source="app.log",
    )
    assert event.source == "worker"


def test_json_source_keeps_first_non_blank_alias_precedence():
    event = parse_json_line(
        '{"source":"gateway","service":"api","component":"worker","message":"ready"}',
        source="app.log",
    )
    assert event.source == "gateway"


def test_json_source_falls_back_to_file_provenance_when_aliases_are_blank():
    event = parse_json_line(
        '{"source":"","service":"  ","component":null,"logger":{},"message":"ready"}',
        source="app.log",
    )
    assert event.source == "app.log"
