import pytest

from loglens.parsers import parse_json_line


@pytest.mark.parametrize("field", ["source", "service", "component", "logger"])
def test_json_source_aliases_override_file_provenance(field):
    event = parse_json_line(
        f'{{"level":"INFO","message":"ok","{field}":" api "}}',
        source="events.jsonl",
    )
    assert event.source == "api"
    assert field not in event.fields


def test_invalid_json_source_falls_back_to_file_provenance():
    event = parse_json_line(
        '{"level":"INFO","message":"ok","source":{"name":"api"}}',
        source="events.jsonl",
    )
    assert event.source == "events.jsonl"
