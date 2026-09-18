"""Regression coverage for structured service identity as event source."""

from loglens.parsers import parse_json_line


def test_nested_ecs_service_name_becomes_source():
    event = parse_json_line(
        '{"service":{"name":"checkout"},"level":"ERROR","message":"payment failed"}',
        source="events.jsonl",
    )

    assert event.source == "checkout"


def test_otel_resource_service_name_becomes_source():
    event = parse_json_line(
        '{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"inventory"}}]},'
        '"severityNumber":17,"body":"database unavailable"}',
        source="otel.jsonl",
    )

    assert event.source == "inventory"
    assert event.fields["resource"]["attributes"][0]["key"] == "service.name"


def test_explicit_source_precedes_structured_service_identity():
    event = parse_json_line(
        '{"source":"gateway","service":{"name":"checkout"},"message":"request"}',
        source="events.jsonl",
    )

    assert event.source == "gateway"


def test_malformed_otel_resource_falls_back_to_provenance():
    event = parse_json_line(
        '{"resource":{"attributes":"invalid"},"message":"request"}',
        source="events.jsonl",
    )

    assert event.source == "events.jsonl"
