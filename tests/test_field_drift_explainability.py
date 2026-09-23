from loglens.field_analysis import summarize_field_coverage
from loglens.model import LogEvent


def test_incompatible_type_drift_exposes_privacy_safe_families():
    events = [
        LogEvent(message="one", fields={"status": 503}),
        LogEvent(message="two", fields={"status": "unavailable"}),
        LogEvent(message="three", fields={"status": None}),
    ]

    field = summarize_field_coverage(events)["fields"]["status"]

    assert field["type_drift"] is True
    assert field["type_drift_families"] == ["number", "string"]
    assert "unavailable" not in repr(field)


def test_numeric_widening_does_not_emit_drift_families():
    events = [
        LogEvent(message="one", fields={"latency_ms": 12}),
        LogEvent(message="two", fields={"latency_ms": 12.5}),
    ]

    field = summarize_field_coverage(events)["fields"]["latency_ms"]

    assert field["types"] == {"integer": 1, "number": 1}
    assert field["type_drift"] is False
    assert "type_drift_families" not in field
