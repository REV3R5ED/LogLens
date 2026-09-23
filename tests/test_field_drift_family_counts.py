from loglens.field_analysis import summarize_field_coverage
from loglens.model import LogEvent


def test_type_drift_family_counts_explain_prevalence_without_values():
    events = [
        LogEvent(message="one", fields={"status": 500}),
        LogEvent(message="two", fields={"status": 503.0}),
        LogEvent(message="three", fields={"status": "unavailable"}),
        LogEvent(message="four", fields={"status": None}),
    ]

    field = summarize_field_coverage(events)["fields"]["status"]

    assert field["type_drift"] is True
    assert field["type_drift_families"] == ["number", "string"]
    assert field["type_drift_family_counts"] == {"number": 2, "string": 1}
    assert "unavailable" not in repr(field)


def test_numeric_widening_stays_compact_without_drift_evidence():
    events = [
        LogEvent(message="one", fields={"latency_ms": 12}),
        LogEvent(message="two", fields={"latency_ms": 12.5}),
    ]

    field = summarize_field_coverage(events)["fields"]["latency_ms"]

    assert field["type_drift"] is False
    assert "type_drift_families" not in field
    assert "type_drift_family_counts" not in field
