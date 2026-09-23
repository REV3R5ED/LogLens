from loglens.field_analysis import summarize_field_coverage
from loglens.model import LogEvent


def test_integer_and_number_values_are_one_numeric_schema_family():
    summary = summarize_field_coverage(
        [
            LogEvent(message="integer", fields={"latency_ms": 12}),
            LogEvent(message="fractional", fields={"latency_ms": 12.5}),
        ]
    )

    field = summary["fields"]["latency_ms"]
    assert field["types"] == {"integer": 1, "number": 1}
    assert field["type_drift"] is False


def test_numeric_to_string_change_remains_type_drift():
    summary = summarize_field_coverage(
        [
            LogEvent(message="integer", fields={"latency_ms": 12}),
            LogEvent(message="fractional", fields={"latency_ms": 12.5}),
            LogEvent(message="text", fields={"latency_ms": "unknown"}),
        ]
    )

    field = summary["fields"]["latency_ms"]
    assert field["types"] == {"integer": 1, "number": 1, "string": 1}
    assert field["type_drift"] is True
    assert "unknown" not in repr(summary)
