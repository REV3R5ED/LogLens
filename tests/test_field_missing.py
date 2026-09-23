from loglens.field_analysis import summarize_field_coverage
from loglens.model import LogEvent


def test_field_coverage_reports_missing_events_without_values():
    summary = summarize_field_coverage([
        LogEvent(message="one", fields={"request_id": "secret-1", "status": 200}),
        LogEvent(message="two", fields={"request_id": "secret-2"}),
        LogEvent(message="three", fields={}),
    ])

    assert summary["fields"]["request_id"]["missing"] == 1
    assert summary["fields"]["status"]["missing"] == 2
    assert "secret-1" not in repr(summary)
    assert "secret-2" not in repr(summary)


def test_field_missing_count_respects_normalized_identity_collisions():
    summary = summarize_field_coverage([
        LogEvent(message="one", fields={"request\u200bid": "a", "requestid": "b"}),
        LogEvent(message="two", fields={"requestid": "c"}),
    ])

    assert summary["fields"]["requestid"]["present"] == 2
    assert summary["fields"]["requestid"]["missing"] == 0
    assert summary["fields"]["requestid"]["coverage"] == 1.0
