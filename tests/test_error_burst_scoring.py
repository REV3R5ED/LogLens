from datetime import datetime, timedelta, timezone

from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def _event(message: str, level: str, second: int, source: str = "api") -> LogEvent:
    return LogEvent(
        message,
        level,
        timestamp=datetime(2026, 9, 18, tzinfo=timezone.utc) + timedelta(seconds=second),
        source=source,
    )


def test_error_burst_score_uses_all_events_in_source_scope():
    events = [_event(f"failure {i}", "ERROR", i) for i in range(5)]
    events.extend(_event(f"normal {i}", "INFO", 120 + i) for i in range(95))

    findings = detect_anomalies(events, error_threshold=100, repeat_threshold=100)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "error-burst"
    assert finding.message == "Error burst [api]: 5 events in 4s (configured window 60s)"
    assert finding.count == 5
    assert finding.score == 51
    assert finding.severity == "low"


def test_error_burst_prevalence_does_not_include_other_sources():
    events = [_event(f"failure {i}", "ERROR", i) for i in range(5)]
    events.extend(_event(f"worker normal {i}", "INFO", 120 + i, source="worker") for i in range(95))

    findings = detect_anomalies(events, error_threshold=100, repeat_threshold=100)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "error-burst"
    assert finding.score == 75
    assert finding.severity == "medium"


def test_error_bursts_do_not_combine_across_sources():
    events = [_event(f"api failure {i}", "ERROR", i, source="api") for i in range(3)]
    events.extend(_event(f"worker failure {i}", "ERROR", i, source="worker") for i in range(3))

    findings = detect_anomalies(
        events,
        error_threshold=100,
        repeat_threshold=100,
        burst_threshold=5,
    )

    assert findings == []
