from datetime import datetime, timedelta, timezone

from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def _event(second: int) -> LogEvent:
    timestamp = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)
    return LogEvent("request failed", "ERROR", timestamp, "api")


def test_error_burst_reports_observed_span_and_configured_window():
    events = [_event(second) for second in (0, 4, 8, 12, 16)]
    finding = detect_anomalies(
        events,
        error_threshold=99,
        repeat_threshold=99,
        burst_threshold=5,
        burst_window_seconds=60,
    )[0]

    assert finding.rule == "error-burst"
    assert finding.count == 5
    assert finding.message == "Error burst [api]: 5 events in 16s (configured window 60s)"


def test_error_burst_reports_tightest_span_when_peak_counts_tie():
    events = [_event(second) for second in (0, 20, 40, 100, 101, 102)]
    finding = detect_anomalies(
        events,
        error_threshold=99,
        repeat_threshold=99,
        burst_threshold=3,
        burst_window_seconds=60,
    )[0]

    assert finding.count == 3
    assert finding.message == "Error burst [api]: 3 events in 2s (configured window 60s)"
