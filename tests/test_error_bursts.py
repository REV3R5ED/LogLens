from datetime import datetime, timedelta, timezone

from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def _event(second: int, source: str = "api", level: str = "ERROR") -> LogEvent:
    return LogEvent("request failed", level, datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second), source)


def test_detects_source_scoped_error_burst_from_unsorted_events():
    events = [_event(40), _event(0), _event(20), _event(10), _event(30)]
    findings = detect_anomalies(events, error_threshold=99, repeat_threshold=99, burst_threshold=5, burst_window_seconds=60)
    assert [finding.to_dict() for finding in findings] == [{
        "rule": "error-burst", "severity": "medium", "message": "Error burst [api]: 5 events in 40s (configured window 60s)", "count": 5, "score": 75,
    }]


def test_error_burst_does_not_merge_sources():
    events = [_event(i * 10, "api") for i in range(3)] + [_event(i * 10, "worker") for i in range(3)]
    findings = detect_anomalies(events, error_threshold=99, repeat_threshold=99, burst_threshold=5)
    assert findings == []


def test_error_burst_ignores_events_without_timestamps():
    events = [LogEvent("failure", "ERROR", source="api") for _ in range(5)]
    findings = detect_anomalies(events, error_threshold=99, repeat_threshold=99, burst_threshold=5)
    assert findings == []


def test_error_burst_respects_window_boundary():
    events = [_event(0), _event(15), _event(30), _event(45), _event(61)]
    findings = detect_anomalies(events, error_threshold=99, repeat_threshold=99, burst_threshold=5, burst_window_seconds=60)
    assert findings == []


def test_error_burst_normalizes_mixed_timezone_offsets():
    offsets = (timezone.utc, timezone(timedelta(hours=-8)), timezone(timedelta(hours=5, minutes=30)))
    instants = (0, 10, 20, 30, 40)
    events = []
    for index, second in enumerate(instants):
        utc_value = datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=second)
        events.append(LogEvent("failure", "ERROR", utc_value.astimezone(offsets[index % len(offsets)]), "api"))
    findings = detect_anomalies(events, error_threshold=99, repeat_threshold=99, burst_threshold=5, burst_window_seconds=60)
    assert len(findings) == 1
    assert findings[0].rule == "error-burst"
    assert findings[0].count == 5


def test_error_burst_treats_naive_timestamp_as_utc():
    events = [_event(0), _event(10), _event(20), _event(30)]
    events.append(LogEvent("failure", "ERROR", datetime(2026, 1, 1, 0, 0, 40), "api"))
    findings = detect_anomalies(events, error_threshold=99, repeat_threshold=99, burst_threshold=5, burst_window_seconds=60)
    assert len(findings) == 1
    assert findings[0].rule == "error-burst"
    assert findings[0].count == 5


def test_burst_configuration_validation():
    for kwargs in ({"burst_threshold": 1}, {"burst_window_seconds": 0}, {"burst_threshold": True}, {"burst_window_seconds": 2.5}):
        try:
            detect_anomalies([], **kwargs)  # type: ignore[arg-type]
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected validation failure for {kwargs!r}")
