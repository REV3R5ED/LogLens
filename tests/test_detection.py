from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def test_detects_elevated_error_count():
    events = [LogEvent(f"failure {i}", "ERROR") for i in range(5)]
    findings = detect_anomalies(events)
    assert [finding.to_dict() for finding in findings] == [{
        "rule": "elevated-errors",
        "severity": "medium",
        "message": "Elevated error-level event count",
        "count": 5,
    }]


def test_detects_repeated_messages_deterministically():
    events = [LogEvent("retry", "WARN") for _ in range(5)] + [LogEvent("ok", "INFO")]
    findings = detect_anomalies(events)
    assert len(findings) == 1
    assert findings[0].rule == "repeated-message"
    assert findings[0].count == 5


def test_no_findings_below_thresholds():
    assert detect_anomalies([LogEvent("ok", "INFO")]) == []


def test_threshold_validation():
    try:
        detect_anomalies([], repeat_threshold=1)
    except ValueError as exc:
        assert "thresholds" in str(exc)
    else:
        raise AssertionError("expected threshold validation failure")
