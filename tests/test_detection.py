from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def test_detects_elevated_error_count_with_explainable_score():
    events = [LogEvent(f"failure {i}", "ERROR") for i in range(5)]
    findings = detect_anomalies(events)
    assert [finding.to_dict() for finding in findings] == [{
        "rule": "elevated-errors",
        "severity": "medium",
        "message": "Elevated error-level event count",
        "count": 5,
        "score": 75,
    }]


def test_score_increases_with_threshold_excess_and_is_bounded():
    at_threshold = detect_anomalies(
        [LogEvent("bad", "ERROR") for _ in range(5)] + [LogEvent("ok", "INFO") for _ in range(5)]
    )[0]
    above_threshold = detect_anomalies(
        [LogEvent("bad", "ERROR") for _ in range(10)] + [LogEvent("ok", "INFO") for _ in range(5)]
    )[0]
    assert at_threshold.score == 62
    assert above_threshold.score == 92
    assert above_threshold.score > at_threshold.score
    assert above_threshold.severity == "high"


def test_detects_repeated_messages_deterministically():
    events = [LogEvent("retry", "WARN") for _ in range(5)] + [LogEvent("ok", "INFO")]
    findings = detect_anomalies(events)
    assert len(findings) == 1
    assert findings[0].rule == "repeated-message"
    assert findings[0].count == 5
    assert findings[0].score == 71
    assert findings[0].severity == "medium"


def test_low_prevalence_threshold_hit_stays_low_severity():
    events = [LogEvent("retry", "WARN") for _ in range(5)] + [
        LogEvent(f"normal {i}", "INFO") for i in range(95)
    ]
    finding = detect_anomalies(events)[0]
    assert finding.score == 51
    assert finding.severity == "low"


def test_no_findings_below_thresholds():
    assert detect_anomalies([LogEvent("ok", "INFO")]) == []


def test_threshold_validation():
    try:
        detect_anomalies([], repeat_threshold=1)
    except ValueError as exc:
        assert "thresholds" in str(exc)
    else:
        raise AssertionError("expected threshold validation failure")
