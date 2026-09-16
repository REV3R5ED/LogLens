from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def test_detects_elevated_error_count_with_explainable_score():
    events = [LogEvent(f"failure {i}", "ERROR") for i in range(5)]
    findings = detect_anomalies(events)
    assert [finding.to_dict() for finding in findings] == [{
        "rule": "elevated-errors", "severity": "medium",
        "message": "Elevated error-level event count", "count": 5, "score": 75,
    }]


def test_score_increases_with_threshold_excess_and_is_bounded():
    at_threshold = detect_anomalies([LogEvent("bad", "ERROR") for _ in range(5)] + [LogEvent("ok", "INFO") for _ in range(5)])[0]
    above_threshold = detect_anomalies([LogEvent("bad", "ERROR") for _ in range(10)] + [LogEvent("ok", "INFO") for _ in range(5)])[0]
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
    assert findings[0].score == 75
    assert findings[0].severity == "medium"


def test_repeated_messages_are_scoped_by_source():
    events = [LogEvent("connection reset", "WARN", source="api") for _ in range(3)] + [LogEvent("connection reset", "WARN", source="worker") for _ in range(3)]
    assert detect_anomalies(events, repeat_threshold=5) == []


def test_repeated_messages_are_scoped_by_severity_level():
    events = [LogEvent("request finished", "INFO", source="api") for _ in range(3)] + [LogEvent("request finished", "ERROR", source="api") for _ in range(3)]
    assert detect_anomalies(events, error_threshold=10, repeat_threshold=5) == []


def test_source_context_is_exposed_in_repeated_message_finding():
    events = [LogEvent("connection reset", "WARN", source="api") for _ in range(5)]
    finding = detect_anomalies(events)[0]
    assert finding.message == "Repeated message [api]: connection reset"
    assert finding.count == 5


def test_repeated_message_prevalence_uses_source_scope():
    events = [LogEvent("connection reset", "WARN", source="api") for _ in range(5)] + [LogEvent(f"normal {i}", "INFO", source="worker") for i in range(95)]
    finding = detect_anomalies(events)[0]
    assert finding.rule == "repeated-message"
    assert finding.score == 75
    assert finding.severity == "medium"


def test_repeated_message_prevalence_uses_severity_scope():
    events = [LogEvent("connection reset", "WARN", source="api") for _ in range(5)] + [LogEvent(f"normal {i}", "INFO", source="api") for i in range(95)]
    finding = detect_anomalies(events)[0]
    assert finding.rule == "repeated-message"
    assert finding.score == 75
    assert finding.severity == "medium"


def test_low_prevalence_threshold_hit_stays_low_severity():
    events = [LogEvent("retry", "WARN") for _ in range(5)] + [LogEvent(f"normal {i}", "WARN") for i in range(95)]
    finding = detect_anomalies(events)[0]
    assert finding.score == 51
    assert finding.severity == "low"


def test_repeated_message_finding_escapes_ascii_controls():
    events = [LogEvent("failed\n\x1b[31m\trequest\x00", "WARN", source="api\rnode") for _ in range(5)]
    finding = detect_anomalies(events)[0]
    assert finding.message == r"Repeated message [api\rnode]: failed\n\x1b[31m\trequest\x00"
    assert "\n" not in finding.message
    assert "\x1b" not in finding.message
    assert "\x00" not in finding.message


def test_no_findings_below_thresholds():
    assert detect_anomalies([LogEvent("ok", "INFO")]) == []


def test_threshold_validation():
    try:
        detect_anomalies([], repeat_threshold=1)
    except ValueError as exc:
        assert "thresholds" in str(exc)
    else:
        raise AssertionError("expected threshold validation failure")


def test_thresholds_reject_non_integer_values():
    invalid_values = (2.5, float("nan"), float("inf"), True, "5")
    for value in invalid_values:
        try:
            detect_anomalies([], error_threshold=value)  # type: ignore[arg-type]
        except ValueError as exc:
            assert "integers" in str(exc)
        else:
            raise AssertionError(f"expected validation failure for {value!r}")
        try:
            detect_anomalies([], repeat_threshold=value)  # type: ignore[arg-type]
        except ValueError as exc:
            assert "integers" in str(exc)
        else:
            raise AssertionError(f"expected validation failure for {value!r}")
