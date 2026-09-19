from datetime import datetime, timezone

from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def test_repeated_message_context_is_bounded_and_escaped():
    message = "A" * 300 + "\nunsafe"
    events = [LogEvent(message=message, level="WARN", source="api") for _ in range(2)]

    finding = next(item for item in detect_anomalies(events, repeat_threshold=2) if item.rule == "repeated-message")

    context = finding.message.split(": ", 1)[1]
    assert len(context) == 240
    assert context.endswith("...")
    assert "\n" not in context


def test_source_context_is_bounded_for_error_findings():
    source = "service-" + "x" * 300
    events = [LogEvent(message="failed", level="ERROR", source=source) for _ in range(2)]

    findings = detect_anomalies(events, error_threshold=2)
    finding = next(item for item in findings if item.rule == "elevated-errors")

    context = finding.message.removeprefix("Elevated error-level event count [").removesuffix("]")
    assert len(context) == 240
    assert context.endswith("...")


def test_error_burst_source_context_is_bounded():
    source = "worker-" + "z" * 300
    start = datetime(2026, 9, 19, tzinfo=timezone.utc)
    events = [
        LogEvent(message="timeout", level="ERROR", source=source, timestamp=start),
        LogEvent(message="timeout", level="ERROR", source=source, timestamp=start),
    ]

    finding = next(item for item in detect_anomalies(events, burst_threshold=2) if item.rule == "error-burst")

    context = finding.message.split(" [", 1)[1].split("] within", 1)[0]
    assert len(context) == 240
    assert context.endswith("...")
