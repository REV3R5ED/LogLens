from loglens.detection import detect_anomalies
from loglens.model import LogEvent


def test_repeated_messages_group_unicode_equivalent_text():
    events = [
        LogEvent(message, "WARN", source="api")
        for message in [
            "retry café",
            "retry cafe\u0301",
            "ｒｅｔｒｙ café",
            "retry\u200b café",
            " retry café ",
        ]
    ]

    findings = detect_anomalies(events, error_threshold=10, repeat_threshold=5, burst_threshold=10)

    assert len(findings) == 1
    assert findings[0].rule == "repeated-message"
    assert findings[0].message == "Repeated message [api]: retry café"
    assert findings[0].count == 5


def test_repeated_message_normalization_preserves_ascii_control_evidence():
    events = [LogEvent("failed\nrequest", "WARN", source="api") for _ in range(2)]

    finding = detect_anomalies(events, error_threshold=10, repeat_threshold=2, burst_threshold=10)[0]

    assert finding.message == r"Repeated message [api]: failed\nrequest"
