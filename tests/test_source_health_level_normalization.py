from loglens.model import LogEvent
from loglens.source_analysis import concentrated_error_sources, summarize_sources


def test_source_health_groups_unicode_equivalent_severity_labels():
    events = [
        LogEvent("failure 1", "ＥＲＲＯＲ", source="api"),
        LogEvent("failure 2", " ＣＲＩＴＩＣＡＬ ", source="api"),
        LogEvent("failure 3", "Ｆａｔａｌ", source="api"),
        LogEvent("healthy", "ＩＮＦＯ", source="api"),
    ]

    summary = summarize_sources(events)[0]

    assert summary.events == 4
    assert summary.error_events == 3
    assert summary.error_rate == 0.75
    assert summary.levels == {"CRITICAL": 1, "ERROR": 1, "FATAL": 1, "INFO": 1}


def test_unicode_severity_variants_cannot_bypass_concentrated_error_gate():
    events = [
        LogEvent("failure 1", "ＥＲＲＯＲ", source="api"),
        LogEvent("failure 2", "ＣＲＩＴＩＣＡＬ", source="api"),
        LogEvent("failure 3", "ＦＡＴＡＬ", source="api"),
        LogEvent("healthy", "INFO", source="api"),
    ]

    findings = concentrated_error_sources(events, min_errors=3, min_error_rate=0.5)

    assert len(findings) == 1
    assert findings[0].source == "api"
    assert findings[0].error_events == 3
