import math

import pytest

from loglens.model import LogEvent
from loglens.source_analysis import concentrated_error_sources, summarize_sources


def test_source_summaries_are_deterministic_and_case_normalized():
    events = [
        LogEvent("ok", "info", source="worker"),
        LogEvent("bad", "error", source="api"),
        LogEvent("fatal", "FATAL", source="api"),
        LogEvent("unknown source", "WARN"),
    ]

    summaries = summarize_sources(events)

    assert [summary.source for summary in summaries] == ["<unknown>", "api", "worker"]
    api = summaries[1]
    assert api.events == 2
    assert api.error_events == 2
    assert api.error_rate == 1.0
    assert api.levels == {"ERROR": 1, "FATAL": 1}


def test_concentration_requires_both_volume_and_rate():
    events = (
        [LogEvent("bad", "ERROR", source="api") for _ in range(3)]
        + [LogEvent("ok", "INFO", source="api") for _ in range(2)]
        + [LogEvent("bad", "ERROR", source="worker") for _ in range(2)]
        + [LogEvent("ok", "INFO", source="worker") for _ in range(8)]
    )

    findings = concentrated_error_sources(events, min_errors=3, min_error_rate=0.5)

    assert [finding.source for finding in findings] == ["api"]
    assert findings[0].error_rate == 0.6


def test_unknown_source_is_analyzed_instead_of_discarded():
    events = [LogEvent("bad", "CRITICAL") for _ in range(3)]
    assert concentrated_error_sources(events)[0].source == "<unknown>"


@pytest.mark.parametrize("value", [0, -1, True, 2.5, "3"])
def test_min_errors_validation(value):
    with pytest.raises(ValueError, match="min_errors"):
        concentrated_error_sources([], min_errors=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [-0.1, 1.1, True, "0.5", math.nan, math.inf])
def test_min_error_rate_validation(value):
    with pytest.raises(ValueError, match="min_error_rate"):
        concentrated_error_sources([], min_error_rate=value)  # type: ignore[arg-type]
