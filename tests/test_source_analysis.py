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


def test_source_summaries_trim_identifiers_and_group_blank_sources_as_unknown():
    events = [
        LogEvent("bad", "ERROR", source=" api "),
        LogEvent("worse", "CRITICAL", source="api"),
        LogEvent("missing", "WARN", source="   "),
        LogEvent("also missing", "INFO"),
    ]

    summaries = summarize_sources(events)

    assert [summary.source for summary in summaries] == ["<unknown>", "api"]
    unknown, api = summaries
    assert unknown.events == 2
    assert unknown.levels == {"INFO": 1, "WARN": 1}
    assert api.events == 2
    assert api.error_events == 2
    assert api.error_rate == 1.0


def test_source_summaries_collapse_invisible_unicode_control_variants():
    events = [
        LogEvent("bad", "ERROR", source="api"),
        LogEvent("bad", "ERROR", source="a\u200bpi"),
        LogEvent("bad", "ERROR", source="\u202eapi"),
        LogEvent("ok", "INFO", source="api\u2066"),
        LogEvent("missing", "WARN", source="\u200b\u202e"),
    ]

    summaries = summarize_sources(events)

    assert [summary.source for summary in summaries] == ["<unknown>", "api"]
    unknown, api = summaries
    assert unknown.events == 1
    assert api.events == 4
    assert api.error_events == 3
    assert api.error_rate == 0.75


def test_source_summaries_collapse_unicode_compatibility_variants():
    events = [
        LogEvent("bad", "ERROR", source="api"),
        LogEvent("bad", "ERROR", source="ａｐｉ"),
        LogEvent("ok", "INFO", source="api"),
    ]

    summaries = summarize_sources(events)

    assert [summary.source for summary in summaries] == ["api"]
    assert summaries[0].events == 3
    assert summaries[0].error_events == 2
    assert summaries[0].error_rate == 2 / 3


def test_source_summaries_collapse_canonically_equivalent_identifiers():
    events = [
        LogEvent("bad", "ERROR", source="café"),
        LogEvent("bad", "ERROR", source="cafe\u0301"),
        LogEvent("bad", "ERROR", source="café"),
    ]

    findings = concentrated_error_sources(events, min_errors=3, min_error_rate=1.0)

    assert [finding.source for finding in findings] == ["café"]
    assert findings[0].events == 3
    assert findings[0].error_events == 3


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


def test_concentration_uses_normalized_source_identity():
    events = [
        LogEvent("bad", "ERROR", source=" api "),
        LogEvent("bad", "ERROR", source="api"),
        LogEvent("bad", "ERROR", source="api "),
        LogEvent("ok", "INFO", source=" api"),
    ]

    findings = concentrated_error_sources(events, min_errors=3, min_error_rate=0.5)

    assert [finding.source for finding in findings] == ["api"]
    assert findings[0].events == 4
    assert findings[0].error_events == 3
    assert findings[0].error_rate == 0.75


def test_concentration_cannot_be_diluted_by_invisible_source_controls():
    events = [
        LogEvent("bad", "ERROR", source="api"),
        LogEvent("bad", "ERROR", source="a\u200bpi"),
        LogEvent("bad", "ERROR", source="\u202eapi"),
        LogEvent("ok", "INFO", source="api\u2069"),
    ]

    findings = concentrated_error_sources(events, min_errors=3, min_error_rate=0.5)

    assert [finding.source for finding in findings] == ["api"]
    assert findings[0].events == 4
    assert findings[0].error_events == 3


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
