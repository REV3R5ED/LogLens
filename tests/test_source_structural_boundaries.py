from loglens.analysis import filter_events, summarize, summarize_sources
from loglens.model import LogEvent


def test_source_filter_preserves_structural_boundaries():
    separated = LogEvent("one", "ERROR", source="api\nworker")
    joined = LogEvent("two", "ERROR", source="apiworker")

    assert filter_events([separated, joined], sources={"api worker"}) == [separated]
    assert filter_events([separated, joined], sources={"apiworker"}) == [joined]


def test_source_summary_collapses_boundary_whitespace_consistently():
    events = [
        LogEvent("one", "ERROR", source="api\tworker"),
        LogEvent("two", "INFO", source="api  worker"),
        LogEvent("three", "WARN", source="api\u2028worker"),
    ]

    assert summarize(events).to_dict()["sources"] == {"api worker": 3}
    assert [item.to_dict() for item in summarize_sources(events)] == [
        {
            "source": "api worker",
            "events": 3,
            "error_events": 1,
            "error_rate": 0.3333,
            "levels": {"ERROR": 1, "INFO": 1, "WARN": 1},
        }
    ]
