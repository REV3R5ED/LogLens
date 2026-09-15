from loglens.analysis import filter_events, summarize
from loglens.model import LogEvent


def test_filter_events_matches_levels_case_insensitively():
    events = [LogEvent("ok", "INFO"), LogEvent("failed", "ERROR")]
    assert filter_events(events, levels={"error"}) == [events[1]]


def test_filter_events_combines_level_and_message_filters():
    events = [
        LogEvent("database timeout", "ERROR"),
        LogEvent("cache timeout", "WARN"),
        LogEvent("database ready", "INFO"),
    ]
    assert filter_events(events, levels={"ERROR", "WARN"}, contains="DATABASE") == [events[0]]


def test_summarize_counts_levels_and_sources():
    events = [
        LogEvent("one", "INFO", source="app.log"),
        LogEvent("two", "ERROR", source="app.log"),
        LogEvent("three", "ERROR", source="worker.log"),
    ]
    report = summarize(events).to_dict()
    assert report == {
        "events": 3,
        "levels": {"ERROR": 2, "INFO": 1},
        "sources": {"app.log": 2, "worker.log": 1},
    }


def test_summarize_empty_stream():
    assert summarize([]).to_dict() == {"events": 0, "levels": {}, "sources": {}}
