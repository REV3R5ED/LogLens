from loglens.analysis import filter_events, summarize, summarize_sources
from loglens.model import LogEvent


def test_filter_events_matches_levels_case_insensitively():
    events = [LogEvent("ok", "INFO"), LogEvent("failed", "ERROR")]
    assert filter_events(events, levels={"error"}) == [events[1]]


def test_filter_events_normalizes_level_whitespace():
    events = [LogEvent("failed", " error\t"), LogEvent("ok", " INFO ")]
    assert filter_events(events, levels={" ERROR "}) == [events[0]]


def test_filter_events_normalizes_unicode_level_variants():
    events = [
        LogEvent("failed", "ＥＲＲＯＲ"),
        LogEvent("fatal", "ＦＡＴＡＬ"),
        LogEvent("ok", "ＩＮＦＯ"),
    ]
    assert filter_events(events, levels={" error ", "fatal"}) == events[:2]
    assert filter_events(events, levels={"ＥＲＲＯＲ"}) == [events[0]]


def test_filter_events_normalizes_equivalent_source_identities():
    events = [
        LogEvent("one", "INFO", source="ａｐｉ"),
        LogEvent("two", "WARN", source="a\u200bpi"),
        LogEvent("three", "ERROR", source="worker"),
    ]
    assert filter_events(events, sources={" api "}) == events[:2]


def test_filter_events_treats_control_only_source_as_unknown():
    event = LogEvent("missing source", "WARN", source="\u202e\u200b")
    assert filter_events([event], sources={"<unknown>"}) == [event]


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


def test_summarize_sources_exposes_error_concentration_deterministically():
    events = [
        LogEvent("failed", "error", source="worker"),
        LogEvent("ready", "INFO", source="api"),
        LogEvent("fatal", "FATAL", source="worker"),
        LogEvent("retry", "WARN", source="worker"),
    ]
    assert [item.to_dict() for item in summarize_sources(events)] == [
        {
            "source": "api", "events": 1, "error_events": 0,
            "error_rate": 0.0, "levels": {"INFO": 1},
        },
        {
            "source": "worker", "events": 3, "error_events": 2,
            "error_rate": 0.6667, "levels": {"ERROR": 1, "FATAL": 1, "WARN": 1},
        },
    ]


def test_summarize_sources_keeps_missing_sources_visible():
    events = [LogEvent("failed", "CRITICAL"), LogEvent("ok", "INFO", source="   ")]
    assert [item.to_dict() for item in summarize_sources(events)] == [{
        "source": "<unknown>", "events": 2, "error_events": 1,
        "error_rate": 0.5, "levels": {"CRITICAL": 1, "INFO": 1},
    }]


def test_summarize_sources_normalizes_equivalent_labels_consistently():
    events = [
        LogEvent("one", " error ", source="ａｐｉ"),
        LogEvent("two", "FATAL", source="a\u200bpi"),
        LogEvent("three", " info\t", source="api"),
        LogEvent("unknown", " critical ", source="\u202e\u200b"),
    ]
    assert [item.to_dict() for item in summarize_sources(events)] == [
        {
            "source": "<unknown>", "events": 1, "error_events": 1,
            "error_rate": 1.0, "levels": {"CRITICAL": 1},
        },
        {
            "source": "api", "events": 3, "error_events": 2,
            "error_rate": 0.6667, "levels": {"ERROR": 1, "FATAL": 1, "INFO": 1},
        },
    ]


def test_summarize_sources_empty_stream_is_empty():
    assert summarize_sources([]) == []
