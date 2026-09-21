from loglens.model import LogEvent


def test_log_event_normalizes_unicode_source_identity() -> None:
    assert LogEvent(message="ok", source="  ａｐｉ\u200b  ").source == "api"


def test_log_event_preserves_visible_unicode_source_text() -> None:
    assert LogEvent(message="ok", source="  café-worker  ").source == "café-worker"


def test_log_event_turns_invisible_or_blank_source_into_missing() -> None:
    assert LogEvent(message="ok", source="\u200b\u2060").source is None
    assert LogEvent(message="ok", source="   ").source is None


def test_serialized_event_uses_canonical_source() -> None:
    event = LogEvent(message="failure", level="ERROR", source="ｗｅｂ\u200b-1")
    assert event.to_dict()["source"] == "web-1"
