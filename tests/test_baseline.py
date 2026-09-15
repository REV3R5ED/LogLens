from datetime import datetime, timezone

import pytest

from loglens.baseline import build_time_windows
from loglens.model import LogEvent


def test_builds_deterministic_utc_windows_and_counts_errors():
    events = [
        LogEvent("ok", "INFO", datetime(2026, 9, 15, 10, 4, tzinfo=timezone.utc)),
        LogEvent("bad", "ERROR", datetime(2026, 9, 15, 10, 1, tzinfo=timezone.utc)),
        LogEvent("later", "WARN", datetime(2026, 9, 15, 10, 7, tzinfo=timezone.utc)),
    ]
    windows = build_time_windows(events, window_minutes=5)
    assert windows == [
        {
            "start": "2026-09-15T10:00:00+00:00",
            "end": "2026-09-15T10:05:00+00:00",
            "events": 2,
            "error_events": 1,
            "levels": {"ERROR": 1, "INFO": 1},
        },
        {
            "start": "2026-09-15T10:05:00+00:00",
            "end": "2026-09-15T10:10:00+00:00",
            "events": 1,
            "error_events": 0,
            "levels": {"WARN": 1},
        },
    ]


def test_ignores_events_without_timestamps():
    assert build_time_windows([LogEvent("no timestamp", "INFO")]) == []


def test_naive_timestamps_are_interpreted_as_utc():
    windows = build_time_windows([
        LogEvent("event", "INFO", datetime(2026, 9, 15, 10, 2))
    ])
    assert windows[0]["start"] == "2026-09-15T10:00:00+00:00"


@pytest.mark.parametrize("minutes", [0, 1441])
def test_window_size_is_bounded(minutes):
    with pytest.raises(ValueError, match="between 1 and 1440"):
        build_time_windows([], window_minutes=minutes)
