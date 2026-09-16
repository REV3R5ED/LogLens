"""Deterministic time-window baselines for defensive log analysis."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Iterable

from .model import LogEvent


def _utc(timestamp: datetime) -> datetime:
    """Normalize timestamps to UTC; treat offset-less log timestamps as UTC."""
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def build_time_windows(events: Iterable[LogEvent], *, window_minutes: int = 5) -> list[dict[str, object]]:
    """Aggregate timestamped events into fixed UTC windows.

    Events without a parsed timestamp are intentionally excluded. Windows are
    aligned to Unix-epoch boundaries so repeated analyses produce identical
    buckets regardless of input ordering.
    """
    if not isinstance(window_minutes, int) or isinstance(window_minutes, bool):
        raise ValueError("window_minutes must be an integer between 1 and 1440")
    if window_minutes < 1 or window_minutes > 1440:
        raise ValueError("window_minutes must be between 1 and 1440")

    window_seconds = window_minutes * 60
    buckets: dict[datetime, list[LogEvent]] = {}
    for event in events:
        if event.timestamp is None:
            continue
        timestamp = _utc(event.timestamp)
        epoch_seconds = int(timestamp.timestamp())
        start = datetime.fromtimestamp(
            epoch_seconds - (epoch_seconds % window_seconds), tz=timezone.utc
        )
        buckets.setdefault(start, []).append(event)

    result: list[dict[str, object]] = []
    for start in sorted(buckets):
        bucket = buckets[start]
        levels = Counter(event.level.upper() for event in bucket)
        result.append({
            "start": start.isoformat(),
            "end": (start + timedelta(minutes=window_minutes)).isoformat(),
            "events": len(bucket),
            "error_events": sum(levels[level] for level in ("ERROR", "CRITICAL", "FATAL")),
            "levels": dict(sorted(levels.items())),
        })
    return result
