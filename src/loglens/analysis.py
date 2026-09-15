"""Defensive event filtering and aggregation helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable

from .model import LogEvent


@dataclass(slots=True)
class AnalysisSummary:
    """Aggregate statistics for a stream of normalized events."""

    total: int = 0
    levels: Counter[str] = field(default_factory=Counter)
    sources: Counter[str] = field(default_factory=Counter)

    def add(self, event: LogEvent) -> None:
        self.total += 1
        self.levels[event.level] += 1
        if event.source:
            self.sources[event.source] += 1

    def to_dict(self) -> dict[str, object]:
        return {
            "events": self.total,
            "levels": dict(sorted(self.levels.items())),
            "sources": dict(sorted(self.sources.items())),
        }


def filter_events(
    events: Iterable[LogEvent],
    *,
    levels: set[str] | None = None,
    contains: str | None = None,
) -> list[LogEvent]:
    """Return events matching optional level and message filters."""
    normalized_levels = {level.upper() for level in levels} if levels else None
    needle = contains.casefold() if contains else None
    matched: list[LogEvent] = []
    for event in events:
        if normalized_levels is not None and event.level.upper() not in normalized_levels:
            continue
        if needle is not None and needle not in event.message.casefold():
            continue
        matched.append(event)
    return matched


def summarize(events: Iterable[LogEvent]) -> AnalysisSummary:
    summary = AnalysisSummary()
    for event in events:
        summary.add(event)
    return summary
