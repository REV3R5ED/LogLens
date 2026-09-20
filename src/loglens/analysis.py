"""Defensive event filtering and aggregation helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable
import unicodedata

from .model import LogEvent

_UNSAFE_SOURCE_CATEGORIES = {"Cc", "Cf", "Zl", "Zp"}


def _filter_source_key(source: str | None) -> str:
    """Return a stable case-insensitive key for source filtering."""
    if source is None:
        return "<unknown>"
    source = unicodedata.normalize("NFKC", source)
    normalized = "".join(
        char for char in source if unicodedata.category(char) not in _UNSAFE_SOURCE_CATEGORIES
    ).strip()
    return (normalized or "<unknown>").casefold()


def _filter_level_key(level: str) -> str:
    """Normalize incidental whitespace/casing in a level filter key."""
    return level.strip().upper()


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


@dataclass(frozen=True, slots=True)
class SourceSummary:
    """Deterministic health-oriented summary for one event source."""

    source: str
    events: int
    error_events: int
    error_rate: float
    levels: dict[str, int]

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "events": self.events,
            "error_events": self.error_events,
            "error_rate": self.error_rate,
            "levels": self.levels,
        }


def filter_events(
    events: Iterable[LogEvent],
    *,
    levels: set[str] | None = None,
    contains: str | None = None,
    sources: set[str] | None = None,
) -> list[LogEvent]:
    """Return events matching optional level, message, and source filters.

    Level matching is case-insensitive after trimming incidental whitespace.
    Source matching is case-insensitive after Unicode compatibility
    normalization, removal of invisible/control formatting characters, and
    whitespace trimming. Events without a logical source can be selected
    explicitly with ``<unknown>`` so incomplete telemetry remains queryable.
    """
    normalized_levels = {_filter_level_key(level) for level in levels} if levels else None
    normalized_sources = {_filter_source_key(source) for source in sources} if sources else None
    needle = contains.casefold() if contains else None
    matched: list[LogEvent] = []
    for event in events:
        if normalized_levels is not None and _filter_level_key(event.level) not in normalized_levels:
            continue
        if needle is not None and needle not in event.message.casefold():
            continue
        if normalized_sources is not None and _filter_source_key(event.source) not in normalized_sources:
            continue
        matched.append(event)
    return matched


def summarize(events: Iterable[LogEvent]) -> AnalysisSummary:
    summary = AnalysisSummary()
    for event in events:
        summary.add(event)
    return summary


def summarize_sources(events: Iterable[LogEvent]) -> list[SourceSummary]:
    """Summarize volume and error concentration for each normalized source.

    Missing/blank source values are retained as ``<unknown>`` so incomplete
    telemetry stays visible rather than silently disappearing from analysis.
    ERROR, CRITICAL, and FATAL are treated as error-level events. Results are
    sorted by source for reproducible JSON/reporting use.
    """
    grouped: dict[str, Counter[str]] = {}
    for event in events:
        source = event.source.strip() if event.source and event.source.strip() else "<unknown>"
        levels = grouped.setdefault(source, Counter())
        levels[event.level.upper()] += 1

    summaries: list[SourceSummary] = []
    for source in sorted(grouped):
        levels = grouped[source]
        total = sum(levels.values())
        error_events = sum(levels[level] for level in ("ERROR", "CRITICAL", "FATAL"))
        summaries.append(SourceSummary(
            source=source,
            events=total,
            error_events=error_events,
            error_rate=round(error_events / total, 4),
            levels=dict(sorted(levels.items())),
        ))
    return summaries
