"""Defensive event filtering and aggregation helpers."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Iterable
import unicodedata

from .model import LogEvent
from .source_analysis import summarize_sources as summarize_source_health

_SOURCE_SEPARATOR_CATEGORIES = {"Cc", "Zl", "Zp"}
_MESSAGE_SEPARATOR_CATEGORIES = {"Cc", "Zl", "Zp"}


def _normalized_source(source: str | None) -> str:
    """Return a stable display identity for source filtering and aggregation.

    Invisible format controls are removed, while structural controls become
    whitespace boundaries. This prevents identifiers such as ``api\nworker``
    from being silently joined into ``apiworker`` during normalization.
    """
    if source is None:
        return "<unknown>"
    source = unicodedata.normalize("NFKC", source)
    normalized = []
    for char in source:
        category = unicodedata.category(char)
        if category == "Cf":
            continue
        if category in _SOURCE_SEPARATOR_CATEGORIES:
            normalized.append(" ")
        else:
            normalized.append(char)
    collapsed = " ".join("".join(normalized).split())
    return collapsed or "<unknown>"


def _filter_source_key(source: str | None) -> str:
    """Return a stable case-insensitive key for source filtering."""
    return _normalized_source(source).casefold()


def _filter_level_key(level: str) -> str:
    """Return a compatibility-normalized severity key for filtering."""
    return unicodedata.normalize("NFKC", level).strip().upper()


def _filter_message_key(message: str) -> str:
    """Return a compatibility-normalized key for defensive substring filtering.

    Unicode format controls are removed so invisible characters cannot split an
    otherwise visible search term. ASCII/line controls become spaces instead of
    being deleted, preventing a search from accidentally matching across record
    structure such as a newline or tab.
    """
    message = unicodedata.normalize("NFKC", message)
    normalized = []
    for char in message:
        category = unicodedata.category(char)
        if category == "Cf":
            continue
        if category in _MESSAGE_SEPARATOR_CATEGORIES:
            normalized.append(" ")
        else:
            normalized.append(char)
    return "".join(normalized).casefold()


@dataclass(slots=True)
class AnalysisSummary:
    """Aggregate statistics for a stream of normalized events."""

    total: int = 0
    levels: Counter[str] = field(default_factory=Counter)
    sources: Counter[str] = field(default_factory=Counter)

    def add(self, event: LogEvent) -> None:
        self.total += 1
        self.levels[_filter_level_key(event.level)] += 1
        source = _normalized_source(event.source)
        self.sources[source] += 1

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

    Level matching is case-insensitive after Unicode compatibility normalization
    and whitespace trimming. Message matching is case-insensitive after Unicode
    compatibility normalization; invisible format controls are ignored while
    structural controls remain separators. Source matching is case-insensitive
    after Unicode compatibility normalization; invisible format controls are
    removed while structural controls remain whitespace boundaries. Events
    without a logical source can be selected explicitly with ``<unknown>`` so
    incomplete telemetry remains queryable.
    """
    normalized_levels = {_filter_level_key(level) for level in levels} if levels else None
    normalized_sources = {_filter_source_key(source) for source in sources} if sources else None
    needle = _filter_message_key(contains) if contains else None
    matched: list[LogEvent] = []
    for event in events:
        if normalized_levels is not None and _filter_level_key(event.level) not in normalized_levels:
            continue
        if needle is not None and needle not in _filter_message_key(event.message):
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
    """Summarize volume and error concentration for each logical source.

    This compatibility API delegates grouping and label normalization to the
    hardened source-health analyzer so reports cannot disagree about equivalent
    Unicode source identities, invisible controls, missing metadata, or padded
    level labels. Error rates retain this API's historical four-decimal output.
    """
    return [
        SourceSummary(
            source=summary.source,
            events=summary.events,
            error_events=summary.error_events,
            error_rate=round(summary.error_rate, 4),
            levels=summary.levels,
        )
        for summary in summarize_source_health(events)
    ]
