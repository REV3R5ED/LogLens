"""Explainable per-source health analysis for normalized defensive log events."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable
import unicodedata

from .model import LogEvent

_ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL"}
_SOURCE_SEPARATOR_CATEGORIES = {"Cc", "Zl", "Zp"}


@dataclass(frozen=True, slots=True)
class SourceHealth:
    """Deterministic health summary for one logical log source."""

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


def _normalized_source(source: str | None) -> str:
    """Return a stable display key without hiding missing source metadata.

    Unicode compatibility normalization is applied first. Invisible format
    controls are removed, while ASCII/line controls and Unicode line/paragraph
    separators become whitespace boundaries so distinct visible source tokens
    cannot be silently concatenated. Whitespace is collapsed deterministically.
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


def _normalized_level(level: str) -> str:
    """Return a stable severity label for source-health aggregation.

    ``LogEvent`` is part of the public Python API, so callers can bypass parser
    normalization. Apply Unicode compatibility normalization before trimming and
    upper-casing so equivalent labels such as ``"ERROR"``, ``" error "``, and
    full-width ``"ＥＲＲＯＲ"`` cannot split counters or bypass error
    classification.
    """
    return unicodedata.normalize("NFKC", level).strip().upper()


def summarize_sources(events: Iterable[LogEvent]) -> list[SourceHealth]:
    """Return stable per-source event/error distributions.

    Source identifiers are Unicode-normalized, trimmed, and stripped of
    invisible format controls before grouping; structural controls remain
    boundaries rather than joining adjacent source tokens. Level labels are
    likewise Unicode-normalized, trimmed, and case-normalized before
    aggregation. Missing or empty source metadata is grouped under ``<unknown>``
    rather than discarded. Error rate is a deterministic fraction in the
    inclusive 0..1 range. The function is read-only and performs no network or
    filesystem I/O.
    """
    accumulator = SourceHealthAccumulator()
    for event in events:
        accumulator.add(event)
    return accumulator.summaries()


class SourceHealthAccumulator:
    """Incremental per-source health aggregation for streaming analysis.

    Feeding events one at a time produces exactly the same summaries as
    :func:`summarize_sources`, while keeping memory proportional to distinct
    sources and levels rather than the total event count.
    """

    def __init__(self) -> None:
        self._totals: Counter[str] = Counter()
        self._errors: Counter[str] = Counter()
        self._levels: dict[str, Counter[str]] = defaultdict(Counter)

    def add(self, event: LogEvent) -> None:
        source = _normalized_source(event.source)
        level = _normalized_level(event.level)
        self._totals[source] += 1
        self._levels[source][level] += 1
        if level in _ERROR_LEVELS:
            self._errors[source] += 1

    def summaries(self) -> list[SourceHealth]:
        """Return deterministic per-source summaries sorted by source."""
        summaries: list[SourceHealth] = []
        for source in sorted(self._totals):
            total = self._totals[source]
            error_events = self._errors[source]
            summaries.append(
                SourceHealth(
                    source=source,
                    events=total,
                    error_events=error_events,
                    error_rate=error_events / total,
                    levels=dict(sorted(self._levels[source].items())),
                )
            )
        return summaries


def concentrated_error_sources(
    events: Iterable[LogEvent],
    *,
    min_errors: int = 3,
    min_error_rate: float = 0.5,
) -> list[SourceHealth]:
    """Return sources whose error volume *and* error rate cross both gates.

    Requiring an absolute count and a rate avoids flagging a source because of a
    single isolated failure while still surfacing concentrated defensive signals.
    """
    if not isinstance(min_errors, int) or isinstance(min_errors, bool) or min_errors < 1:
        raise ValueError("min_errors must be an integer >= 1")
    if (
        not isinstance(min_error_rate, (int, float))
        or isinstance(min_error_rate, bool)
        or not 0 <= min_error_rate <= 1
    ):
        raise ValueError("min_error_rate must be a number between 0 and 1")

    return [
        summary
        for summary in summarize_sources(events)
        if summary.error_events >= min_errors and summary.error_rate >= min_error_rate
    ]
