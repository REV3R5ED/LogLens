"""Deterministic anomaly rules and transparent scoring for defensive log events."""

from __future__ import annotations

from collections import Counter, defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import unicodedata
from typing import Iterable

from .model import LogEvent


@dataclass(frozen=True, slots=True)
class Finding:
    """One explainable anomaly finding produced by a built-in rule."""

    rule: str
    severity: str
    message: str
    count: int
    score: int

    def to_dict(self) -> dict[str, object]:
        return {"rule": self.rule, "severity": self.severity, "message": self.message, "count": self.count, "score": self.score}


@dataclass(frozen=True, slots=True)
class ScoringConfig:
    """Tunable weights and cutoffs for the transparent 0-100 anomaly score.

    A rule that reaches its configured threshold starts at ``base_points``.
    Up to ``excess_points`` reflect how far the observed count exceeds the
    threshold, and up to ``prevalence_points`` reflect the finding's
    prevalence across the matched event set. Scores at or above
    ``high_cutoff`` are ``high``; scores at or above ``medium_cutoff`` are
    ``medium``; anything lower is ``low``. ``max_finding_context`` bounds the
    untrusted text embedded in finding messages. The defaults reproduce the
    historical 50/25/25 split with cutoffs at 60/80.
    """

    base_points: int = 50
    excess_points: int = 25
    prevalence_points: int = 25
    medium_cutoff: int = 60
    high_cutoff: int = 80
    max_finding_context: int = 240

    def __post_init__(self) -> None:
        for name in ("base_points", "excess_points", "prevalence_points"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")
        for name in ("medium_cutoff", "high_cutoff"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 100:
                raise ValueError(f"{name} must be an integer between 1 and 100")
        context = self.max_finding_context
        if not isinstance(context, int) or isinstance(context, bool) or context < 1:
            raise ValueError("max_finding_context must be a positive integer")
        if self.medium_cutoff >= self.high_cutoff:
            raise ValueError("medium_cutoff must be below high_cutoff")

    def to_dict(self) -> dict[str, int]:
        return {
            "base_points": self.base_points,
            "excess_points": self.excess_points,
            "prevalence_points": self.prevalence_points,
            "medium_cutoff": self.medium_cutoff,
            "high_cutoff": self.high_cutoff,
            "max_finding_context": self.max_finding_context,
        }


@dataclass(frozen=True, slots=True)
class SourceThresholds:
    """Optional per-source threshold overrides; ``None`` keeps the global value."""

    error_threshold: int | None = None
    repeat_threshold: int | None = None
    burst_threshold: int | None = None
    burst_window_seconds: int | None = None

    def __post_init__(self) -> None:
        bounds = (
            ("error_threshold", self.error_threshold, 1),
            ("repeat_threshold", self.repeat_threshold, 2),
            ("burst_threshold", self.burst_threshold, 2),
            ("burst_window_seconds", self.burst_window_seconds, 1),
        )
        for name, value, minimum in bounds:
            if value is None:
                continue
            if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
                raise ValueError(f"{name} must be an integer >= {minimum}")

    def to_dict(self) -> dict[str, int]:
        return {
            name: value
            for name, value in (
                ("error_threshold", self.error_threshold),
                ("repeat_threshold", self.repeat_threshold),
                ("burst_threshold", self.burst_threshold),
                ("burst_window_seconds", self.burst_window_seconds),
            )
            if value is not None
        }


_DEFAULT_SCORING = ScoringConfig()


def _score(count: int, threshold: int, total: int, scoring: ScoringConfig = _DEFAULT_SCORING) -> int:
    if total < 1:
        return 0
    excess = max(0, count - threshold)
    excess_points = min(scoring.excess_points, round(scoring.excess_points * excess / threshold))
    prevalence_points = min(scoring.prevalence_points, round(scoring.prevalence_points * count / total))
    return min(100, scoring.base_points + excess_points + prevalence_points)


def _severity(score: int, scoring: ScoringConfig = _DEFAULT_SCORING) -> str:
    if score >= scoring.high_cutoff:
        return "high"
    if score >= scoring.medium_cutoff:
        return "medium"
    return "low"


def _escape_controls(value: str) -> str:
    """Render control/format characters visibly so findings cannot spoof reports."""
    parts: list[str] = []
    for char in value:
        codepoint = ord(char)
        category = unicodedata.category(char)
        if char in {"\n", "\r", "\t"}:
            parts.append({"\n": r"\n", "\r": r"\r", "\t": r"\t"}[char])
        elif category in {"Cc", "Cf", "Zl", "Zp"}:
            if codepoint <= 0xFF:
                parts.append(f"\\x{codepoint:02x}")
            elif codepoint <= 0xFFFF:
                parts.append(f"\\u{codepoint:04x}")
            else:
                parts.append(f"\\U{codepoint:08x}")
        else:
            parts.append(char)
    return "".join(parts)


def _normalize_source(value: str | None) -> str | None:
    """Canonicalize logical source labels before anomaly grouping."""
    if value is None:
        return None
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(char for char in normalized if unicodedata.category(char) not in {"Cc", "Cf", "Zl", "Zp"}).strip()
    return normalized or None


def _normalize_level(value: str) -> str:
    """Canonicalize severity labels used by anomaly rules."""
    return unicodedata.normalize("NFKC", value).strip().upper()


def _normalize_message(value: str) -> str:
    """Canonicalize repeated-message keys while retaining raw evidence separately."""
    normalized = unicodedata.normalize("NFKC", value)
    normalized = "".join(char for char in normalized if unicodedata.category(char) not in {"Cf", "Zl", "Zp"})
    return normalized.strip()


def _safe_context(value: str, scoring: ScoringConfig = _DEFAULT_SCORING) -> str:
    """Escape control characters and bound untrusted finding context."""
    escaped = _escape_controls(value)
    limit = scoring.max_finding_context
    if len(escaped) <= limit:
        return escaped
    return escaped[: limit - 3] + "..."


def _utc_timestamp(value: datetime) -> datetime:
    """Normalize event timestamps for deterministic cross-offset comparisons."""
    if value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _threshold_for(
    overrides: Mapping[str | None, SourceThresholds] | None,
    source: str | None,
    name: str,
    default: int,
) -> int:
    """Return the per-source override for ``name`` when configured, else ``default``."""
    if overrides:
        override = overrides.get(source)
        if override is not None:
            value = getattr(override, name)
            if value is not None:
                return value
    return default


class DetectionAccumulator:
    """Incremental per-source state for the deterministic anomaly rules.

    Feeding events one at a time produces exactly the same findings as
    passing a materialized list to :func:`detect_anomalies`, while keeping
    memory proportional to distinct sources and messages rather than the
    total event count.
    """

    def __init__(self) -> None:
        self.totals: Counter[str | None] = Counter()
        self.errors: Counter[str | None] = Counter()
        self.scope_totals: Counter[tuple[str | None, str]] = Counter()
        self.messages: Counter[tuple[str | None, str, str]] = Counter()
        self.evidence: dict[tuple[str | None, str, str], str] = {}
        self.error_timestamps: dict[str | None, list[datetime]] = defaultdict(list)

    def add(self, event: LogEvent) -> None:
        source = _normalize_source(event.source)
        level = _normalize_level(event.level)
        self.totals[source] += 1
        self.scope_totals[(source, level)] += 1
        if level in {"ERROR", "CRITICAL", "FATAL"}:
            self.errors[source] += 1
            if event.timestamp is not None:
                self.error_timestamps[source].append(_utc_timestamp(event.timestamp))
        normalized_message = _normalize_message(event.message)
        if normalized_message:
            key = (source, level, normalized_message)
            self.messages[key] += 1
            if key not in self.evidence:
                self.evidence[key] = event.message.strip()

    def message_counts(self) -> dict[tuple[str | None, str, str], int]:
        """Return a snapshot of per (source, level, message) occurrence counts."""
        return dict(self.messages)

    def findings(
        self,
        *,
        error_threshold: int = 5,
        repeat_threshold: int = 5,
        burst_threshold: int = 5,
        burst_window_seconds: int = 60,
        scoring: ScoringConfig | None = None,
        source_overrides: Mapping[str | None, SourceThresholds] | None = None,
    ) -> list[Finding]:
        """Evaluate the elevated-errors, repeated-message, and error-burst rules."""
        resolved = scoring if scoring is not None else _DEFAULT_SCORING
        findings = self._elevated_error_findings(error_threshold, resolved, source_overrides)
        findings.extend(self._repeated_message_findings(repeat_threshold, resolved, source_overrides))
        findings.extend(self._error_burst_findings(burst_threshold, burst_window_seconds, resolved, source_overrides))
        return findings

    def novelty_findings(
        self,
        known_keys: Iterable[tuple[str | None, str, str]],
        *,
        scoring: ScoringConfig | None = None,
    ) -> list[Finding]:
        """Flag (source, level, message) keys absent from a reference corpus.

        Novelty scoring reuses the transparent formula with an effective
        threshold of 1: any unseen message starts at base points, with excess
        and prevalence points added exactly as for the other count rules.
        """
        resolved = scoring if scoring is not None else _DEFAULT_SCORING
        known = set(known_keys)
        findings: list[Finding] = []
        for (source, level, message), count in sorted(
            self.messages.items(), key=lambda item: ((item[0][0] or ""), item[0][1], item[0][2])
        ):
            if (source, level, message) in known:
                continue
            score = _score(count, 1, self.scope_totals[(source, level)], resolved)
            source_context = f" [{_safe_context(source, resolved)}]" if source else ""
            display_message = self.evidence[(source, level, message)]
            findings.append(Finding(
                "novel-message",
                _severity(score, resolved),
                f"Novel message{source_context}: {_safe_context(display_message, resolved)}",
                count,
                score,
            ))
        return findings

    def _elevated_error_findings(
        self,
        error_threshold: int,
        scoring: ScoringConfig,
        source_overrides: Mapping[str | None, SourceThresholds] | None,
    ) -> list[Finding]:
        """Detect elevated error counts per logical source."""
        findings: list[Finding] = []
        for source in sorted(self.errors, key=lambda item: item or ""):
            threshold = _threshold_for(source_overrides, source, "error_threshold", error_threshold)
            count = self.errors[source]
            if count >= threshold:
                score = _score(count, threshold, self.totals[source], scoring)
                context = f" [{_safe_context(source, scoring)}]" if source else ""
                findings.append(Finding("elevated-errors", _severity(score, scoring), f"Elevated error-level event count{context}", count, score))
        return findings

    def _repeated_message_findings(
        self,
        repeat_threshold: int,
        scoring: ScoringConfig,
        source_overrides: Mapping[str | None, SourceThresholds] | None,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for (source, level, message), count in sorted(
            self.messages.items(), key=lambda item: ((item[0][0] or ""), item[0][1], item[0][2])
        ):
            threshold = _threshold_for(source_overrides, source, "repeat_threshold", repeat_threshold)
            if count >= threshold:
                score = _score(count, threshold, self.scope_totals[(source, level)], scoring)
                source_context = f" [{_safe_context(source, scoring)}]" if source else ""
                display_message = self.evidence[(source, level, message)]
                findings.append(Finding("repeated-message", _severity(score, scoring), f"Repeated message{source_context}: {_safe_context(display_message, scoring)}", count, score))
        return findings

    def _error_burst_findings(
        self,
        burst_threshold: int,
        burst_window_seconds: int,
        scoring: ScoringConfig,
        source_overrides: Mapping[str | None, SourceThresholds] | None,
    ) -> list[Finding]:
        """Detect dense error windows per source without requiring ordered input."""
        findings: list[Finding] = []
        window_cache: dict[int, timedelta] = {}
        for source in sorted(self.error_timestamps, key=lambda item: item or ""):
            threshold = _threshold_for(source_overrides, source, "burst_threshold", burst_threshold)
            window_seconds = _threshold_for(source_overrides, source, "burst_window_seconds", burst_window_seconds)
            if window_seconds not in window_cache:
                window_cache[window_seconds] = timedelta(seconds=window_seconds)
            window = window_cache[window_seconds]
            ordered = sorted(self.error_timestamps[source])
            left = 0
            best = 0
            best_span = timedelta(0)
            for right, timestamp in enumerate(ordered):
                while timestamp - ordered[left] > window:
                    left += 1
                count = right - left + 1
                span = timestamp - ordered[left]
                if count > best or (count == best and span < best_span):
                    best = count
                    best_span = span
            if best >= threshold:
                score = _score(best, threshold, self.totals[source], scoring)
                context = f" [{_safe_context(source, scoring)}]" if source else ""
                observed_seconds = best_span.total_seconds()
                observed = f"{observed_seconds:g}s"
                findings.append(Finding("error-burst", _severity(score, scoring), f"Error burst{context}: {best} events in {observed} (configured window {window_seconds}s)", best, score))
        return findings


def detect_anomalies(
    events: Iterable[LogEvent],
    *,
    error_threshold: int = 5,
    repeat_threshold: int = 5,
    burst_threshold: int = 5,
    burst_window_seconds: int = 60,
    scoring: ScoringConfig | None = None,
    source_overrides: Mapping[str | None, SourceThresholds] | None = None,
) -> list[Finding]:
    """Apply transparent count, repetition, and timestamp-aware burst rules.

    ``scoring`` replaces the default 50/25/25 weights and 60/80 severity
    cutoffs with analyst-tuned values; ``source_overrides`` maps normalized
    source names to per-source threshold overrides, leaving other sources on
    the global thresholds.
    """
    thresholds = (error_threshold, repeat_threshold, burst_threshold, burst_window_seconds)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in thresholds):
        raise ValueError("thresholds and burst window must be integers")
    if error_threshold < 1 or repeat_threshold < 2 or burst_threshold < 2 or burst_window_seconds < 1:
        raise ValueError("thresholds must be positive (repeat/burst threshold >= 2)")

    accumulator = DetectionAccumulator()
    for event in events:
        accumulator.add(event)
    return accumulator.findings(
        error_threshold=error_threshold,
        repeat_threshold=repeat_threshold,
        burst_threshold=burst_threshold,
        burst_window_seconds=burst_window_seconds,
        scoring=scoring,
        source_overrides=source_overrides,
    )


def detect_novel_messages(
    events: Iterable[LogEvent],
    known_keys: Iterable[tuple[str | None, str, str]],
    *,
    scoring: ScoringConfig | None = None,
) -> list[Finding]:
    """Flag messages never observed in a reference corpus.

    ``known_keys`` holds ``(source, level, normalized_message)`` triples as
    produced by :func:`loglens.novelty.corpus_key`; every other distinct
    message becomes a ``novel-message`` finding scored with an effective
    threshold of 1.
    """
    accumulator = DetectionAccumulator()
    for event in events:
        accumulator.add(event)
    return accumulator.novelty_findings(known_keys, scoring=scoring)
