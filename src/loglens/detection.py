"""Deterministic anomaly rules and transparent scoring for defensive log events."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import timedelta
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


def _score(count: int, threshold: int, total: int) -> int:
    if total < 1:
        return 0
    excess = max(0, count - threshold)
    excess_points = min(25, round(25 * excess / threshold))
    prevalence_points = min(25, round(25 * count / total))
    return min(100, 50 + excess_points + prevalence_points)


def _severity(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def _escape_controls(value: str) -> str:
    parts: list[str] = []
    for char in value:
        codepoint = ord(char)
        if codepoint < 32 or codepoint == 127:
            escapes = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
            parts.append(escapes.get(char, f"\\x{codepoint:02x}"))
        else:
            parts.append(char)
    return "".join(parts)


def _detect_elevated_errors(events: list[LogEvent], threshold: int) -> list[Finding]:
    """Detect elevated error counts per logical source."""
    totals = Counter(event.source for event in events)
    errors = Counter(
        event.source
        for event in events
        if event.level.upper() in {"ERROR", "CRITICAL", "FATAL"}
    )
    findings: list[Finding] = []
    for source, count in sorted(errors.items(), key=lambda item: item[0] or ""):
        if count >= threshold:
            score = _score(count, threshold, totals[source])
            context = f" [{_escape_controls(source)}]" if source else ""
            findings.append(
                Finding(
                    "elevated-errors",
                    _severity(score),
                    f"Elevated error-level event count{context}",
                    count,
                    score,
                )
            )
    return findings


def _detect_error_bursts(events: list[LogEvent], threshold: int, window_seconds: int) -> list[Finding]:
    """Detect dense error windows per source without requiring ordered input."""
    source_totals = Counter(event.source for event in events)
    errors_by_source: dict[str | None, list[LogEvent]] = defaultdict(list)
    for event in events:
        if event.timestamp is not None and event.level.upper() in {"ERROR", "CRITICAL", "FATAL"}:
            errors_by_source[event.source].append(event)

    findings: list[Finding] = []
    window = timedelta(seconds=window_seconds)
    for source, scoped in sorted(errors_by_source.items(), key=lambda item: item[0] or ""):
        ordered = sorted(scoped, key=lambda event: event.timestamp)  # type: ignore[arg-type]
        left = 0
        best = 0
        for right, event in enumerate(ordered):
            while event.timestamp - ordered[left].timestamp > window:  # type: ignore[operator]
                left += 1
            best = max(best, right - left + 1)
        if best >= threshold:
            score = _score(best, threshold, source_totals[source])
            context = f" [{_escape_controls(source)}]" if source else ""
            findings.append(Finding("error-burst", _severity(score), f"Error burst{context} within {window_seconds}s window", best, score))
    return findings


def detect_anomalies(events: Iterable[LogEvent], *, error_threshold: int = 5, repeat_threshold: int = 5, burst_threshold: int = 5, burst_window_seconds: int = 60) -> list[Finding]:
    """Apply transparent count, repetition, and timestamp-aware burst rules."""
    thresholds = (error_threshold, repeat_threshold, burst_threshold, burst_window_seconds)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in thresholds):
        raise ValueError("thresholds and burst window must be integers")
    if error_threshold < 1 or repeat_threshold < 2 or burst_threshold < 2 or burst_window_seconds < 1:
        raise ValueError("thresholds must be positive (repeat/burst threshold >= 2)")

    materialized = list(events)
    findings = _detect_elevated_errors(materialized, error_threshold)

    scope_totals = Counter((event.source, event.level.upper()) for event in materialized)
    messages = Counter((event.source, event.level.upper(), event.message.strip()) for event in materialized if event.message.strip())
    for (source, level, message), count in sorted(messages.items(), key=lambda item: ((item[0][0] or ""), item[0][1], item[0][2])):
        if count >= repeat_threshold:
            score = _score(count, repeat_threshold, scope_totals[(source, level)])
            source_context = f" [{_escape_controls(source)}]" if source else ""
            findings.append(Finding("repeated-message", _severity(score), f"Repeated message{source_context}: {_escape_controls(message)}", count, score))

    findings.extend(_detect_error_bursts(materialized, burst_threshold, burst_window_seconds))
    return findings
