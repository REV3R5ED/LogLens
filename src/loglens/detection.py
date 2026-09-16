"""Deterministic anomaly rules and transparent scoring for defensive log events."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
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
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "count": self.count,
            "score": self.score,
        }


def _score(count: int, threshold: int, total: int) -> int:
    """Return a bounded 0-100 score from threshold excess and prevalence.

    A finding starts at 50 when it reaches its configured threshold. Up to 25
    points reflect how far the count exceeds that threshold and up to 25 points
    reflect how much of the relevant event set the signal represents. This keeps
    scoring deterministic, bounded, and straightforward to reproduce.
    """
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


def detect_anomalies(
    events: Iterable[LogEvent],
    *,
    error_threshold: int = 5,
    repeat_threshold: int = 5,
) -> list[Finding]:
    """Apply small, transparent rules to a finite event collection.

    Repeated-message detection is scoped by source and normalized severity level.
    This prevents identical text emitted at different severities from being merged
    into a misleading repetition signal. Prevalence scoring remains source-local
    when source metadata is available.
    """
    if error_threshold < 1 or repeat_threshold < 2:
        raise ValueError("thresholds must be positive (repeat_threshold >= 2)")

    materialized = list(events)
    total = len(materialized)
    findings: list[Finding] = []

    error_count = sum(event.level.upper() in {"ERROR", "CRITICAL", "FATAL"} for event in materialized)
    if error_count >= error_threshold:
        score = _score(error_count, error_threshold, total)
        findings.append(Finding(
            "elevated-errors", _severity(score), "Elevated error-level event count", error_count, score
        ))

    source_totals = Counter(event.source for event in materialized)
    messages = Counter(
        (event.source, event.level.upper(), event.message.strip())
        for event in materialized
        if event.message.strip()
    )
    for (source, _level, message), count in sorted(
        messages.items(), key=lambda item: ((item[0][0] or ""), item[0][1], item[0][2])
    ):
        if count >= repeat_threshold:
            score = _score(count, repeat_threshold, source_totals[source])
            source_context = f" [{source}]" if source else ""
            findings.append(Finding(
                "repeated-message",
                _severity(score),
                f"Repeated message{source_context}: {message}",
                count,
                score,
            ))

    return findings
