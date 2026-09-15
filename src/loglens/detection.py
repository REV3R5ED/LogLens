"""Deterministic anomaly rules for normalized defensive log events."""

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

    def to_dict(self) -> dict[str, object]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "message": self.message,
            "count": self.count,
        }


def detect_anomalies(
    events: Iterable[LogEvent],
    *,
    error_threshold: int = 5,
    repeat_threshold: int = 5,
) -> list[Finding]:
    """Apply small, transparent rules to a finite event collection.

    Rules intentionally use absolute counts rather than hidden statistical
    models so every finding can be reproduced and explained by an analyst.
    """
    if error_threshold < 1 or repeat_threshold < 2:
        raise ValueError("thresholds must be positive (repeat_threshold >= 2)")

    materialized = list(events)
    findings: list[Finding] = []

    error_count = sum(event.level.upper() in {"ERROR", "CRITICAL", "FATAL"} for event in materialized)
    if error_count >= error_threshold:
        findings.append(Finding("elevated-errors", "medium", "Elevated error-level event count", error_count))

    messages = Counter(event.message.strip() for event in materialized if event.message.strip())
    for message, count in sorted(messages.items()):
        if count >= repeat_threshold:
            findings.append(Finding("repeated-message", "low", f"Repeated message: {message}", count))

    return findings
