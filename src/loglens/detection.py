"""Transparent defensive anomaly rules for normalized log events."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import math
import unicodedata
from typing import Iterable

from .model import LogEvent
from .reporting import Finding


_ERROR_LEVELS = {"ERROR", "CRITICAL", "FATAL"}


def _severity(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    return "low"


def _score(count: int, threshold: int, scope_total: int) -> int:
    """Score a threshold hit using excess count and within-scope prevalence."""
    excess = max(0, count - threshold)
    excess_component = min(25, excess * 5)
    prevalence = count / max(1, scope_total)
    prevalence_component = min(25, round(prevalence * 25))
    return min(100, 50 + excess_component + prevalence_component)


def _escape_controls(value: str) -> str:
    """Render control/format characters visibly so findings stay single-line and safe."""
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


_MAX_FINDING_CONTEXT = 240


def _safe_context(value: str) -> str:
    """Escape control characters and bound untrusted finding context."""
    escaped = _escape_controls(value)
    if len(escaped) <= _MAX_FINDING_CONTEXT:
        return escaped
    return escaped[: _MAX_FINDING_CONTEXT - 3] + "..."


def _utc_timestamp(value: datetime) -> datetime:
    """Normalize event timestamps for deterministic cross-offset comparisons."""
    if value.utcoffset() is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _detect_elevated_errors(events: list[LogEvent], threshold: int) -> list[Finding]:
    totals = Counter(_normalize_source(event.source) for event in events)
    errors = Counter(
        _normalize_source(event.source)
        for event in events
        if _normalize_level(event.level) in _ERROR_LEVELS
    )
    findings: list[Finding] = []
    for source, count in sorted(errors.items(), key=lambda item: item[0] or ""):
        if count >= threshold:
            score = _score(count, threshold, totals[source])
            context = f" [{_safe_context(source)}]" if source else ""
            findings.append(Finding("elevated-errors", _severity(score), f"Elevated error-level event count{context}", count, score))
    return findings


def _detect_error_bursts(events: list[LogEvent], threshold: int, window_seconds: int) -> list[Finding]:
    by_source: dict[str | None, list[datetime]] = defaultdict(list)
    source_totals = Counter(_normalize_source(event.source) for event in events)
    for event in events:
        if _normalize_level(event.level) not in _ERROR_LEVELS or event.timestamp is None:
            continue
        by_source[_normalize_source(event.source)].append(_utc_timestamp(event.timestamp))

    findings: list[Finding] = []
    window = timedelta(seconds=window_seconds)
    for source, timestamps in sorted(by_source.items(), key=lambda item: item[0] or ""):
        ordered = sorted(timestamps)
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
            score = _score(best, threshold, source_totals[source])
            context = f" [{_safe_context(source)}]" if source else ""
            observed_seconds = best_span.total_seconds()
            observed = f"{observed_seconds:g}s"
            findings.append(Finding("error-burst", _severity(score), f"Error burst{context}: {best} events in {observed} (configured window {window_seconds}s)", best, score))
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

    scope_totals = Counter((_normalize_source(event.source), _normalize_level(event.level)) for event in materialized)
    messages: Counter[tuple[str | None, str, str]] = Counter()
    evidence: dict[tuple[str | None, str, str], str] = {}
    for event in materialized:
        normalized_message = _normalize_message(event.message)
        if not normalized_message:
            continue
        key = (_normalize_source(event.source), _normalize_level(event.level), normalized_message)
        messages[key] += 1
        evidence.setdefault(key, event.message.strip())

    for (source, level, message), count in sorted(messages.items(), key=lambda item: ((item[0][0] or ""), item[0][1], item[0][2])):
        if count >= repeat_threshold:
            score = _score(count, repeat_threshold, scope_totals[(source, level)])
            source_context = f" [{_safe_context(source)}]" if source else ""
            display_message = evidence[(source, level, message)]
            findings.append(Finding("repeated-message", _severity(score), f"Repeated message{source_context}: {_safe_context(display_message)}", count, score))

    findings.extend(_detect_error_bursts(materialized, burst_threshold, burst_window_seconds))
    return findings
