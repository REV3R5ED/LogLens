"""Deterministic time-window baselines for defensive log analysis."""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping
import unicodedata

from .detection import Finding, ScoringConfig, _severity
from .model import LogEvent

logger = logging.getLogger("loglens")


class BaselineDiffError(ValueError):
    """Raised when a baseline reference cannot be loaded or compared."""


def _utc(timestamp: datetime) -> datetime:
    """Normalize timestamps to UTC; treat offset-less log timestamps as UTC."""
    if timestamp.tzinfo is None:
        return timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def _normalized_level(level: str) -> str:
    """Return the canonical level label used by time-window aggregation."""
    return unicodedata.normalize("NFKC", level).strip().upper()


def _check_window_minutes(window_minutes: int) -> int:
    if not isinstance(window_minutes, int) or isinstance(window_minutes, bool):
        raise ValueError("window_minutes must be an integer between 1 and 1440")
    if window_minutes < 1 or window_minutes > 1440:
        raise ValueError("window_minutes must be between 1 and 1440")
    return window_minutes


class TimeWindowAccumulator:
    """Incremental fixed-UTC-window aggregation for streaming analysis.

    Feeding events one at a time produces exactly the same windows as
    :func:`build_time_windows`, while keeping memory proportional to distinct
    windows and levels rather than the total event count. Windows align to
    Unix-epoch boundaries so repeated analyses produce identical buckets
    regardless of input ordering; events without a parsed timestamp are
    excluded but counted via :attr:`timestamped_events`.
    """

    def __init__(self, *, window_minutes: int = 5) -> None:
        self.window_minutes = _check_window_minutes(window_minutes)
        self.window_seconds = self.window_minutes * 60
        self.buckets: dict[datetime, Counter[str]] = {}
        self.timestamped_events = 0

    def add(self, event: LogEvent) -> None:
        if event.timestamp is None:
            return
        self.timestamped_events += 1
        timestamp = _utc(event.timestamp)
        epoch_seconds = int(timestamp.timestamp())
        start = datetime.fromtimestamp(
            epoch_seconds - (epoch_seconds % self.window_seconds), tz=timezone.utc
        )
        self.buckets.setdefault(start, Counter())[_normalized_level(event.level)] += 1

    def windows(self) -> list[dict[str, object]]:
        """Return deterministic window dicts sorted by window start."""
        result: list[dict[str, object]] = []
        for start in sorted(self.buckets):
            levels = self.buckets[start]
            event_count = sum(levels.values())
            result.append({
                "start": start.isoformat(),
                "end": (start + timedelta(minutes=self.window_minutes)).isoformat(),
                "events": event_count,
                "error_events": sum(levels[level] for level in ("ERROR", "CRITICAL", "FATAL")),
                "levels": dict(sorted(levels.items())),
            })
        return result


def build_time_windows(events: Iterable[LogEvent], *, window_minutes: int = 5) -> list[dict[str, object]]:
    """Aggregate timestamped events into fixed UTC windows.

    Events without a parsed timestamp are intentionally excluded. Windows are
    aligned to Unix-epoch boundaries so repeated analyses produce identical
    buckets regardless of input ordering.
    """
    accumulator = TimeWindowAccumulator(window_minutes=window_minutes)
    for event in events:
        accumulator.add(event)
    return accumulator.windows()


def load_reference_windows(path: Path | str) -> tuple[list[dict[str, Any]], int | None]:
    """Load reference time windows for baseline diffing.

    Accepts either a full LogLens JSON report (using its
    ``time_baseline.windows``) or a bare ``{"windows": [...]}`` object, and
    returns ``(windows, window_minutes)`` with ``window_minutes`` defaulting
    to ``None`` for bare window files.
    """
    reference = Path(path)
    try:
        raw = json.loads(reference.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise BaselineDiffError(f"baseline reference not found: {reference}") from None
    except OSError as exc:
        raise BaselineDiffError(f"cannot read baseline reference {reference}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise BaselineDiffError(f"invalid JSON in baseline reference {reference}: {exc}") from exc
    if not isinstance(raw, dict):
        raise BaselineDiffError(f"baseline reference {reference} must contain a JSON object")

    window_minutes: int | None = None
    baseline = raw.get("time_baseline")
    if isinstance(baseline, dict):
        raw_windows = baseline.get("windows", [])
        candidate = baseline.get("window_minutes")
        if isinstance(candidate, int) and not isinstance(candidate, bool):
            window_minutes = candidate
    elif "windows" in raw:
        raw_windows = raw["windows"]
    else:
        raise BaselineDiffError(
            f"baseline reference {reference} has no time_baseline.windows or windows; "
            "save a report with --window-minutes first"
        )
    if not isinstance(raw_windows, list):
        raise BaselineDiffError(f"baseline reference {reference}: windows must be a list")

    windows: list[dict[str, Any]] = []
    for entry in raw_windows:
        if not isinstance(entry, Mapping):
            raise BaselineDiffError(f"baseline reference {reference}: window entries must be objects")
        try:
            start = str(entry["start"])
            events = int(entry["events"])  # type: ignore[arg-type]
            error_events = int(entry["error_events"])  # type: ignore[arg-type]
        except (KeyError, TypeError, ValueError) as exc:
            raise BaselineDiffError(
                f"baseline reference {reference}: window entries need start/events/error_events ({exc})"
            ) from exc
        if isinstance(entry["events"], bool) or isinstance(entry["error_events"], bool):
            raise BaselineDiffError(f"baseline reference {reference}: window events/error_events must be integers")
        if events < 0 or error_events < 0:
            raise BaselineDiffError(f"baseline reference {reference}: window counts must be non-negative")
        windows.append({"start": start, "events": events, "error_events": error_events})
    return windows, window_minutes


def _window_error_rate(window: Mapping[str, Any]) -> float:
    events = window["events"]
    return window["error_events"] / events if events else 0.0


def diff_time_windows(
    current: Iterable[Mapping[str, Any]],
    reference: Iterable[Mapping[str, Any]],
    *,
    threshold: float,
    scoring: ScoringConfig | None = None,
) -> tuple[list[Finding], list[dict[str, Any]]]:
    """Compare current windows against a reference and flag error-rate drift.

    Returns ``(findings, deltas)``. A ``baseline-drift`` finding is emitted for
    each window present in both sets whose absolute error-rate delta reaches
    ``threshold`` (a fraction in 0..1). Drift scores reuse the transparent
    scale as ``min(100, round(50 + 50 * |delta|))``, so a threshold-sized drift
    lands exactly on the medium boundary. Windows present only in the current
    run that contain error events produce a low-severity
    ``baseline-new-window`` finding; windows that vanished from the reference
    are reported in ``deltas`` without a finding.
    """
    if not isinstance(threshold, (int, float)) or isinstance(threshold, bool) or not 0 <= threshold <= 1:
        raise BaselineDiffError(f"baseline diff threshold must be a number between 0 and 1, got {threshold!r}")
    resolved = scoring if scoring is not None else ScoringConfig()

    reference_by_start = {window["start"]: window for window in reference}
    current_by_start = {window["start"]: window for window in current}

    findings: list[Finding] = []
    deltas: list[dict[str, Any]] = []
    for start in sorted(set(reference_by_start) | set(current_by_start)):
        ref_window = reference_by_start.get(start)
        cur_window = current_by_start.get(start)
        ref_rate = _window_error_rate(ref_window) if ref_window is not None else None
        cur_rate = _window_error_rate(cur_window) if cur_window is not None else None
        finding: Finding | None = None
        if ref_window is not None and cur_window is not None:
            delta: float | None = cur_rate - ref_rate  # type: ignore[operator]
            if abs(delta) >= threshold:
                score = min(100, round(50 + 50 * abs(delta)))
                finding = Finding(
                    "baseline-drift",
                    _severity(score, resolved),
                    f"Error-rate drift in window {start}: {ref_rate:.1%} -> {cur_rate:.1%} "
                    f"(delta {delta:+.1%}, threshold {threshold:.0%})",
                    cur_window["error_events"],
                    score,
                )
        elif cur_window is not None and cur_window["error_events"] > 0:
            delta = None
            finding = Finding(
                "baseline-new-window",
                _severity(resolved.base_points, resolved),
                f"New window {start} with {cur_window['error_events']} error events has no reference baseline",
                cur_window["error_events"],
                resolved.base_points,
            )
        else:
            delta = None
        if finding is not None:
            findings.append(finding)
        deltas.append({
            "window_start": start,
            "reference_error_rate": ref_rate,
            "current_error_rate": cur_rate,
            "delta": delta,
            "threshold": threshold,
            "finding": finding is not None,
        })
    return findings, deltas
