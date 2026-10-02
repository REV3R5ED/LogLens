"""Single-pass streaming analysis pipeline: parse -> filter -> detect.

The pipeline feeds each input line through parsing, filtering, and
incremental aggregation without ever materializing the full event list, so
multi-gigabyte logs stay bounded by distinct sources/messages rather than the
total record count. Rule semantics are identical to the list-based path:
every accumulator produces exactly the same summaries and findings as its
functional counterpart.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .analysis import AnalysisSummary, EventFilter
from .baseline import TimeWindowAccumulator
from .detection import (
    DetectionAccumulator,
    Finding,
    ScoringConfig,
    SourceThresholds,
)
from .field_analysis import FieldCoverageAccumulator
from .model import LogEvent
from .parsers import parse_line
from .source_analysis import SourceHealthAccumulator
from .syslog import parse_rfc5424_line

logger = logging.getLogger("loglens")


@dataclass(slots=True)
class PipelineConfig:
    """Tunable inputs for one streaming analysis run."""

    format: str = "auto"
    levels: set[str] | None = None
    contains: str | None = None
    sources: set[str] | None = None
    error_threshold: int = 5
    repeat_threshold: int = 5
    burst_threshold: int = 5
    burst_window_seconds: int = 60
    scoring: ScoringConfig | None = None
    source_overrides: Mapping[str, SourceThresholds] | None = None
    novelty_known: frozenset[tuple[str | None, str, str]] | None = None
    window_minutes: int | None = None


class StreamAnalyzer:
    """Incremental parse/filter/detect pipeline producing full LogLens reports."""

    def __init__(self, config: PipelineConfig, *, source_name: str) -> None:
        if config.format not in {"auto", "json", "text", "rfc5424"}:
            raise ValueError("format must be one of: auto, json, text, rfc5424")
        self.config = config
        self.source_name = source_name
        self.input_events = 0
        self.parse_errors = 0
        self.matched_events = 0
        self.summary = AnalysisSummary()
        self.detector = DetectionAccumulator()
        self.source_health = SourceHealthAccumulator()
        self.field_coverage = FieldCoverageAccumulator()
        self.windows = (
            TimeWindowAccumulator(window_minutes=config.window_minutes)
            if config.window_minutes is not None
            else None
        )
        self._filter = EventFilter(levels=config.levels, contains=config.contains, sources=config.sources)

    def add_line(self, line: str) -> None:
        """Parse one raw input line and fold it into the running analysis.

        Blank lines are skipped before counting. Any parser failure becomes a
        counted parse error with a debug diagnostic instead of a traceback.
        """
        if not line.strip():
            return
        self.input_events += 1
        try:
            if self.config.format == "rfc5424":
                event = parse_rfc5424_line(line, source=self.source_name)
            else:
                event = parse_line(line, source=self.source_name, format=self.config.format)
        except Exception as exc:
            self.parse_errors += 1
            logger.debug(
                "line %d: parse failed (%s: %s)", self.input_events, type(exc).__name__, exc
            )
            return
        self.add_event(event)

    def add_event(self, event: LogEvent) -> None:
        """Fold one parsed event into the running analysis."""
        if not self._filter.matches(event):
            return
        self.matched_events += 1
        self.summary.add(event)
        self.detector.add(event)
        self.source_health.add(event)
        self.field_coverage.add(event)
        if self.windows is not None:
            self.windows.add(event)

    def findings(self) -> list[Finding]:
        """Evaluate detection rules (plus novelty) over events seen so far."""
        config = self.config
        findings = self.detector.findings(
            error_threshold=config.error_threshold,
            repeat_threshold=config.repeat_threshold,
            burst_threshold=config.burst_threshold,
            burst_window_seconds=config.burst_window_seconds,
            scoring=config.scoring,
            source_overrides=config.source_overrides,
        )
        if config.novelty_known is not None:
            findings.extend(self.detector.novelty_findings(config.novelty_known, scoring=config.scoring))
        return findings

    def detection_config_dict(self) -> dict[str, int]:
        config = self.config
        return {
            "error_threshold": config.error_threshold,
            "repeat_threshold": config.repeat_threshold,
            "burst_threshold": config.burst_threshold,
            "burst_window_seconds": config.burst_window_seconds,
        }

    def build_report(
        self,
        *,
        policy_name: str,
        max_parse_errors: int,
        extra_findings: list[Finding] | None = None,
        baseline_diff: dict[str, Any] | None = None,
        novelty: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assemble the deterministic report dict from accumulated state."""
        config = self.config
        scoring = config.scoring if config.scoring is not None else ScoringConfig()
        findings = [finding.to_dict() for finding in self.findings()]
        if extra_findings:
            findings.extend(finding.to_dict() for finding in extra_findings)
        report: dict[str, Any] = self.summary.to_dict()
        report.update({
            "source": self.source_name,
            "input_events": self.input_events,
            "matched_events": self.matched_events,
            "parse_errors": self.parse_errors,
            "max_parse_errors": max_parse_errors,
            "policy": policy_name,
            "scoring_config": scoring.to_dict(),
            "source_health": [summary.to_dict() for summary in self.source_health.summaries()],
            "field_coverage": self.field_coverage.result(),
            "detection_config": self.detection_config_dict(),
            "findings": findings,
        })
        if config.source_overrides:
            report["source_overrides"] = {
                source: overrides.to_dict()
                for source, overrides in sorted(config.source_overrides.items())
            }
        if self.windows is not None:
            report["time_baseline"] = {
                "window_minutes": self.windows.window_minutes,
                "timestamped_events": self.windows.timestamped_events,
                "windows": self.windows.windows(),
            }
        if baseline_diff is not None:
            report["baseline_diff"] = baseline_diff
        if novelty is not None:
            report["novelty"] = novelty
        return report
