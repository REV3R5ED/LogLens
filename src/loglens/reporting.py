"""Reusable report serialization for LogLens."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Mapping, Sequence
from typing import Any


def report_to_json(report: Mapping[str, Any]) -> str:
    """Serialize an analysis report as deterministic, human-readable JSON."""
    return json.dumps(report, indent=2, sort_keys=True)


def report_to_csv(report: Mapping[str, Any]) -> str:
    """Serialize an analysis report as deterministic, spreadsheet-friendly CSV.

    The long-form schema intentionally carries summary data, effective detection
    configuration, time-window baselines, aggregates, and findings without
    requiring consumers to understand LogLens' internal Python objects.
    """
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("record_type", "name", "value", "severity", "score", "message"))

    for name in ("source", "input_events", "matched_events", "parse_errors", "events"):
        if name in report:
            writer.writerow(("summary", name, report[name], "", "", ""))

    for name, value in sorted(report.get("detection_config", {}).items()):
        writer.writerow(("config", name, value, "", "", ""))

    baseline = report.get("time_baseline")
    if isinstance(baseline, Mapping):
        for name in ("window_minutes", "timestamped_events"):
            if name in baseline:
                writer.writerow(("baseline", name, baseline[name], "", "", ""))
        windows: Sequence[Mapping[str, Any]] = baseline.get("windows", ())
        for window in windows:
            message = json.dumps(window.get("levels", {}), sort_keys=True, separators=(",", ":"))
            writer.writerow((
                "window",
                window.get("start", ""),
                window.get("events", ""),
                "",
                window.get("error_events", ""),
                message,
            ))

    for level, count in sorted(report.get("levels", {}).items()):
        writer.writerow(("level", level, count, "", "", ""))
    for source, count in sorted(report.get("sources", {}).items()):
        writer.writerow(("source", source, count, "", "", ""))

    findings: Sequence[Mapping[str, Any]] = report.get("findings", ())
    for finding in findings:
        writer.writerow((
            "finding",
            finding.get("rule", ""),
            finding.get("count", ""),
            finding.get("severity", ""),
            finding.get("score", ""),
            finding.get("message", ""),
        ))

    return output.getvalue()
