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


def _csv_safe(value: Any) -> Any:
    """Neutralize spreadsheet formula prefixes in untrusted text cells."""
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def report_to_csv(report: Mapping[str, Any]) -> str:
    """Serialize an analysis report as deterministic, spreadsheet-friendly CSV.

    The long-form schema intentionally carries summary data, effective detection
    configuration, time-window baselines, aggregates, and findings without
    requiring consumers to understand LogLens' internal Python objects. Text
    cells that could be interpreted as spreadsheet formulas are neutralized.
    """
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("record_type", "name", "value", "severity", "score", "message"))

    for name in ("source", "input_events", "matched_events", "parse_errors", "events"):
        if name in report:
            writer.writerow(("summary", name, _csv_safe(report[name]), "", "", ""))

    for name, value in sorted(report.get("detection_config", {}).items()):
        writer.writerow(("config", _csv_safe(name), _csv_safe(value), "", "", ""))

    baseline = report.get("time_baseline")
    if isinstance(baseline, Mapping):
        for name in ("window_minutes", "timestamped_events"):
            if name in baseline:
                writer.writerow(("baseline", name, _csv_safe(baseline[name]), "", "", ""))
        windows: Sequence[Mapping[str, Any]] = baseline.get("windows", ())
        for window in windows:
            message = json.dumps(window.get("levels", {}), sort_keys=True, separators=(",", ":"))
            writer.writerow((
                "window",
                _csv_safe(window.get("start", "")),
                _csv_safe(window.get("events", "")),
                "",
                _csv_safe(window.get("error_events", "")),
                _csv_safe(message),
            ))

    for level, count in sorted(report.get("levels", {}).items()):
        writer.writerow(("level", _csv_safe(level), _csv_safe(count), "", "", ""))
    for source, count in sorted(report.get("sources", {}).items()):
        writer.writerow(("source", _csv_safe(source), _csv_safe(count), "", "", ""))

    findings: Sequence[Mapping[str, Any]] = report.get("findings", ())
    for finding in findings:
        writer.writerow((
            "finding",
            _csv_safe(finding.get("rule", "")),
            _csv_safe(finding.get("count", "")),
            _csv_safe(finding.get("severity", "")),
            _csv_safe(finding.get("score", "")),
            _csv_safe(finding.get("message", "")),
        ))

    return output.getvalue()
