"""Reusable report serialization for LogLens."""

from __future__ import annotations

import csv
import io
from collections.abc import Mapping, Sequence
from typing import Any


def report_to_csv(report: Mapping[str, Any]) -> str:
    """Serialize an analysis report as deterministic, spreadsheet-friendly CSV.

    The long-form schema keeps summary metrics, level/source aggregates, and
    anomaly findings in one stream without flattening away their meaning.
    """
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("record_type", "name", "value", "severity", "message"))

    for name in ("source", "input_events", "matched_events", "parse_errors", "events"):
        if name in report:
            writer.writerow(("summary", name, report[name], "", ""))

    for level, count in sorted(report.get("levels", {}).items()):
        writer.writerow(("level", level, count, "", ""))
    for source, count in sorted(report.get("sources", {}).items()):
        writer.writerow(("source", source, count, "", ""))

    findings: Sequence[Mapping[str, Any]] = report.get("findings", ())
    for finding in findings:
        writer.writerow((
            "finding",
            finding.get("rule", ""),
            finding.get("count", ""),
            finding.get("severity", ""),
            finding.get("message", ""),
        ))

    return output.getvalue()
