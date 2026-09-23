"""Reusable report serialization for LogLens."""

from __future__ import annotations

import csv
import io
import json
import math
import unicodedata
from collections.abc import Mapping, Sequence
from typing import Any


def report_to_json(report: Mapping[str, Any]) -> str:
    """Serialize an analysis report as deterministic, standards-compliant JSON."""
    return json.dumps(report, indent=2, sort_keys=True, allow_nan=False)


def _compact_json(value: Any) -> str:
    """Serialize machine-readable CSV subfields as strict, deterministic JSON."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _escape_csv_controls(value: str) -> str:
    """Keep untrusted text visually explicit and on one physical CSV row."""
    escapes = {"\n": r"\n", "\r": r"\r", "\t": r"\t"}
    parts: list[str] = []
    for char in value:
        codepoint = ord(char)
        category = unicodedata.category(char)
        if codepoint < 32 or codepoint == 127:
            parts.append(escapes.get(char, f"\\x{codepoint:02x}"))
        elif category in {"Cf", "Zl", "Zp"}:
            escape = "\\u" if codepoint <= 0xFFFF else "\\U"
            width = 4 if codepoint <= 0xFFFF else 8
            parts.append(f"{escape}{codepoint:0{width}x}")
        else:
            parts.append(char)
    return "".join(parts)


def _csv_safe(value: Any) -> Any:
    """Neutralize unsafe spreadsheet text and reject non-finite numeric cells."""
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("CSV reports do not support non-finite numeric values")
    if not isinstance(value, str):
        return value
    formula_like = value.lstrip().startswith(("=", "+", "-", "@"))
    safe = _escape_csv_controls(value)
    return "'" + safe if formula_like else safe


def report_to_csv(report: Mapping[str, Any]) -> str:
    """Serialize an analysis report as deterministic, spreadsheet-friendly CSV."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\r\n")
    writer.writerow(("record_type", "name", "value", "severity", "score", "message"))

    for name in ("source", "input_events", "matched_events", "parse_errors", "max_parse_errors", "events"):
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
            start = _csv_safe(window.get("start", ""))
            end = _csv_safe(window.get("end", ""))
            message = _compact_json(window.get("levels", {}))
            writer.writerow((
                "window", start, _csv_safe(window.get("events", "")),
                "", _csv_safe(window.get("error_events", "")), _csv_safe(message),
            ))
            if end != "":
                writer.writerow(("window_end", start, end, "", "", ""))

    for level, count in sorted(report.get("levels", {}).items()):
        writer.writerow(("level", _csv_safe(level), _csv_safe(count), "", "", ""))
    for source, count in sorted(report.get("sources", {}).items()):
        writer.writerow(("source", _csv_safe(source), _csv_safe(count), "", "", ""))

    source_health: Sequence[Mapping[str, Any]] = report.get("source_health", ())
    for source in source_health:
        levels = _compact_json(source.get("levels", {}))
        writer.writerow((
            "source_health", _csv_safe(source.get("source", "")), _csv_safe(source.get("events", "")),
            _csv_safe(source.get("error_rate", "")), _csv_safe(source.get("error_events", "")), _csv_safe(levels),
        ))

    field_coverage = report.get("field_coverage")
    if isinstance(field_coverage, Mapping):
        if "events" in field_coverage:
            writer.writerow((
                "field_coverage_meta", "events", _csv_safe(field_coverage["events"]), "", "", "",
            ))
        fields = field_coverage.get("fields", {})
        if isinstance(fields, Mapping):
            for field, stats in sorted(fields.items(), key=lambda item: str(item[0])):
                if not isinstance(stats, Mapping):
                    continue
                details: dict[str, Any] = {}
                for name in ("missing", "populated", "populated_rate", "nulls", "null_rate"):
                    if name in stats:
                        details[name] = stats[name]
                types = stats.get("types", {})
                if isinstance(types, Mapping):
                    details["types"] = types
                if "type_drift" in stats:
                    details["type_drift"] = bool(stats["type_drift"])
                for name in (
                    "type_drift_families",
                    "type_drift_family_counts",
                    "type_drift_family_rates",
                ):
                    if name in stats:
                        details[name] = stats[name]
                detail_summary = _compact_json(details) if details else ""
                writer.writerow((
                    "field_coverage", _csv_safe(str(field)), _csv_safe(stats.get("present", "")),
                    "", _csv_safe(stats.get("coverage", "")), _csv_safe(detail_summary),
                ))

    findings: Sequence[Mapping[str, Any]] = report.get("findings", ())
    for finding in findings:
        writer.writerow((
            "finding", _csv_safe(finding.get("rule", "")), _csv_safe(finding.get("count", "")),
            _csv_safe(finding.get("severity", "")), _csv_safe(finding.get("score", "")),
            _csv_safe(finding.get("message", "")),
        ))

    return output.getvalue()
