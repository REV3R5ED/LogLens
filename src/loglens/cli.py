"""Command-line interface for LogLens."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analysis import filter_events, summarize, summarize_sources
from .baseline import build_time_windows
from .detection import detect_anomalies
from .parsers import parse_line
from .reporting import report_to_csv, report_to_json


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _repeat_threshold(value: str) -> int:
    parsed = int(value)
    if parsed < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return parsed


def _window_minutes(value: str) -> int:
    parsed = int(value)
    if parsed < 1 or parsed > 1440:
        raise argparse.ArgumentTypeError("must be between 1 and 1440")
    return parsed


def _analyze(path: Path, format: str, output_format: str, levels: set[str] | None, contains: str | None, error_threshold: int, repeat_threshold: int, burst_threshold: int, burst_window_seconds: int, window_minutes: int | None, fail_on_finding: bool) -> int:
    events = []
    total_input = 0
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            total_input += 1
            try:
                events.append(parse_line(line, source=str(path), format=format))
            except (ValueError, json.JSONDecodeError):
                parse_errors += 1

    matched = filter_events(events, levels=levels, contains=contains)
    findings = [finding.to_dict() for finding in detect_anomalies(matched, error_threshold=error_threshold, repeat_threshold=repeat_threshold, burst_threshold=burst_threshold, burst_window_seconds=burst_window_seconds)]
    report = summarize(matched).to_dict()
    report.update({
        "source": str(path), "input_events": total_input, "matched_events": len(matched), "parse_errors": parse_errors,
        "source_health": [summary.to_dict() for summary in summarize_sources(matched)],
        "detection_config": {"error_threshold": error_threshold, "repeat_threshold": repeat_threshold, "burst_threshold": burst_threshold, "burst_window_seconds": burst_window_seconds},
        "findings": findings,
    })
    if window_minutes is not None:
        report["time_baseline"] = {"window_minutes": window_minutes, "timestamped_events": sum(event.timestamp is not None for event in matched), "windows": build_time_windows(matched, window_minutes=window_minutes)}
    if output_format == "json":
        print(report_to_json(report))
    elif output_format == "csv":
        print(report_to_csv(report), end="")
    else:
        print(f"LogLens: {path}")
        print(f"Input: {total_input} | Matched: {len(matched)} | Parse errors: {parse_errors}")
        for level, count in report["levels"].items(): print(f"{level:>8}: {count}")
        if report["source_health"]:
            print("Source health:")
            for source in report["source_health"]: print(f"  {source['source']}: {source['events']} events | {source['error_events']} errors | {source['error_rate']:.1%} error rate")
        if "time_baseline" in report:
            baseline = report["time_baseline"]
            print(f"Time windows: {len(baseline['windows'])} x {window_minutes}m | Timestamped: {baseline['timestamped_events']}")
        if findings:
            print("Findings:")
            for finding in findings: print(f"  [{finding['severity']}] {finding['rule']}: {finding['message']} ({finding['count']})")
    if parse_errors: return 2
    if fail_on_finding and findings: return 3
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loglens", description="Lightweight defensive log analysis")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="summarize a local log file")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--format", choices=("auto", "json", "text"), default="auto")
    analyze.add_argument("--level", action="append", dest="levels", help="include only this level; repeat for multiple levels")
    analyze.add_argument("--contains", help="include only events whose message contains this text")
    analyze.add_argument("--error-threshold", type=_positive_int, default=5, help="matched ERROR/CRITICAL/FATAL events required for an elevated-errors finding (default: 5)")
    analyze.add_argument("--repeat-threshold", type=_repeat_threshold, default=5, help="identical matched messages required for a repeated-message finding (default: 5, minimum: 2)")
    analyze.add_argument("--burst-threshold", type=_repeat_threshold, default=5, help="timestamped error events from one source required for an error-burst finding (default: 5, minimum: 2)")
    analyze.add_argument("--burst-window-seconds", type=_positive_int, default=60, help="sliding window used for error-burst detection in seconds (default: 60)")
    analyze.add_argument("--window-minutes", type=_window_minutes, help="include deterministic UTC time-window baselines (1-1440 minutes; timestamped events only)")
    analyze.add_argument("--fail-on-finding", action="store_true", help="return exit code 3 when one or more anomaly findings are emitted")
    output = analyze.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_const", const="json", dest="output_format", help="emit a JSON report")
    output.add_argument("--csv", action="store_const", const="csv", dest="output_format", help="emit a CSV report")
    analyze.set_defaults(output_format="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        try:
            return _analyze(args.path, args.format, args.output_format, set(args.levels) if args.levels else None, args.contains, args.error_threshold, args.repeat_threshold, args.burst_threshold, args.burst_window_seconds, args.window_minutes, args.fail_on_finding)
        except OSError as exc:
            print(f"loglens: {exc}", file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
