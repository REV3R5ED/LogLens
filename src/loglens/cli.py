"""Command-line interface for LogLens."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .analysis import filter_events, summarize
from .parsers import parse_line


def _analyze(path: Path, format: str, json_output: bool, levels: set[str] | None, contains: str | None) -> int:
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
    report = summarize(matched).to_dict()
    report.update({"source": str(path), "input_events": total_input, "matched_events": len(matched), "parse_errors": parse_errors})
    if json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"LogLens: {path}")
        print(f"Input: {total_input} | Matched: {len(matched)} | Parse errors: {parse_errors}")
        for level, count in report["levels"].items():
            print(f"{level:>8}: {count}")
    return 0 if parse_errors == 0 else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loglens", description="Lightweight defensive log analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="summarize a local log file")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--format", choices=("auto", "json", "text"), default="auto")
    analyze.add_argument("--level", action="append", dest="levels", help="include only this level; repeat for multiple levels")
    analyze.add_argument("--contains", help="include only events whose message contains this text")
    analyze.add_argument("--json", action="store_true", dest="json_output", help="emit a JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        try:
            return _analyze(args.path, args.format, args.json_output, set(args.levels) if args.levels else None, args.contains)
        except OSError as exc:
            print(f"loglens: {exc}", file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
