"""Command-line interface for LogLens."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from .parsers import parse_line


def _analyze(path: Path, format: str, json_output: bool) -> int:
    counts: Counter[str] = Counter()
    total = 0
    parse_errors = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            total += 1
            try:
                event = parse_line(line, source=str(path), format=format)
            except (ValueError, json.JSONDecodeError):
                parse_errors += 1
                continue
            counts[event.level] += 1

    report = {"source": str(path), "events": total, "levels": dict(sorted(counts.items())), "parse_errors": parse_errors}
    if json_output:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"LogLens: {path}")
        print(f"Events: {total} | Parse errors: {parse_errors}")
        for level, count in sorted(counts.items()):
            print(f"{level:>8}: {count}")
    return 0 if parse_errors == 0 else 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loglens", description="Lightweight defensive log analysis")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="summarize a local log file")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--format", choices=("auto", "json", "text"), default="auto")
    analyze.add_argument("--json", action="store_true", dest="json_output", help="emit a JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "analyze":
        try:
            return _analyze(args.path, args.format, args.json_output)
        except OSError as exc:
            print(f"loglens: {exc}", file=sys.stderr)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
