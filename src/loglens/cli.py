"""Command-line interface for LogLens."""

from __future__ import annotations

import argparse
import gzip
import logging
import sys
import time
from contextlib import nullcontext
from pathlib import Path

from . import __version__
from .baseline import BaselineDiffError, diff_time_windows, load_reference_windows
from .config import (
    ConfigError,
    DetectionPolicy,
    DEFAULT_POLICY,
    load_policies,
    resolve_policy,
)
from .detection import Finding
from .novelty import KnownCorpus, NoveltyError
from .pipeline import PipelineConfig, StreamAnalyzer
from .reporting import report_to_csv, report_to_json, report_to_json_line

logger = logging.getLogger("loglens")

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3}
_PROGRESS_EVERY_LINES = 1000


def _parse_int(value: str, label: str) -> int:
    """Parse an integer CLI value, raising ArgumentTypeError on junk input."""
    try:
        return int(value, 10)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"{label}: expected an integer, got {value!r}") from None


def _parse_float(value: str, label: str) -> float:
    """Parse a float CLI value, raising ArgumentTypeError on junk input."""
    try:
        return float(value)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(f"{label}: expected a number, got {value!r}") from None


def _positive_int(value: str) -> int:
    parsed = _parse_int(value, "threshold")
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = _parse_int(value, "threshold")
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be at least 0")
    return parsed


def _repeat_threshold(value: str) -> int:
    parsed = _parse_int(value, "threshold")
    if parsed < 2:
        raise argparse.ArgumentTypeError("must be at least 2")
    return parsed


def _window_minutes(value: str) -> int:
    parsed = _parse_int(value, "--window-minutes")
    if parsed < 1 or parsed > 1440:
        raise argparse.ArgumentTypeError("must be between 1 and 1440")
    return parsed


def _positive_float(value: str) -> float:
    parsed = _parse_float(value, "--watch-interval")
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def _nonnegative_float(value: str) -> float:
    parsed = _parse_float(value, "--watch-timeout")
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be at least 0")
    return parsed


def _unit_float(value: str) -> float:
    parsed = _parse_float(value, "--baseline-diff-threshold")
    if parsed < 0 or parsed > 1:
        raise argparse.ArgumentTypeError("must be between 0 and 1")
    return parsed


def _configure_logging(*, verbose: bool, info: bool = False) -> None:
    """Route diagnostics to stderr; reports always go to stdout."""
    level = logging.DEBUG if verbose else (logging.INFO if info else logging.WARNING)
    logger.setLevel(level)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("loglens: %(levelname)s: %(message)s"))
    logger.addHandler(handler)


def _open_input(path: Path):
    """Open stdin or a local log, transparently decompressing .gz files."""
    if str(path) == "-":
        return nullcontext(sys.stdin)
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def _resolve_policy(args: argparse.Namespace) -> DetectionPolicy:
    if args.config is None:
        if args.policy is not None:
            raise ConfigError("--policy requires --config")
        return DEFAULT_POLICY
    return resolve_policy(load_policies(args.config), args.policy)


def _resolve_thresholds(args: argparse.Namespace, policy: DetectionPolicy) -> dict[str, int]:
    """Merge explicit CLI flags over the active policy; flags always win."""
    return {
        "error_threshold": args.error_threshold if args.error_threshold is not None else policy.error_threshold,
        "repeat_threshold": args.repeat_threshold if args.repeat_threshold is not None else policy.repeat_threshold,
        "burst_threshold": args.burst_threshold if args.burst_threshold is not None else policy.burst_threshold,
        "burst_window_seconds": args.burst_window_seconds if args.burst_window_seconds is not None else policy.burst_window_seconds,
    }


def _setup_novelty(args: argparse.Namespace) -> tuple[KnownCorpus | None, bool]:
    """Return (corpus, learn_mode) for the novelty rule; missing store starts empty."""
    if args.novelty_store is None:
        if args.novelty_learn:
            raise ConfigError("--novelty-learn requires --novelty-store")
        return None, False
    try:
        corpus = KnownCorpus.load(args.novelty_store)
    except NoveltyError as exc:
        raise ConfigError(str(exc)) from exc
    return corpus, args.novelty_learn


def _build_analyzer(
    args: argparse.Namespace,
    policy: DetectionPolicy,
    *,
    source_name: str,
    novelty_known: frozenset | None,
) -> StreamAnalyzer:
    thresholds = _resolve_thresholds(args, policy)
    return StreamAnalyzer(
        PipelineConfig(
            format=args.format,
            levels=set(args.levels) if args.levels else None,
            contains=args.contains,
            sources=set(args.sources) if args.sources else None,
            scoring=policy.scoring,
            source_overrides=policy.sources or None,
            novelty_known=novelty_known,
            window_minutes=args.window_minutes,
            **thresholds,
        ),
        source_name=source_name,
    )


def _baseline_diff_section(
    args: argparse.Namespace, analyzer: StreamAnalyzer
) -> tuple[list[Finding], dict | None]:
    """Diff current time windows against a saved reference report."""
    if args.baseline_diff is None:
        return [], None
    if args.window_minutes is None:
        raise ConfigError("--baseline-diff requires --window-minutes")
    try:
        reference_windows, reference_minutes = load_reference_windows(args.baseline_diff)
    except BaselineDiffError as exc:
        raise ConfigError(str(exc)) from exc
    if reference_minutes is not None and reference_minutes != args.window_minutes:
        logger.warning(
            "reference baseline used window_minutes=%s; current run uses %s",
            reference_minutes, args.window_minutes,
        )
    current_windows = analyzer.windows.windows() if analyzer.windows is not None else []
    try:
        findings, deltas = diff_time_windows(
            current_windows,
            reference_windows,
            threshold=args.baseline_diff_threshold,
            scoring=analyzer.config.scoring,
        )
    except BaselineDiffError as exc:
        raise ConfigError(str(exc)) from exc
    section = {
        "reference": str(args.baseline_diff),
        "threshold": args.baseline_diff_threshold,
        "compared_windows": len(deltas),
        "drifted_windows": sum(1 for delta in deltas if delta["finding"]),
        "deltas": deltas,
    }
    return findings, section


def _print_report(report: dict, output_format: str, window_minutes: int | None) -> None:
    if output_format == "json":
        print(report_to_json(report))
    elif output_format == "csv":
        print(report_to_csv(report), end="")
    else:
        print(f"LogLens: {report['source']}")
        print(f"Input: {report['input_events']} | Matched: {report['matched_events']} | Parse errors: {report['parse_errors']}")
        for level, count in report["levels"].items():
            print(f"{level:>8}: {count}")
        if report["source_health"]:
            print("Source health:")
            for source in report["source_health"]:
                print(f"  {source['source']}: {source['events']} events | {source['error_events']} errors | {source['error_rate']:.1%} error rate")
        if "time_baseline" in report:
            baseline = report["time_baseline"]
            print(f"Time windows: {len(baseline['windows'])} x {window_minutes}m | Timestamped: {baseline['timestamped_events']}")
        if "baseline_diff" in report:
            diff = report["baseline_diff"]
            drifted = [delta for delta in diff["deltas"] if delta["finding"]]
            print(f"Baseline diff vs {diff['reference']}: {diff['drifted_windows']} drifted of {diff['compared_windows']} windows")
            for delta in drifted:
                if delta["delta"] is None:
                    print(f"  {delta['window_start']}: no reference window")
                else:
                    print(f"  {delta['window_start']}: {delta['reference_error_rate']:.1%} -> {delta['current_error_rate']:.1%} (delta {delta['delta']:+.1%})")
        if report["findings"]:
            print("Findings:")
            for finding in report["findings"]:
                print(f"  [{finding['severity']}] {finding['rule']}: {finding['message']} ({finding['count']})")


def _failure_exit_code(findings: list[dict], fail_on_severity: str | None) -> int:
    if fail_on_severity is not None:
        threshold = _SEVERITY_RANK[fail_on_severity]
        if any(_SEVERITY_RANK.get(finding["severity"], 0) >= threshold for finding in findings):
            return 3
    return 0


def _analyze(args: argparse.Namespace) -> int:
    policy = _resolve_policy(args)
    corpus, learn_mode = _setup_novelty(args)
    source_name = "<stdin>" if str(args.path) == "-" else str(args.path)
    analyzer = _build_analyzer(
        args, policy,
        source_name=source_name,
        novelty_known=corpus.keys() if corpus is not None and not learn_mode else None,
    )
    with _open_input(args.path) as handle:
        for line in handle:
            analyzer.add_line(line)
            if args.progress and analyzer.input_events % _PROGRESS_EVERY_LINES == 0:
                logger.info(
                    "processed %d input lines (%d matched, %d parse errors)",
                    analyzer.input_events, analyzer.matched_events, analyzer.parse_errors,
                )
    if args.progress:
        logger.info(
            "processed %d input lines (%d matched, %d parse errors): done",
            analyzer.input_events, analyzer.matched_events, analyzer.parse_errors,
        )

    novelty_section: dict | None = None
    if corpus is not None:
        if learn_mode:
            new_keys = corpus.learn_counts(analyzer.detector.message_counts())
            try:
                corpus.save(args.novelty_store)
            except NoveltyError as exc:
                raise ConfigError(str(exc)) from exc
            logger.info(
                "novelty store %s: learned %d new message keys (%d total)",
                args.novelty_store, new_keys, len(corpus),
            )
            novelty_section = {
                "store": str(args.novelty_store),
                "mode": "learn",
                "known_messages": len(corpus),
                "learned_messages": new_keys,
            }
        else:
            novelty_section = {
                "store": str(args.novelty_store),
                "mode": "detect",
                "known_messages": len(corpus),
            }

    extra_findings, baseline_section = _baseline_diff_section(args, analyzer)
    report = analyzer.build_report(
        policy_name=policy.name,
        max_parse_errors=args.max_parse_errors,
        extra_findings=extra_findings,
        baseline_diff=baseline_section,
        novelty=novelty_section,
    )
    _print_report(report, args.output_format, args.window_minutes)
    if analyzer.parse_errors > args.max_parse_errors:
        return 2
    return _failure_exit_code(report["findings"], args.fail_on_severity)


class _FileTailer:
    """Track a growing file by byte offset, yielding complete lines per poll.

    Handles truncation/rotation by restarting from the beginning, and holds
    back a trailing partial line until its newline arrives.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._offset = 0
        self._carry = b""

    def poll(self) -> list[str]:
        try:
            size = self._path.stat().st_size
        except OSError as exc:
            logger.warning("cannot stat %s: %s", self._path, exc)
            return []
        if size < self._offset:
            logger.info("%s truncated; restarting from the beginning", self._path)
            self._offset = 0
            self._carry = b""
        try:
            with self._path.open("rb") as handle:
                handle.seek(self._offset)
                chunk = handle.read()
        except OSError as exc:
            logger.warning("cannot read %s: %s", self._path, exc)
            return []
        data = self._carry + chunk
        self._carry = b""
        if not data or data.endswith(b"\n"):
            complete = data
        else:
            *parts, last = data.split(b"\n")
            complete = b"\n".join(parts) + b"\n" if parts else b""
            self._carry = last
        # The file offset always advances over newly read bytes; the held-back
        # partial line is tracked in memory so it is never re-read or lost.
        self._offset += len(chunk)
        return complete.decode("utf-8", errors="replace").splitlines()


def _emit_watch_findings(
    fresh: list[Finding], scan: int, analyzer: StreamAnalyzer, output_format: str
) -> None:
    if output_format == "json":
        print(report_to_json_line({
            "watch_scan": scan,
            "matched_events": analyzer.matched_events,
            "parse_errors": analyzer.parse_errors,
            "new_findings": [finding.to_dict() for finding in fresh],
        }))
    else:
        for finding in fresh:
            print(f"  [{finding.severity}] {finding.rule}: {finding.message} ({finding.count})")


def _follow(args: argparse.Namespace, *, _max_scans: int | None = None) -> int:
    """Watch a file for appended lines, emitting findings as thresholds trip."""
    policy = _resolve_policy(args)
    corpus, _ = _setup_novelty(args)
    args.path.stat()  # fail fast on missing/unreadable files
    analyzer = _build_analyzer(
        args, policy,
        source_name=str(args.path),
        novelty_known=corpus.keys() if corpus is not None else None,
    )
    tailer = _FileTailer(args.path)
    seen: set[tuple[str, str]] = set()
    tripped = False
    scan = 0
    deadline = None if args.watch_timeout is None else time.monotonic() + args.watch_timeout
    fail_rank = _SEVERITY_RANK[args.fail_on_severity] if args.fail_on_severity else None
    logger.info("following %s (poll every %.2fs)", args.path, args.watch_interval)
    try:
        while True:
            for line in tailer.poll():
                analyzer.add_line(line)
            if analyzer.parse_errors > args.max_parse_errors:
                logger.error(
                    "parse error budget exceeded: %d > %d",
                    analyzer.parse_errors, args.max_parse_errors,
                )
                return 2
            fresh = [
                finding for finding in analyzer.findings()
                if (finding.rule, finding.message) not in seen
            ]
            for finding in fresh:
                seen.add((finding.rule, finding.message))
            if fresh:
                _emit_watch_findings(fresh, scan, analyzer, args.output_format)
                if fail_rank is not None and any(
                    _SEVERITY_RANK.get(finding.severity, 0) >= fail_rank for finding in fresh
                ):
                    tripped = True
            scan += 1
            if _max_scans is not None and scan >= _max_scans:
                break
            if deadline is not None and time.monotonic() >= deadline:
                break
            time.sleep(args.watch_interval)
    except KeyboardInterrupt:
        logger.info("watch interrupted after %d scans", scan)
    logger.info(
        "watch finished: %d scans, %d input lines, %d matched, %d parse errors",
        scan, analyzer.input_events, analyzer.matched_events, analyzer.parse_errors,
    )
    return 3 if tripped else 0


def _validate_follow_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if str(args.path) == "-":
        parser.error("--follow requires a file path, not '-' (stdin)")
    if args.path.suffix.lower() == ".gz":
        parser.error("--follow does not support .gz files")
    if args.output_format == "csv":
        parser.error("--follow supports text and JSON output only, not --csv")
    if args.baseline_diff is not None:
        parser.error("--baseline-diff is not supported with --follow")
    if args.window_minutes is not None:
        parser.error("--window-minutes is not supported with --follow")
    if args.novelty_learn:
        parser.error("--novelty-learn is not supported with --follow")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="loglens", description="Lightweight defensive log analysis")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)
    analyze = subparsers.add_parser("analyze", help="summarize a local log file or stdin")
    analyze.add_argument("path", type=Path, help="local log path (.gz supported), or '-' to read from stdin")
    analyze.add_argument("--format", choices=("auto", "json", "text", "rfc5424"), default="auto", help="input format; use rfc5424 for strict RFC 5424 syslog parsing")
    analyze.add_argument("--level", action="append", dest="levels", help="include only this level; repeat for multiple levels")
    analyze.add_argument("--contains", help="include only events whose message contains this text")
    analyze.add_argument("--source", action="append", dest="sources", help="include only this logical source; repeat for multiple sources (case-insensitive)")
    analyze.add_argument("--error-threshold", type=_positive_int, default=None, help="matched ERROR/CRITICAL/FATAL events required for an elevated-errors finding (default: 5, or the --config policy value)")
    analyze.add_argument("--repeat-threshold", type=_repeat_threshold, default=None, help="identical matched messages required for a repeated-message finding (default: 5, minimum: 2, or the --config policy value)")
    analyze.add_argument("--burst-threshold", type=_repeat_threshold, default=None, help="timestamped errors from one source required for an error-burst finding (default: 5, minimum: 2, or the --config policy value)")
    analyze.add_argument("--burst-window-seconds", type=_positive_int, default=None, help="sliding window used for error-burst detection in seconds (default: 60, or the --config policy value)")
    analyze.add_argument("--window-minutes", type=_window_minutes, help="include deterministic UTC time-window baselines (1-1440 minutes; timestamped events only)")
    analyze.add_argument("--max-parse-errors", type=_nonnegative_int, default=0, help="allow up to this many malformed records before returning exit code 2 (default: 0)")
    analyze.add_argument("--config", type=Path, help="TOML or JSON config file with named detection policies (see --policy)")
    analyze.add_argument("--policy", help="named policy from --config to apply (default: the 'default' policy, or the only policy defined)")
    analyze.add_argument("--novelty-store", type=Path, help="JSON file persisting known (source, level, message) keys; enables novel-message detection")
    analyze.add_argument("--novelty-learn", action="store_true", help="update the novelty store from this run instead of emitting novel-message findings")
    analyze.add_argument("--baseline-diff", type=Path, help="reference LogLens JSON report to diff error-rate drift against (requires --window-minutes)")
    analyze.add_argument("--baseline-diff-threshold", type=_unit_float, default=0.2, help="absolute error-rate delta that trips a baseline-drift finding, as a 0-1 fraction (default: 0.2)")
    analyze.add_argument("--follow", "--watch", dest="follow", action="store_true", help="watch the file for appended lines and emit findings as thresholds trip")
    analyze.add_argument("--watch-interval", type=_positive_float, default=1.0, metavar="SECONDS", help="poll interval for --follow in seconds (default: 1.0)")
    analyze.add_argument("--watch-timeout", type=_nonnegative_float, default=None, metavar="SECONDS", help="stop --follow after this many seconds (default: run until interrupted)")
    analyze.add_argument("-v", "--verbose", action="store_true", help="enable debug diagnostics on stderr")
    analyze.add_argument("--progress", action="store_true", help="log input progress to stderr while streaming")
    failure = analyze.add_mutually_exclusive_group()
    failure.add_argument("--fail-on-finding", action="store_const", const="low", dest="fail_on_severity", help="return exit code 3 when one or more anomaly findings are emitted")
    failure.add_argument("--fail-on-severity", choices=("low", "medium", "high"), help="return exit code 3 when a finding reaches this severity or higher")
    output = analyze.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_const", const="json", dest="output_format", help="emit a JSON report")
    output.add_argument("--csv", action="store_const", const="csv", dest="output_format", help="emit a CSV report")
    analyze.set_defaults(output_format="text")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _configure_logging(verbose=args.verbose, info=args.progress or args.follow)
    if args.command == "analyze":
        try:
            if args.follow:
                _validate_follow_args(parser, args)
                return _follow(args)
            return _analyze(args)
        except (ConfigError, NoveltyError, BaselineDiffError) as exc:
            logger.error("%s", exc)
            return 1
        except OSError as exc:
            logger.error("%s", exc)
            return 1
        except Exception as exc:
            if args.verbose:
                logger.exception("unexpected failure")
            else:
                logger.error("unexpected failure: %s: %s", type(exc).__name__, exc)
            return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
