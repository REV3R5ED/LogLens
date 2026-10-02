"""Live tail mode: re-scan on file growth and emit findings as thresholds trip."""

import json
import threading
import time

import pytest

from loglens.cli import _FileTailer, build_parser, main


def _write_lines(path, lines):
    with path.open("a", encoding="utf-8") as handle:
        handle.writelines(lines)


def _run_follow(log, *extra, timeout=1.0, interval=0.02):
    """Run --follow in a thread-safe way; returns (exit_code, stdout, stderr)."""
    import io
    from contextlib import redirect_stderr, redirect_stdout

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main([
            "analyze", str(log), "--follow",
            "--watch-interval", str(interval), "--watch-timeout", str(timeout),
            *extra,
        ])
    return code, out.getvalue(), err.getvalue()


def test_follow_emits_findings_as_thresholds_trip(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("INFO starting\n", encoding="utf-8")

    def writer():
        time.sleep(0.1)
        _write_lines(log, ["ERROR boom\n"] * 6)

    thread = threading.Thread(target=writer)
    thread.start()
    code, out, err = _run_follow(log, "--error-threshold", "5", "--repeat-threshold", "5", "--json")
    thread.join()
    assert code == 0
    scans = [json.loads(line) for line in out.splitlines() if line.strip()]
    assert scans, "expected at least one scan emitting new findings"
    rules = {finding["rule"] for scan in scans for finding in scan["new_findings"]}
    assert rules == {"elevated-errors", "repeated-message"}
    assert all(scan["watch_scan"] >= 0 for scan in scans)


def test_follow_does_not_reemit_unchanged_findings(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("ERROR boom\n" * 6, encoding="utf-8")

    def writer():
        time.sleep(0.1)
        _write_lines(log, ["INFO unrelated\n"] * 3)

    thread = threading.Thread(target=writer)
    thread.start()
    code, out, err = _run_follow(
        log, "--error-threshold", "5", "--repeat-threshold", "5", "--json", timeout=0.6
    )
    thread.join()
    assert code == 0
    scans = [json.loads(line) for line in out.splitlines() if line.strip()]
    # The tripped findings are emitted exactly once despite later scans.
    assert len(scans) == 1
    assert len(scans[0]["new_findings"]) == 2


def test_follow_text_output_lists_findings(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("ERROR boom\n" * 6, encoding="utf-8")
    code, out, err = _run_follow(log, "--error-threshold", "5", "--repeat-threshold", "5", timeout=0.3)
    assert code == 0
    assert "elevated-errors" in out
    assert "repeated-message" in out
    assert "loglens: INFO: following" in err


def test_follow_fail_on_severity_returns_three(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("ERROR boom\n" * 10, encoding="utf-8")
    code, out, err = _run_follow(
        log, "--error-threshold", "2", "--repeat-threshold", "2",
        "--fail-on-severity", "medium", "--json", timeout=0.3,
    )
    assert code == 3


def test_follow_below_severity_gate_stays_zero(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("ERROR boom\nERROR boom\n", encoding="utf-8")
    code, out, err = _run_follow(
        log, "--error-threshold", "2", "--repeat-threshold", "2",
        "--fail-on-severity", "high", "--json", timeout=0.3,
    )
    assert code == 0


def test_follow_parse_error_budget_returns_two(tmp_path):
    log = tmp_path / "events.jsonl"
    log.write_text('{"level":"INFO","message":"ok"}\n{bad}\n', encoding="utf-8")
    code, out, err = _run_follow(
        log, "--format", "json", "--max-parse-errors", "0", "--json", timeout=0.3
    )
    assert code == 2
    assert "parse error budget exceeded" in err


def test_follow_missing_file_is_operational_error(tmp_path):
    code, out, err = _run_follow(tmp_path / "missing.log", timeout=0.3)
    assert code == 1
    assert out == ""
    assert "loglens: ERROR:" in err


@pytest.mark.parametrize(
    "extra",
    [
        ["--format", "json", "--baseline-diff", "ref.json"],
        ["--window-minutes", "5"],
        ["--novelty-learn", "--novelty-store", "corpus.json"],
        ["--csv"],
    ],
)
def test_follow_rejects_incompatible_options(tmp_path, extra):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["analyze", str(log), "--follow", *extra])
    assert exc.value.code == 2


def test_follow_rejects_stdin_and_gz_and_csv(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        main(["analyze", "-", "--follow"])
    assert exc.value.code == 2
    gz = tmp_path / "app.log.gz"
    gz.write_bytes(b"")
    with pytest.raises(SystemExit) as exc:
        main(["analyze", str(gz), "--follow"])
    assert exc.value.code == 2
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    with pytest.raises(SystemExit) as exc:
        main(["analyze", str(log), "--follow", "--csv"])
    assert exc.value.code == 2


def test_file_tailer_reads_appends_and_holds_partial_lines(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("", encoding="utf-8")
    tailer = _FileTailer(log)
    assert tailer.poll() == []
    with log.open("ab") as handle:
        handle.write("partial".encode("utf-8"))
    assert tailer.poll() == []  # no newline yet: held back
    with log.open("ab") as handle:
        handle.write(b" line\nsecond\n")
    assert tailer.poll() == ["partial line", "second"]
    assert tailer.poll() == []


def test_file_tailer_restarts_after_truncation(tmp_path):
    log = tmp_path / "app.log"
    log.write_text("a\nb\n", encoding="utf-8")
    tailer = _FileTailer(log)
    assert tailer.poll() == ["a", "b"]
    log.write_text("c\n", encoding="utf-8")  # rotation/truncation
    assert tailer.poll() == ["c"]


def test_watch_alias_enables_follow():
    args = build_parser().parse_args(["analyze", "app.log", "--watch"])
    assert args.follow is True
