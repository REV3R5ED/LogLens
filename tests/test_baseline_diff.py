"""Baseline diff: compare current time windows against a saved reference report."""

import json

import pytest

from loglens.baseline import BaselineDiffError, diff_time_windows, load_reference_windows
from loglens.cli import main


def _window(start, events, error_events):
    return {"start": start, "end": start, "events": events,
            "error_events": error_events, "levels": {}}


def test_drift_finding_uses_transparent_score_and_severity():
    current = [_window("2026-09-15T10:00:00+00:00", 6, 2)]  # 33.3% vs 0%
    reference = [_window("2026-09-15T10:00:00+00:00", 4, 0)]
    findings, deltas = diff_time_windows(current, reference, threshold=0.2)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule == "baseline-drift"
    assert finding.count == 2
    # score = min(100, round(50 + 50 * 1/3)) = 67 -> medium
    assert finding.score == 67
    assert finding.severity == "medium"
    assert "33.3%" in finding.message and "delta +33.3%" in finding.message
    assert deltas[0]["finding"] is True
    assert deltas[0]["delta"] == pytest.approx(1 / 3)


def test_large_drift_reaches_high_severity():
    current = [_window("2026-09-15T10:00:00+00:00", 4, 4)]  # 100% vs 0%
    reference = [_window("2026-09-15T10:00:00+00:00", 4, 0)]
    findings, _ = diff_time_windows(current, reference, threshold=0.2)
    assert findings[0].score == 100
    assert findings[0].severity == "high"


def test_sub_threshold_drift_produces_no_finding_but_records_delta():
    current = [_window("2026-09-15T10:00:00+00:00", 10, 1)]  # 10% vs 0%
    reference = [_window("2026-09-15T10:00:00+00:00", 10, 0)]
    findings, deltas = diff_time_windows(current, reference, threshold=0.2)
    assert findings == []
    assert deltas[0]["finding"] is False
    assert deltas[0]["delta"] == pytest.approx(0.1)


def test_new_window_with_errors_is_flagged_low():
    current = [_window("2026-09-15T10:05:00+00:00", 3, 2)]
    findings, deltas = diff_time_windows(current, [], threshold=0.2)
    assert len(findings) == 1
    assert findings[0].rule == "baseline-new-window"
    assert findings[0].severity == "low"
    assert findings[0].count == 2
    assert deltas[0]["reference_error_rate"] is None


def test_new_window_without_errors_is_quiet():
    current = [_window("2026-09-15T10:05:00+00:00", 3, 0)]
    findings, deltas = diff_time_windows(current, [], threshold=0.2)
    assert findings == []
    assert deltas[0]["finding"] is False


def test_vanished_window_records_delta_without_finding():
    findings, deltas = diff_time_windows([], [_window("2026-09-15T10:00:00+00:00", 4, 1)], threshold=0.2)
    assert findings == []
    assert deltas[0]["current_error_rate"] is None
    assert deltas[0]["finding"] is False


def test_threshold_bounds_are_validated():
    with pytest.raises(BaselineDiffError):
        diff_time_windows([], [], threshold=1.5)
    with pytest.raises(BaselineDiffError):
        diff_time_windows([], [], threshold="0.2")


def test_load_reference_windows_accepts_full_report_and_bare_windows(tmp_path):
    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "time_baseline": {
            "window_minutes": 5,
            "windows": [_window("2026-09-15T10:00:00+00:00", 4, 1)],
        }
    }), encoding="utf-8")
    windows, minutes = load_reference_windows(report)
    assert minutes == 5
    assert windows[0]["events"] == 4

    bare = tmp_path / "bare.json"
    bare.write_text(json.dumps({"windows": [_window("2026-09-15T10:00:00+00:00", 2, 0)]}), encoding="utf-8")
    windows, minutes = load_reference_windows(bare)
    assert minutes is None
    assert windows[0]["error_events"] == 0


def test_load_reference_windows_rejects_garbage(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(BaselineDiffError, match="not found"):
        load_reference_windows(missing)
    bad = tmp_path / "bad.json"
    bad.write_text("{oops", encoding="utf-8")
    with pytest.raises(BaselineDiffError, match="invalid JSON"):
        load_reference_windows(bad)
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"findings": []}), encoding="utf-8")
    with pytest.raises(BaselineDiffError, match="no time_baseline.windows or windows"):
        load_reference_windows(empty)


def _write_events(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")


def test_cli_baseline_diff_flags_drift(tmp_path, capsys):
    ref = tmp_path / "ref.jsonl"
    _write_events(ref, [
        {"timestamp": "2026-09-15T10:01:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:02:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:03:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:04:00Z", "level": "INFO", "message": "ok", "source": "api"},
    ])
    cur = tmp_path / "cur.jsonl"
    _write_events(cur, [
        {"timestamp": "2026-09-15T10:01:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:02:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:03:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:04:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:01:30Z", "level": "ERROR", "message": "boom", "source": "api"},
        {"timestamp": "2026-09-15T10:02:30Z", "level": "ERROR", "message": "boom", "source": "api"},
    ])
    reference = tmp_path / "reference.json"
    assert main(["analyze", str(ref), "--format", "json", "--window-minutes", "5", "--json"]) == 0
    reference.write_text(capsys.readouterr().out, encoding="utf-8")

    exit_code = main([
        "analyze", str(cur), "--format", "json", "--window-minutes", "5",
        "--baseline-diff", str(reference), "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    drift = [f for f in report["findings"] if f["rule"] == "baseline-drift"]
    assert len(drift) == 1
    assert drift[0]["severity"] == "medium"
    assert report["baseline_diff"]["drifted_windows"] == 1
    assert report["baseline_diff"]["compared_windows"] == 1
    assert report["baseline_diff"]["reference"] == str(reference)
    assert report["baseline_diff"]["threshold"] == 0.2


def test_cli_baseline_diff_text_output_handles_new_windows(tmp_path, capsys):
    ref = tmp_path / "ref.jsonl"
    _write_events(ref, [
        {"timestamp": "2026-09-15T10:01:00Z", "level": "INFO", "message": "ok", "source": "api"},
    ])
    cur = tmp_path / "cur.jsonl"
    _write_events(cur, [
        {"timestamp": "2026-09-15T10:01:00Z", "level": "INFO", "message": "ok", "source": "api"},
        {"timestamp": "2026-09-15T10:06:00Z", "level": "ERROR", "message": "boom", "source": "api"},
    ])
    reference = tmp_path / "reference.json"
    assert main(["analyze", str(ref), "--format", "json", "--window-minutes", "5", "--json"]) == 0
    reference.write_text(capsys.readouterr().out, encoding="utf-8")

    exit_code = main([
        "analyze", str(cur), "--format", "json", "--window-minutes", "5",
        "--baseline-diff", str(reference),
    ])
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "baseline-new-window" in out
    assert "no reference window" in out


def test_cli_baseline_diff_requires_window_minutes(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--baseline-diff", "ref.json"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--baseline-diff requires --window-minutes" in captured.err


def test_cli_baseline_diff_missing_reference_is_structured_error(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--window-minutes", "5",
        "--baseline-diff", str(tmp_path / "missing.json"),
    ])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "baseline reference not found" in captured.err


def test_cli_baseline_drift_participates_in_fail_on_severity(tmp_path, capsys):
    ref = tmp_path / "ref.jsonl"
    _write_events(ref, [
        {"timestamp": "2026-09-15T10:01:00Z", "level": "INFO", "message": "ok", "source": "api"},
    ])
    cur = tmp_path / "cur.jsonl"
    _write_events(cur, [
        {"timestamp": "2026-09-15T10:01:00Z", "level": "ERROR", "message": "boom", "source": "api"},
    ])
    reference = tmp_path / "reference.json"
    assert main(["analyze", str(ref), "--format", "json", "--window-minutes", "5", "--json"]) == 0
    reference.write_text(capsys.readouterr().out, encoding="utf-8")

    exit_code = main([
        "analyze", str(cur), "--format", "json", "--window-minutes", "5",
        "--baseline-diff", str(reference), "--baseline-diff-threshold", "0.5",
        "--fail-on-severity", "medium", "--json",
    ])
    assert exit_code == 3
    report = json.loads(capsys.readouterr().out)
    assert any(f["rule"] == "baseline-drift" and f["severity"] == "high" for f in report["findings"])
