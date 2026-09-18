import csv
import io
import json

import pytest

from loglens import __version__
from loglens.cli import build_parser, main


def test_cli_version_matches_runtime_package_version(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"loglens {__version__}"


def test_detection_threshold_flags_are_parsed():
    args = build_parser().parse_args([
        "analyze", "app.log", "--error-threshold", "3", "--repeat-threshold", "4",
    ])
    assert args.error_threshold == 3
    assert args.repeat_threshold == 4


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--error-threshold", "0"), ("--repeat-threshold", "1"), ("--window-minutes", "0"), ("--window-minutes", "1441"), ("--max-parse-errors", "-1")],
)
def test_invalid_detection_and_window_values_are_rejected(flag, value):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze", "app.log", flag, value])
    assert exc.value.code == 2


def test_json_report_records_effective_detection_config(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR database unavailable\nERROR database unavailable\n", encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "2", "--repeat-threshold", "2", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["detection_config"] == {
        "error_threshold": 2,
        "repeat_threshold": 2,
        "burst_threshold": 5,
        "burst_window_seconds": 60,
    }
    assert report["max_parse_errors"] == 0
    assert {finding["rule"] for finding in report["findings"]} == {"elevated-errors", "repeated-message"}


def test_json_report_can_include_time_window_baseline(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"timestamp":"2026-09-15T10:01:00Z","level":"INFO","message":"ok"}\n'
        '{"timestamp":"2026-09-15T10:03:00Z","level":"ERROR","message":"bad"}\n'
        '{"level":"WARN","message":"no timestamp"}\n',
        encoding="utf-8",
    )
    exit_code = main(["analyze", str(log), "--format", "json", "--window-minutes", "5", "--json"])
    assert exit_code == 0
    baseline = json.loads(capsys.readouterr().out)["time_baseline"]
    assert baseline["window_minutes"] == 5
    assert baseline["timestamped_events"] == 2
    assert baseline["windows"][0]["events"] == 2
    assert baseline["windows"][0]["error_events"] == 1


def test_text_output_reports_filters_findings_and_baseline(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"timestamp":"2026-09-15T10:01:00Z","level":"ERROR","message":"database unavailable"}\n'
        '{"timestamp":"2026-09-15T10:02:00Z","level":"ERROR","message":"database unavailable"}\n'
        '{"timestamp":"2026-09-15T10:03:00Z","level":"INFO","message":"healthy"}\n',
        encoding="utf-8",
    )
    exit_code = main([
        "analyze", str(log), "--format", "json", "--level", "ERROR",
        "--error-threshold", "2", "--repeat-threshold", "2", "--window-minutes", "5",
    ])
    assert exit_code == 0
    output = capsys.readouterr().out
    assert "Input: 3 | Matched: 2 | Parse errors: 0" in output
    assert "Time windows: 1 x 5m | Timestamped: 2" in output
    assert "elevated-errors" in output
    assert "repeated-message" in output


def test_csv_output_is_parseable_and_preserves_report_sections(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\nERROR disk full\n", encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "2", "--repeat-threshold", "2", "--csv",
    ])
    assert exit_code == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    assert rows
    assert {row["record_type"] for row in rows} >= {"summary", "config", "finding"}
    assert {row["name"] for row in rows if row["record_type"] == "config"} == {
        "error_threshold", "repeat_threshold", "burst_threshold", "burst_window_seconds",
    }
    assert {row["name"] for row in rows if row["record_type"] == "finding"} == {
        "elevated-errors", "repeated-message",
    }


def test_strict_json_parse_errors_return_nonzero_but_emit_report(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"level":"INFO","message":"valid"}\n'
        '{not valid json}\n',
        encoding="utf-8",
    )
    exit_code = main(["analyze", str(log), "--format", "json", "--json"])
    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["input_events"] == 2
    assert report["matched_events"] == 1
    assert report["parse_errors"] == 1
    assert report["max_parse_errors"] == 0


def test_parse_error_budget_allows_known_noise_but_remains_auditable(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"level":"INFO","message":"valid"}\n'
        '{not valid json}\n',
        encoding="utf-8",
    )
    exit_code = main([
        "analyze", str(log), "--format", "json", "--max-parse-errors", "1", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["parse_errors"] == 1
    assert report["max_parse_errors"] == 1
    assert report["matched_events"] == 1


def test_parse_error_budget_fails_when_exceeded(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text('{bad}\n{also bad}\n', encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--format", "json", "--max-parse-errors", "1", "--json",
    ])
    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["parse_errors"] == 2
    assert report["max_parse_errors"] == 1


def test_missing_input_file_returns_operational_error(tmp_path, capsys):
    missing = tmp_path / "missing.log"
    exit_code = main(["analyze", str(missing)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "loglens:" in captured.err
    assert str(missing) in captured.err


def test_json_and_csv_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze", "app.log", "--json", "--csv"])
    assert exc.value.code == 2


def test_fail_on_finding_returns_three_after_emitting_report(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\nERROR disk full\n", encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "2", "--repeat-threshold", "2",
        "--fail-on-finding", "--json",
    ])
    assert exit_code == 3
    report = json.loads(capsys.readouterr().out)
    assert {finding["rule"] for finding in report["findings"]} == {
        "elevated-errors", "repeated-message",
    }


def test_fail_on_finding_keeps_clean_analysis_successful(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO healthy\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--fail-on-finding", "--json"])
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["findings"] == []


def test_parse_error_takes_precedence_over_finding_exit_code(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"level":"ERROR","message":"database unavailable"}\n'
        '{"level":"ERROR","message":"database unavailable"}\n'
        '{not valid json}\n',
        encoding="utf-8",
    )
    exit_code = main([
        "analyze", str(log), "--format", "json", "--error-threshold", "2",
        "--repeat-threshold", "2", "--fail-on-finding", "--json",
    ])
    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["parse_errors"] == 1
    assert report["findings"]


def test_fail_on_severity_ignores_findings_below_threshold(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\nERROR disk full\n", encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "2", "--repeat-threshold", "2",
        "--fail-on-severity", "high", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"]
    assert all(finding["severity"] != "high" for finding in report["findings"])


def test_fail_on_severity_returns_three_at_or_above_threshold(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\n" * 10, encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "2", "--repeat-threshold", "2",
        "--fail-on-severity", "medium", "--json",
    ])
    assert exit_code == 3
    report = json.loads(capsys.readouterr().out)
    assert any(finding["severity"] in {"medium", "high"} for finding in report["findings"])


def test_failure_gate_options_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([
            "analyze", "app.log", "--fail-on-finding", "--fail-on-severity", "high",
        ])
    assert exc.value.code == 2
