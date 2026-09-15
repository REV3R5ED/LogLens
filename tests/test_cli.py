import json

import pytest

from loglens.cli import build_parser, main


def test_detection_threshold_flags_are_parsed():
    args = build_parser().parse_args([
        "analyze", "app.log", "--error-threshold", "3", "--repeat-threshold", "4",
    ])
    assert args.error_threshold == 3
    assert args.repeat_threshold == 4


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--error-threshold", "0"), ("--repeat-threshold", "1"), ("--window-minutes", "0"), ("--window-minutes", "1441")],
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
    assert report["detection_config"] == {"error_threshold": 2, "repeat_threshold": 2}
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
