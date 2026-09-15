import json

import pytest

from loglens.cli import build_parser, main


def test_detection_threshold_flags_are_parsed():
    args = build_parser().parse_args([
        "analyze",
        "app.log",
        "--error-threshold",
        "3",
        "--repeat-threshold",
        "4",
    ])
    assert args.error_threshold == 3
    assert args.repeat_threshold == 4


@pytest.mark.parametrize(
    ("flag", "value"),
    [("--error-threshold", "0"), ("--repeat-threshold", "1")],
)
def test_invalid_detection_thresholds_are_rejected(flag, value):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze", "app.log", flag, value])
    assert exc.value.code == 2


def test_json_report_records_effective_detection_config(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR database unavailable\nERROR database unavailable\n", encoding="utf-8")

    exit_code = main([
        "analyze",
        str(log),
        "--error-threshold",
        "2",
        "--repeat-threshold",
        "2",
        "--json",
    ])

    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["detection_config"] == {"error_threshold": 2, "repeat_threshold": 2}
    assert {finding["rule"] for finding in report["findings"]} == {
        "elevated-errors",
        "repeated-message",
    }
