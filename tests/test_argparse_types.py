"""Integer CLI options reject junk with ArgumentTypeError, not raw ValueError."""

import pytest

from loglens.cli import build_parser


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--error-threshold", "abc"),
        ("--error-threshold", "1.5"),
        ("--error-threshold", ""),
        ("--repeat-threshold", "many"),
        ("--burst-threshold", "x"),
        ("--burst-window-seconds", "soon"),
        ("--window-minutes", "five"),
        ("--max-parse-errors", "none"),
        ("--watch-interval", "often"),
        ("--watch-timeout", "later"),
        ("--baseline-diff-threshold", "high"),
    ],
)
def test_non_numeric_values_are_rejected_cleanly(flag, value, capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze", "app.log", flag, value])
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "expected an integer" in err or "expected a number" in err
    assert "invalid _positive_int value" not in err


@pytest.mark.parametrize(
    ("flag", "value", "message"),
    [
        ("--watch-interval", "0", "must be greater than 0"),
        ("--watch-interval", "-1", "must be greater than 0"),
        ("--watch-timeout", "-1", "must be at least 0"),
        ("--baseline-diff-threshold", "-0.1", "must be between 0 and 1"),
        ("--baseline-diff-threshold", "1.5", "must be between 0 and 1"),
    ],
)
def test_range_violations_report_bounds(flag, value, message, capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze", "app.log", flag, value])
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


def test_valid_float_options_are_parsed():
    args = build_parser().parse_args(
        ["analyze", "app.log", "--watch-interval", "0.5", "--watch-timeout", "10",
         "--baseline-diff-threshold", "0.75"]
    )
    assert args.watch_interval == 0.5
    assert args.watch_timeout == 10.0
    assert args.baseline_diff_threshold == 0.75


def test_threshold_defaults_come_from_policy_resolution():
    args = build_parser().parse_args(["analyze", "app.log"])
    assert args.error_threshold is None
    assert args.repeat_threshold is None
    assert args.burst_threshold is None
    assert args.burst_window_seconds is None
