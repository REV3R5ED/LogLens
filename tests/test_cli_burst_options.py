import pytest

from loglens.cli import build_parser


def test_burst_flags_are_parsed():
    args = build_parser().parse_args(["analyze", "app.log", "--burst-threshold", "3", "--burst-window-seconds", "30"])
    assert args.burst_threshold == 3
    assert args.burst_window_seconds == 30


@pytest.mark.parametrize(("flag", "value"), [("--burst-threshold", "1"), ("--burst-window-seconds", "0")])
def test_invalid_burst_values_are_rejected(flag, value):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["analyze", "app.log", flag, value])
    assert exc.value.code == 2
