"""Diagnostics go through the logging module on stderr; reports stay on stdout."""

import json

import pytest

import loglens.cli
from loglens.cli import build_parser, main


def test_verbose_flag_is_parsed():
    args = build_parser().parse_args(["analyze", "app.log", "--verbose"])
    assert args.verbose is True
    args = build_parser().parse_args(["analyze", "app.log", "-v"])
    assert args.verbose is True
    args = build_parser().parse_args(["analyze", "app.log"])
    assert args.verbose is False


def test_missing_file_logs_structured_error_without_stdout(tmp_path, capsys):
    missing = tmp_path / "missing.log"
    exit_code = main(["analyze", str(missing)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "loglens: ERROR:" in captured.err
    assert str(missing) in captured.err


def test_unexpected_errors_become_structured_exit_1(tmp_path, capsys, monkeypatch):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")

    class Boom:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("simulated pipeline failure")

    monkeypatch.setattr(loglens.cli, "StreamAnalyzer", Boom)
    exit_code = main(["analyze", str(log)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "loglens: ERROR: unexpected failure: RuntimeError: simulated pipeline failure" in captured.err
    assert "Traceback" not in captured.err


def test_verbose_unexpected_errors_include_traceback(tmp_path, capsys, monkeypatch):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")

    class Boom:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("simulated pipeline failure")

    monkeypatch.setattr(loglens.cli, "StreamAnalyzer", Boom)
    exit_code = main(["analyze", str(log), "--verbose"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Traceback (most recent call last):" in captured.err
    assert "RuntimeError: simulated pipeline failure" in captured.err


def test_per_line_unexpected_parser_errors_are_counted(tmp_path, capsys, monkeypatch):
    import loglens.pipeline

    real_parse_line = loglens.pipeline.parse_line

    def flaky_parse_line(line, *, source=None, format="auto"):
        if "BOOM" in line:
            raise RuntimeError("parser exploded")
        return real_parse_line(line, source=source, format=format)

    monkeypatch.setattr(loglens.pipeline, "parse_line", flaky_parse_line)
    log = tmp_path / "app.log"
    log.write_text("INFO ok\nBOOM line\nINFO ok again\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--max-parse-errors", "5", "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    report = json.loads(captured.out)
    assert report["parse_errors"] == 1
    assert report["matched_events"] == 2
    # No raw traceback leaks into the report or diagnostics by default.
    assert "Traceback" not in captured.err


def test_verbose_logs_per_line_parse_diagnostics(tmp_path, capsys, monkeypatch):
    import loglens.pipeline

    real_parse_line = loglens.pipeline.parse_line

    def flaky_parse_line(line, *, source=None, format="auto"):
        if "BOOM" in line:
            raise RuntimeError("parser exploded")
        return real_parse_line(line, source=source, format=format)

    monkeypatch.setattr(loglens.pipeline, "parse_line", flaky_parse_line)
    log = tmp_path / "app.log"
    log.write_text("INFO ok\nBOOM line\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--max-parse-errors", "5", "--verbose", "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "loglens: DEBUG: line 2: parse failed (RuntimeError: parser exploded)" in captured.err
    # Diagnostics never pollute the machine-readable report on stdout.
    json.loads(captured.out)


def test_keyboard_interrupt_is_not_swallowed_as_operational_error(tmp_path, monkeypatch):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    monkeypatch.setattr(loglens.cli, "StreamAnalyzer", _raise_keyboard_interrupt)
    with pytest.raises(KeyboardInterrupt):
        main(["analyze", str(log)])


class _raise_keyboard_interrupt:
    def __init__(self, *args, **kwargs):
        raise KeyboardInterrupt()
