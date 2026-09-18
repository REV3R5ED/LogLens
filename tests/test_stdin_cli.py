import io
import json
import sys

from loglens.cli import main


def test_stdin_json_analysis_emits_report(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            '{"level":"INFO","message":"healthy","source":"api"}\n'
            '{"level":"ERROR","message":"database unavailable","source":"api"}\n'
        ),
    )

    exit_code = main(["analyze", "-", "--format", "json", "--json"])

    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["source"] == "<stdin>"
    assert report["input_events"] == 2
    assert report["matched_events"] == 2
    assert report["parse_errors"] == 0
    assert report["levels"] == {"ERROR": 1, "INFO": 1}


def test_stdin_preserves_parse_error_exit_precedence(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "stdin",
        io.StringIO(
            '{"level":"ERROR","message":"disk full"}\n'
            '{"level":"ERROR","message":"disk full"}\n'
            '{not valid json}\n'
        ),
    )

    exit_code = main([
        "analyze", "-", "--format", "json", "--error-threshold", "2",
        "--repeat-threshold", "2", "--fail-on-finding", "--json",
    ])

    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["source"] == "<stdin>"
    assert report["parse_errors"] == 1
    assert report["findings"]
