import gzip
import json

from loglens.cli import main


def test_cli_analyzes_gzip_jsonl_without_manual_decompression(tmp_path, capsys):
    log = tmp_path / "events.jsonl.gz"
    with gzip.open(log, "wt", encoding="utf-8") as handle:
        handle.write('{"level":"INFO","message":"healthy","service":"api"}\n')
        handle.write('{"level":"ERROR","message":"database unavailable","service":"api"}\n')

    exit_code = main(["analyze", str(log), "--format", "json", "--json"])

    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["source"] == str(log)
    assert report["input_events"] == 2
    assert report["matched_events"] == 2
    assert report["parse_errors"] == 0
    assert report["levels"] == {"ERROR": 1, "INFO": 1}


def test_cli_reports_invalid_gzip_as_operational_error(tmp_path, capsys):
    log = tmp_path / "broken.log.gz"
    log.write_bytes(b"not actually gzip")

    exit_code = main(["analyze", str(log), "--json"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "loglens:" in captured.err
