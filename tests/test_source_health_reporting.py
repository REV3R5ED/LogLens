import csv
import io
import json

from loglens.cli import main


def _write_multisource_log(path):
    path.write_text(
        '{"level":"ERROR","message":"db unavailable","source":"api"}\n'
        '{"level":"INFO","message":"request complete","source":"api"}\n'
        '{"level":"WARN","message":"queue delayed","source":"worker"}\n',
        encoding="utf-8",
    )


def test_json_report_includes_deterministic_source_health(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    _write_multisource_log(log)

    assert main(["analyze", str(log), "--format", "json", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)

    assert report["source_health"] == [
        {
            "source": "api",
            "events": 2,
            "error_events": 1,
            "error_rate": 0.5,
            "levels": {"ERROR": 1, "INFO": 1},
        },
        {
            "source": "worker",
            "events": 1,
            "error_events": 0,
            "error_rate": 0.0,
            "levels": {"WARN": 1},
        },
    ]


def test_csv_report_preserves_source_health_metrics(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    _write_multisource_log(log)

    assert main(["analyze", str(log), "--format", "json", "--csv"]) == 0
    rows = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))
    health = [row for row in rows if row["record_type"] == "source_health"]

    assert [row["name"] for row in health] == ["api", "worker"]
    assert health[0]["value"] == "2"
    assert health[0]["severity"] == "0.5"
    assert health[0]["score"] == "1"
    assert json.loads(health[0]["message"]) == {"ERROR": 1, "INFO": 1}


def test_text_report_surfaces_source_health_for_analyst(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    _write_multisource_log(log)

    assert main(["analyze", str(log), "--format", "json"]) == 0
    output = capsys.readouterr().out

    assert "Source health:" in output
    assert "api: 2 events | 1 errors | 50.0% error rate" in output
    assert "worker: 1 events | 0 errors | 0.0% error rate" in output
