import csv
import io
import json

from loglens.cli import main


def test_json_report_includes_privacy_safe_field_coverage(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"level":"INFO","message":"one","request_id":"secret-1","status":200}\n'
        '{"level":"ERROR","message":"two","request_id":"secret-2"}\n',
        encoding="utf-8",
    )

    exit_code = main(["analyze", str(log), "--format", "json", "--json"])

    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["field_coverage"] == {
        "events": 2,
        "fields": {
            "request_id": {"present": 2, "coverage": 1.0},
            "status": {"present": 1, "coverage": 0.5},
        },
    }
    assert "secret-1" not in repr(report["field_coverage"])
    assert "secret-2" not in repr(report["field_coverage"])


def test_csv_report_includes_privacy_safe_field_coverage(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"level":"INFO","message":"one","request_id":"secret-1","status":200}\n'
        '{"level":"ERROR","message":"two","request_id":"secret-2"}\n',
        encoding="utf-8",
    )

    exit_code = main(["analyze", str(log), "--format", "json", "--csv"])

    assert exit_code == 0
    output = capsys.readouterr().out
    rows = list(csv.DictReader(io.StringIO(output)))
    coverage_rows = [row for row in rows if row["record_type"].startswith("field_coverage")]

    assert {tuple(row[key] for key in ("record_type", "name", "value", "score")) for row in coverage_rows} == {
        ("field_coverage_meta", "events", "2", ""),
        ("field_coverage", "request_id", "2", "1.0"),
        ("field_coverage", "status", "1", "0.5"),
    }
    assert "secret-1" not in output
    assert "secret-2" not in output
