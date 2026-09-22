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
