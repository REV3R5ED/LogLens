import csv
import io
import json

from loglens.reporting import report_to_csv


def test_csv_field_coverage_exposes_type_drift_with_types():
    report = {
        "events": 2,
        "levels": {},
        "sources": {},
        "field_coverage": {
            "events": 2,
            "fields": {
                "request_id": {
                    "present": 2,
                    "coverage": 1.0,
                    "types": {"string": 2},
                    "type_drift": False,
                },
                "status": {
                    "present": 2,
                    "coverage": 1.0,
                    "types": {"integer": 1, "string": 1},
                    "type_drift": True,
                },
            },
        },
        "findings": [],
    }

    rows = list(csv.DictReader(io.StringIO(report_to_csv(report), newline="")))
    coverage = {row["name"]: row for row in rows if row["record_type"] == "field_coverage"}

    assert json.loads(coverage["request_id"]["message"]) == {
        "type_drift": False,
        "types": {"string": 2},
    }
    assert json.loads(coverage["status"]["message"]) == {
        "type_drift": True,
        "types": {"integer": 1, "string": 1},
    }
    assert "secret-request-id" not in report_to_csv(report)
