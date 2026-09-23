import csv
import io
import json

from loglens.reporting import report_to_csv


def test_csv_field_coverage_preserves_drift_evidence():
    report = {
        "field_coverage": {
            "events": 3,
            "fields": {
                "status": {
                    "present": 3,
                    "coverage": 1.0,
                    "types": {"integer": 2, "string": 1},
                    "type_drift": True,
                    "type_drift_families": ["number", "string"],
                    "type_drift_family_counts": {"number": 2, "string": 1},
                    "type_drift_family_rates": {"number": 2 / 3, "string": 1 / 3},
                }
            },
        }
    }

    rows = list(csv.DictReader(io.StringIO(report_to_csv(report), newline="")))
    coverage = next(row for row in rows if row["record_type"] == "field_coverage")
    details = json.loads(coverage["message"])

    assert details["type_drift"] is True
    assert details["type_drift_families"] == ["number", "string"]
    assert details["type_drift_family_counts"] == {"number": 2, "string": 1}
    assert details["type_drift_family_rates"] == {"number": 2 / 3, "string": 1 / 3}
