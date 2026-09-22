import csv
import io

from loglens.reporting import report_to_csv


def test_csv_field_coverage_includes_denominator_context():
    report = {
        "events": 4,
        "levels": {},
        "sources": {},
        "field_coverage": {
            "events": 4,
            "fields": {"request_id": {"present": 3, "coverage": 0.75}},
        },
        "findings": [],
    }

    rows = list(csv.DictReader(io.StringIO(report_to_csv(report), newline="")))
    metadata = next(row for row in rows if row["record_type"] == "field_coverage_meta")
    coverage = next(row for row in rows if row["record_type"] == "field_coverage")

    assert (metadata["name"], metadata["value"]) == ("events", "4")
    assert (coverage["name"], coverage["value"], coverage["score"]) == (
        "request_id", "3", "0.75"
    )
