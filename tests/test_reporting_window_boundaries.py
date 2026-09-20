import csv
import io

from loglens.reporting import report_to_csv


def test_report_to_csv_preserves_window_end_boundary():
    report = {
        "events": 2,
        "levels": {},
        "sources": {},
        "time_baseline": {
            "window_minutes": 5,
            "timestamped_events": 2,
            "windows": [{
                "start": "2026-09-20T09:00:00+00:00",
                "end": "2026-09-20T09:05:00+00:00",
                "events": 2,
                "error_events": 1,
                "levels": {"ERROR": 1, "INFO": 1},
            }],
        },
        "findings": [],
    }

    rows = list(csv.DictReader(io.StringIO(report_to_csv(report), newline="")))
    window = next(row for row in rows if row["record_type"] == "window")
    boundary = next(row for row in rows if row["record_type"] == "window_end")

    assert boundary["name"] == window["name"]
    assert boundary["value"] == "2026-09-20T09:05:00+00:00"


def test_report_to_csv_omits_empty_window_end_boundary():
    report = {
        "events": 1,
        "levels": {},
        "sources": {},
        "time_baseline": {
            "window_minutes": 5,
            "timestamped_events": 1,
            "windows": [{"start": "2026-09-20T09:00:00+00:00", "events": 1, "error_events": 0, "levels": {}}],
        },
        "findings": [],
    }

    rows = list(csv.DictReader(io.StringIO(report_to_csv(report), newline="")))
    assert all(row["record_type"] != "window_end" for row in rows)
