import csv
import io
import json

from loglens.reporting import report_to_csv, report_to_json


def test_report_to_json_is_deterministic_and_readable():
    report = {"z": 1, "a": {"b": 2}}
    rendered = report_to_json(report)
    assert rendered == '{\n  "a": {\n    "b": 2\n  },\n  "z": 1\n}'
    assert json.loads(rendered) == report


def test_report_to_csv_preserves_summary_aggregates_and_findings():
    report = {
        "source": "app.log", "input_events": 6, "matched_events": 5,
        "parse_errors": 1, "events": 5, "levels": {"ERROR": 5},
        "sources": {"app.log": 5},
        "findings": [{"rule": "elevated-errors", "severity": "medium", "score": 75,
                      "message": "Elevated error-level event count", "count": 5}],
    }
    rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
    assert rows[0] == {"record_type": "summary", "name": "source", "value": "app.log", "severity": "", "score": "", "message": ""}
    assert {"record_type": "level", "name": "ERROR", "value": "5", "severity": "", "score": "", "message": ""} in rows
    assert rows[-1]["record_type"] == "finding"
    assert rows[-1]["name"] == "elevated-errors"
    assert rows[-1]["severity"] == "medium"
    assert rows[-1]["score"] == "75"


def test_report_to_csv_preserves_config_and_time_baseline():
    report = {
        "events": 3, "levels": {}, "sources": {},
        "detection_config": {"repeat_threshold": 5, "error_threshold": 3},
        "time_baseline": {"window_minutes": 5, "timestamped_events": 3,
            "windows": [{"start": "2026-09-15T10:00:00+00:00", "end": "2026-09-15T10:05:00+00:00",
                         "events": 3, "error_events": 2, "levels": {"WARN": 1, "ERROR": 2}}]},
        "findings": [],
    }
    rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
    assert [(row["name"], row["value"]) for row in rows if row["record_type"] == "config"] == [("error_threshold", "3"), ("repeat_threshold", "5")]
    assert {row["name"] for row in rows if row["record_type"] == "baseline"} == {"window_minutes", "timestamped_events"}
    window = next(row for row in rows if row["record_type"] == "window")
    assert window["name"] == "2026-09-15T10:00:00+00:00"
    assert window["value"] == "3"
    assert window["score"] == "2"
    assert json.loads(window["message"]) == {"ERROR": 2, "WARN": 1}


def test_report_to_csv_quotes_untrusted_text_safely():
    report = {"events": 1, "levels": {}, "sources": {}, "findings": [{"rule": "repeat", "count": 2, "severity": "low", "score": 51, "message": "comma, quote \" text"}]}
    rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
    assert rows[-1]["message"] == "comma, quote \" text"


def test_report_to_csv_neutralizes_spreadsheet_formula_prefixes():
    report = {"source": "=cmd", "events": 4, "levels": {"+WARN": 1}, "sources": {"@service": 4},
              "findings": [{"rule": "-rule", "count": 4, "severity": "low", "score": 50,
                            "message": "=HYPERLINK(\"https://example.invalid\")"}]}
    rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
    assert rows[0]["value"] == "'=cmd"
    assert next(row for row in rows if row["record_type"] == "level")["name"] == "'+WARN"
    assert next(row for row in rows if row["record_type"] == "source")["name"] == "'@service"
    assert rows[-1]["name"] == "'-rule"
    assert rows[-1]["message"].startswith("'=HYPERLINK")


def test_report_to_csv_neutralizes_formula_prefixes_after_leading_whitespace():
    prefixes = (" =1+1", "\t+cmd", "\r-2+3", "\n@SUM(A1:A2)")
    for value in prefixes:
        report = {"source": value, "events": 1, "levels": {}, "sources": {}, "findings": []}
        rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
        assert rows[0]["value"] == "'" + value


def test_report_to_csv_preserves_benign_leading_whitespace_and_numeric_values():
    report = {"source": "  normal.log", "events": -1, "levels": {}, "sources": {}, "findings": []}
    rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
    assert rows[0]["value"] == "  normal.log"
    assert next(row for row in rows if row["name"] == "events")["value"] == "-1"


def test_report_to_csv_is_deterministic_for_aggregates():
    report = {"events": 2, "levels": {"WARN": 1, "ERROR": 1}, "sources": {"z": 1, "a": 1}, "findings": []}
    rows = list(csv.DictReader(io.StringIO(report_to_csv(report))))
    aggregate_names = [(row["record_type"], row["name"]) for row in rows[1:]]
    assert aggregate_names == [("level", "ERROR"), ("level", "WARN"), ("source", "a"), ("source", "z")]
