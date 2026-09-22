import csv
import io
import json

from loglens.reporting import report_to_csv, report_to_json


def _read_csv(rendered: str):
    """Parse generated CSV without translating embedded CR/LF characters."""
    return list(csv.DictReader(io.StringIO(rendered, newline="")))


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
    rows = _read_csv(report_to_csv(report))
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
    rows = _read_csv(report_to_csv(report))
    assert [(row["name"], row["value"]) for row in rows if row["record_type"] == "config"] == [("error_threshold", "3"), ("repeat_threshold", "5")]
    assert {row["name"] for row in rows if row["record_type"] == "baseline"} == {"window_minutes", "timestamped_events"}
    window = next(row for row in rows if row["record_type"] == "window")
    assert window["name"] == "2026-09-15T10:00:00+00:00"
    assert window["value"] == "3"
    assert window["score"] == "2"
    assert json.loads(window["message"]) == {"ERROR": 2, "WARN": 1}


def test_report_to_csv_preserves_privacy_safe_field_coverage():
    report = {
        "events": 4, "levels": {}, "sources": {},
        "field_coverage": {"events": 4, "fields": {
            "request_id": {"present": 3, "coverage": 0.75},
            "status": {"present": 4, "coverage": 1.0},
        }},
        "findings": [],
    }
    rows = _read_csv(report_to_csv(report))
    coverage = [row for row in rows if row["record_type"] == "field_coverage"]
    assert [(row["name"], row["value"], row["score"]) for row in coverage] == [
        ("request_id", "3", "0.75"), ("status", "4", "1.0")
    ]
    assert "request-123" not in report_to_csv(report)


def test_report_to_csv_neutralizes_field_names_that_look_like_formulas():
    report = {
        "events": 1, "levels": {}, "sources": {},
        "field_coverage": {"events": 1, "fields": {"=HYPERLINK()": {"present": 1, "coverage": 1.0}}},
        "findings": [],
    }
    rows = _read_csv(report_to_csv(report))
    coverage = next(row for row in rows if row["record_type"] == "field_coverage")
    assert coverage["name"] == "'=HYPERLINK()"


def test_report_to_csv_quotes_untrusted_text_safely():
    report = {"events": 1, "levels": {}, "sources": {}, "findings": [{"rule": "repeat", "count": 2, "severity": "low", "score": 51, "message": "comma, quote \" text"}]}
    rows = _read_csv(report_to_csv(report))
    assert rows[-1]["message"] == "comma, quote \" text"


def test_report_to_csv_neutralizes_spreadsheet_formula_prefixes():
    report = {"source": "=cmd", "events": 4, "levels": {"+WARN": 1}, "sources": {"@service": 4},
              "findings": [{"rule": "-rule", "count": 4, "severity": "low", "score": 50,
                            "message": "=HYPERLINK(\"https://example.invalid\")"}]}
    rows = _read_csv(report_to_csv(report))
    assert rows[0]["value"] == "'=cmd"
    assert next(row for row in rows if row["record_type"] == "level")["name"] == "'+WARN"
    assert next(row for row in rows if row["record_type"] == "source")["name"] == "'@service"
    assert rows[-1]["name"] == "'-rule"
    assert rows[-1]["message"].startswith("'=HYPERLINK")


def test_report_to_csv_neutralizes_formula_prefixes_after_leading_whitespace():
    prefixes = (" =1+1", "\t+cmd", "\r-2+3", "\n@SUM(A1:A2)")
    for value in prefixes:
        report = {"source": value, "events": 1, "levels": {}, "sources": {}, "findings": []}
        rows = _read_csv(report_to_csv(report))
        assert rows[0]["value"] == "'" + value.replace("\t", r"\t").replace("\r", r"\r").replace("\n", r"\n")


def test_report_to_csv_neutralizes_formula_prefixes_after_unicode_whitespace():
    prefixes = ("\u00a0=1+1", "\u2003+cmd", "\u202f-2+3", "\u3000@SUM(A1:A2)")
    for value in prefixes:
        report = {"source": value, "events": 1, "levels": {}, "sources": {}, "findings": []}
        rows = _read_csv(report_to_csv(report))
        assert rows[0]["value"] == "'" + value


def test_report_to_csv_escapes_control_characters_without_creating_rows():
    report = {
        "source": "api\nworker\tqueue\x00",
        "events": 1,
        "levels": {},
        "sources": {},
        "findings": [{"rule": "repeat", "count": 2, "severity": "low", "score": 51,
                      "message": "line one\r\nline two\x7f"}],
    }
    rendered = report_to_csv(report)
    rows = _read_csv(rendered)
    assert rows[0]["value"] == r"api\nworker\tqueue\x00"
    assert rows[-1]["message"] == r"line one\r\nline two\x7f"
    assert len(rendered.splitlines()) == len(rows) + 1


def test_report_to_csv_escapes_unicode_format_and_line_separator_controls():
    report = {
        "source": "api\u202eexe.log",
        "events": 1,
        "levels": {},
        "sources": {},
        "findings": [{"rule": "repeat", "count": 2, "severity": "low", "score": 51,
                      "message": "before\u2066isolated\u2069\u2028after"}],
    }
    rendered = report_to_csv(report)
    rows = _read_csv(rendered)
    assert rows[0]["value"] == r"api\u202eexe.log"
    assert rows[-1]["message"] == r"before\u2066isolated\u2069\u2028after"
    assert "\u202e" not in rendered
    assert "\u2066" not in rendered
    assert "\u2069" not in rendered
    assert "\u2028" not in rendered


def test_report_to_csv_preserves_benign_leading_whitespace_and_numeric_values():
    report = {"source": "  normal.log", "events": -1, "levels": {}, "sources": {}, "findings": []}
    rows = _read_csv(report_to_csv(report))
    assert rows[0]["value"] == "  normal.log"
    assert next(row for row in rows if row["name"] == "events")["value"] == "-1"


def test_report_to_csv_is_deterministic_for_aggregates():
    report = {"events": 2, "levels": {"WARN": 1, "ERROR": 1}, "sources": {"z": 1, "a": 1}, "findings": []}
    rows = _read_csv(report_to_csv(report))
    aggregate_names = [(row["record_type"], row["name"]) for row in rows[1:]]
    assert aggregate_names == [("level", "ERROR"), ("level", "WARN"), ("source", "a"), ("source", "z")]
