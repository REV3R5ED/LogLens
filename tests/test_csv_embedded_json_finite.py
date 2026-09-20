import math

import pytest

from loglens.reporting import report_to_csv


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_csv_report_rejects_non_finite_window_level_counts(value):
    report = {
        "events": 1,
        "levels": {},
        "sources": {},
        "time_baseline": {
            "windows": [{"start": "2026-09-20T00:00:00+00:00", "levels": {"ERROR": value}}]
        },
        "findings": [],
    }

    with pytest.raises(ValueError, match="Out of range float values"):
        report_to_csv(report)


def test_csv_report_rejects_non_finite_source_health_level_counts():
    report = {
        "events": 1,
        "levels": {},
        "sources": {},
        "source_health": [{"source": "api", "levels": {"ERROR": math.nan}}],
        "findings": [],
    }

    with pytest.raises(ValueError, match="Out of range float values"):
        report_to_csv(report)


def test_csv_report_keeps_finite_embedded_json_compact():
    report = {
        "events": 1,
        "levels": {},
        "sources": {},
        "source_health": [{"source": "api", "levels": {"ERROR": 0.25}}],
        "findings": [],
    }

    rendered = report_to_csv(report)

    assert '{""ERROR"":0.25}' in rendered
