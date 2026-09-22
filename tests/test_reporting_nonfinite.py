import math

import pytest

from loglens.reporting import report_to_csv


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_report_to_csv_rejects_non_finite_summary_values(value):
    report = {"events": value, "levels": {}, "sources": {}, "findings": []}

    with pytest.raises(ValueError, match="non-finite"):
        report_to_csv(report)


def test_report_to_csv_rejects_non_finite_finding_scores():
    report = {
        "events": 1,
        "levels": {},
        "sources": {},
        "findings": [
            {
                "rule": "example",
                "count": 1,
                "severity": "low",
                "score": math.nan,
                "message": "example finding",
            }
        ],
    }

    with pytest.raises(ValueError, match="non-finite"):
        report_to_csv(report)
