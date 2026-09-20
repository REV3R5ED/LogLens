import math

import pytest

from loglens.reporting import report_to_json


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_json_report_rejects_non_finite_numbers(value):
    """JSON reports must not emit JavaScript-only NaN/Infinity tokens."""
    with pytest.raises(ValueError, match="Out of range float values"):
        report_to_json({"score": value})


def test_json_report_keeps_finite_floats_supported():
    rendered = report_to_json({"error_rate": 0.25})

    assert '"error_rate": 0.25' in rendered
