import pytest

from loglens.syslog import parse_rfc5424_line


PREFIX = "<34>1 2026-09-19T18:00:00Z host app 123 ID47 "


@pytest.mark.parametrize(
    "structured_data",
    [
        '[meta key="value"]',
        '[meta key="value" count="2"]',
        '[meta@32473 path="C:\\\\logs" note="quote\\\" and bracket\\]"]',
        '[meta empty=""]',
    ],
)
def test_accepts_well_formed_structured_data_parameters(structured_data):
    event = parse_rfc5424_line(f"{PREFIX}{structured_data} payload")
    assert event.message == "payload"


@pytest.mark.parametrize(
    "structured_data",
    [
        '[meta ="value"]',
        '[meta key=value]',
        '[meta key="unterminated]',
        '[meta key="raw]bracket"]',
        '[meta key="bad\\escape"]',
        '[meta key="value"broken="2"]',
        '[meta key="value" ]',
        f'[meta {"k" * 33}="value"]',
    ],
)
def test_rejects_malformed_structured_data_parameters(structured_data):
    with pytest.raises(ValueError, match="structured data"):
        parse_rfc5424_line(f"{PREFIX}{structured_data} payload")
