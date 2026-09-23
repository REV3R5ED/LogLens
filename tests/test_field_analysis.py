from loglens.field_analysis import summarize_field_coverage
from loglens.model import LogEvent


def test_field_coverage_counts_presence_without_values():
    events = [
        LogEvent(message="one", fields={"request_id": "secret-1", "status": 200}),
        LogEvent(message="two", fields={"request_id": "secret-2"}),
        LogEvent(message="three", fields={}),
    ]

    summary = summarize_field_coverage(events)

    assert summary == {
        "events": 3,
        "fields": {
            "request_id": {"present": 2, "coverage": 2 / 3},
            "status": {"present": 1, "coverage": 1 / 3},
        },
    }
    assert "secret-1" not in repr(summary)
    assert "secret-2" not in repr(summary)


def test_field_coverage_is_deterministic_and_accepts_generators():
    events = (
        LogEvent(message=str(index), fields=fields)
        for index, fields in enumerate(({"z": 1}, {"a": 2, "z": 3}))
    )

    summary = summarize_field_coverage(events)

    assert list(summary["fields"]) == ["a", "z"]
    assert summary["fields"]["z"] == {"present": 2, "coverage": 1.0}


def test_field_coverage_deduplicates_keys_with_same_display_identity():
    events = [
        LogEvent(message="mixed keys", fields={1: "numeric", "1": "text"}),
        LogEvent(message="text key", fields={"1": "again"}),
    ]

    summary = summarize_field_coverage(events)

    assert summary["fields"]["1"] == {"present": 2, "coverage": 1.0}
    assert all(field["coverage"] <= 1.0 for field in summary["fields"].values())


def test_field_coverage_normalizes_unicode_and_control_characters():
    events = [
        LogEvent(
            message="equivalent keys",
            fields={"request\u200bid": "one", "requestid": "two", "status\ncode": 200},
        ),
        LogEvent(message="compatibility key", fields={"ｒｅｑｕｅｓｔｉｄ": "three"}),
    ]

    summary = summarize_field_coverage(events)

    assert summary["fields"]["requestid"] == {"present": 2, "coverage": 1.0}
    assert summary["fields"]["status code"] == {"present": 1, "coverage": 0.5}
    assert "\u200b" not in repr(summary)
    assert "\n" not in "".join(summary["fields"])


def test_field_coverage_uses_explicit_identity_for_empty_keys():
    summary = summarize_field_coverage([LogEvent(message="empty", fields={"\u200b": 1})])

    assert summary["fields"] == {"<empty>": {"present": 1, "coverage": 1.0}}


def test_field_coverage_handles_empty_input():
    assert summarize_field_coverage([]) == {"events": 0, "fields": {}}
