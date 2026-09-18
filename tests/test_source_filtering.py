import json

from loglens.analysis import filter_events
from loglens.cli import main
from loglens.model import LogEvent


def test_filter_events_matches_sources_case_insensitively_and_combines_filters():
    events = [
        LogEvent("database timeout", "ERROR", source=" API "),
        LogEvent("database timeout", "ERROR", source="worker"),
        LogEvent("database ready", "INFO", source="api"),
    ]
    assert filter_events(
        events, levels={"error"}, contains="DATABASE", sources={"api"}
    ) == [events[0]]


def test_filter_events_can_select_unknown_source():
    events = [LogEvent("missing", "WARN"), LogEvent("known", "WARN", source="api")]
    assert filter_events(events, sources={"<unknown>"}) == [events[0]]


def test_cli_source_filter_limits_analysis_and_findings(tmp_path, capsys):
    path = tmp_path / "events.jsonl"
    records = [
        {"source": "api", "level": "ERROR", "message": "api failed"},
        {"source": "worker", "level": "ERROR", "message": "worker failed"},
        {"source": "API", "level": "INFO", "message": "api recovered"},
    ]
    path.write_text("\n".join(json.dumps(record) for record in records), encoding="utf-8")

    assert main(["analyze", str(path), "--source", "api", "--error-threshold", "2", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input_events"] == 3
    assert report["matched_events"] == 2
    assert report["levels"] == {"ERROR": 1, "INFO": 1}
    assert report["findings"] == []
    assert [item["source"] for item in report["source_health"]] == ["API", "api"]
