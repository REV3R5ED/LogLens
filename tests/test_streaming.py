"""Streaming pipeline: lazy parse/filter/detect with identical rule semantics."""

import json

from loglens.analysis import filter_events, iter_matching
from loglens.cli import main
from loglens.detection import detect_anomalies
from loglens.model import LogEvent
from loglens.pipeline import PipelineConfig, StreamAnalyzer


def _log_events():
    return [
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="ok", level="INFO", source="api"),
        LogEvent(message="boom", level="ERROR", source="web"),
    ]


def test_detection_accepts_oneshot_generators():
    from_list = detect_anomalies(_log_events(), error_threshold=2, repeat_threshold=2)
    from_generator = detect_anomalies(
        (event for event in _log_events()), error_threshold=2, repeat_threshold=2
    )
    assert from_generator == from_list
    assert {finding.rule for finding in from_generator} == {"elevated-errors", "repeated-message"}


def test_iter_matching_is_lazy_and_equivalent():
    pulled = []

    def gen():
        for event in _log_events():
            pulled.append(event.message)
            yield event

    matches = iter_matching(gen(), levels={"ERROR"})
    first = next(matches)
    assert first.message == "disk full"
    assert pulled == ["disk full"]  # generator not exhausted
    assert [event.message for event in matches] == ["disk full", "boom"]
    assert [event.message for event in filter_events(_log_events(), levels={"ERROR"})] == [
        "disk full", "disk full", "boom",
    ]


def test_stream_analyzer_matches_list_based_report(tmp_path, capsys):
    log = tmp_path / "events.jsonl"
    log.write_text(
        '{"timestamp":"2026-09-15T10:01:00Z","level":"ERROR","message":"db down","source":"api"}\n'
        '{"timestamp":"2026-09-15T10:02:00Z","level":"ERROR","message":"db down","source":"api"}\n'
        '{"timestamp":"2026-09-15T10:03:00Z","level":"INFO","message":"ok","source":"api"}\n'
        '{"level":"WARN","message":"slow","source":"web"}\n'
        '{broken}\n',
        encoding="utf-8",
    )
    exit_code = main([
        "analyze", str(log), "--format", "json", "--max-parse-errors", "1",
        "--error-threshold", "2", "--repeat-threshold", "2", "--window-minutes", "5", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input_events"] == 5
    assert report["matched_events"] == 4
    assert report["parse_errors"] == 1
    assert report["levels"] == {"ERROR": 2, "INFO": 1, "WARN": 1}
    assert {finding["rule"] for finding in report["findings"]} == {"elevated-errors", "repeated-message"}
    assert report["time_baseline"]["timestamped_events"] == 3
    assert report["field_coverage"]["events"] == 4
    assert report["source_health"][0]["source"] == "api"


def test_stream_analyzer_add_line_counts_blank_and_bad_lines():
    analyzer = StreamAnalyzer(PipelineConfig(format="json"), source_name="test")
    analyzer.add_line("\n")
    analyzer.add_line("   \n")
    analyzer.add_line('{"level":"INFO","message":"ok"}\n')
    analyzer.add_line("{broken}\n")
    assert analyzer.input_events == 2
    assert analyzer.parse_errors == 1
    assert analyzer.matched_events == 1


def test_stream_analyzer_never_materializes_events():
    analyzer = StreamAnalyzer(PipelineConfig(), source_name="test")
    for index in range(1000):
        analyzer.add_event(LogEvent(message=f"message {index % 10}", level="INFO", source="svc"))
    # Only aggregated state is retained: no event list anywhere on the analyzer.
    assert not any(
        isinstance(value, list) and value and isinstance(value[0], LogEvent)
        for value in vars(analyzer).values()
    )
    assert analyzer.matched_events == 1000
    assert analyzer.summary.total == 1000


def test_progress_logs_to_stderr_not_stdout(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\nERROR bad\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--progress", "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert "loglens: INFO: processed 2 input lines (2 matched, 0 parse errors): done" in captured.err
    json.loads(captured.out)  # stdout is still pure JSON


def test_no_progress_by_default(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--json"])
    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert json.loads(captured.out)["input_events"] == 1


def test_filtered_streaming_report_counts_only_matches(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO keep\nERROR drop\nINFO keep2\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--level", "INFO", "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input_events"] == 3
    assert report["matched_events"] == 2
    assert report["levels"] == {"INFO": 2}
