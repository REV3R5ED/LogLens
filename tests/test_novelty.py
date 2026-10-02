"""Novelty rule: flag messages never observed in a persisted reference corpus."""

import json

import pytest

from loglens.cli import main
from loglens.detection import detect_novel_messages
from loglens.model import LogEvent
from loglens.novelty import KnownCorpus, NoveltyError, corpus_key


def _events():
    return [
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="cache miss", level="WARN", source="api"),
    ]


def test_corpus_key_normalizes_like_detection_rules():
    assert corpus_key(" api ", "error", "Disk Full") == ("api", "ERROR", "Disk Full")
    assert corpus_key(None, "INFO", "  hello  ") == (None, "INFO", "hello")


def test_learn_save_load_roundtrip_is_deterministic(tmp_path):
    store = tmp_path / "corpus.json"
    corpus = KnownCorpus()
    assert len(corpus) == 0
    new_keys = corpus.learn(_events())
    assert new_keys == 2  # two distinct (source, level, message) keys
    assert corpus.learn(_events()) == 0  # re-learning adds no new keys
    corpus.save(store)

    payload = json.loads(store.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert [(m["source"], m["level"], m["message"]) for m in payload["messages"]] == [
        ("api", "ERROR", "disk full"),
        ("api", "WARN", "cache miss"),
    ]
    assert payload["messages"][0]["count"] == 4  # learned twice

    reloaded = KnownCorpus.load(store)
    assert reloaded.keys() == corpus.keys()
    assert len(reloaded) == 2


def test_missing_store_loads_empty_corpus(tmp_path):
    corpus = KnownCorpus.load(tmp_path / "missing.json")
    assert len(corpus) == 0


def test_corrupt_store_raises_novelty_error(tmp_path):
    store = tmp_path / "corpus.json"
    store.write_text("{oops", encoding="utf-8")
    with pytest.raises(NoveltyError, match="invalid JSON"):
        KnownCorpus.load(store)
    store.write_text(json.dumps({"version": 99, "messages": []}), encoding="utf-8")
    with pytest.raises(NoveltyError, match="unsupported version"):
        KnownCorpus.load(store)
    store.write_text(json.dumps({"messages": [{"level": "INFO"}]}), encoding="utf-8")
    with pytest.raises(NoveltyError, match="string level and message"):
        KnownCorpus.load(store)


def test_detect_novel_messages_flags_only_unseen_keys():
    known = {corpus_key("api", "ERROR", "disk full")}
    findings = detect_novel_messages(_events(), known)
    assert [(f.rule, f.message) for f in findings] == [
        ("novel-message", "Novel message [api]: cache miss"),
    ]
    assert findings[0].count == 1


def test_novelty_scoring_uses_effective_threshold_of_one():
    events = [LogEvent(message="brand new", level="ERROR", source="api")]
    (finding,) = detect_novel_messages(events, set())
    # 1 occurrence vs threshold 1 from 1 event: 50 + 0 + 25 = 75 -> medium
    assert finding.score == 75
    assert finding.severity == "medium"


def test_cli_learn_mode_populates_store_without_findings(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\nERROR disk full\n", encoding="utf-8")
    store = tmp_path / "corpus.json"
    exit_code = main([
        "analyze", str(log), "--error-threshold", "100", "--repeat-threshold", "100",
        "--novelty-store", str(store), "--novelty-learn", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["findings"] == []
    assert report["novelty"]["mode"] == "learn"
    assert report["novelty"]["learned_messages"] == 1
    assert report["novelty"]["known_messages"] == 1
    assert len(KnownCorpus.load(store)) == 1


def test_cli_detect_mode_flags_novel_messages(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\nERROR disk full\n", encoding="utf-8")
    store = tmp_path / "corpus.json"
    assert main(["analyze", str(log), "--novelty-store", str(store), "--novelty-learn"]) == 0
    capsys.readouterr()

    log.write_text("ERROR disk full\nERROR something else\n", encoding="utf-8")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "100", "--repeat-threshold", "100",
        "--novelty-store", str(store), "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["novelty"]["mode"] == "detect"
    novel = [f for f in report["findings"] if f["rule"] == "novel-message"]
    assert len(novel) == 1
    assert "something else" in novel[0]["message"]
    # Detect mode never mutates the store.
    assert len(KnownCorpus.load(store)) == 1


def test_cli_novelty_learn_requires_store(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--novelty-learn"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--novelty-learn requires --novelty-store" in captured.err


def test_cli_corrupt_store_is_structured_error(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    store = tmp_path / "corpus.json"
    store.write_text("{oops", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--novelty-store", str(store)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "invalid JSON in novelty store" in captured.err
