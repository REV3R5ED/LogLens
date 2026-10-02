"""CLI integration: config files drive analysis; explicit flags win."""

import json


from loglens.cli import main


def _write_config(tmp_path, text, name="loglens.toml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def _log_with_sources(tmp_path):
    log = tmp_path / "app.log"
    lines = []
    for _ in range(4):
        lines.append('{"level":"ERROR","message":"noisy failure","source":"noisy"}\n')
    for _ in range(4):
        lines.append('{"level":"ERROR","message":"quiet failure","source":"quiet"}\n')
    log.write_text("".join(lines), encoding="utf-8")
    return log


def test_config_policy_drives_thresholds_and_report(tmp_path, capsys):
    log = _log_with_sources(tmp_path)
    config = _write_config(tmp_path, """
[policy.default]
error_threshold = 3

[policy.default.sources."noisy"]
error_threshold = 100
""")
    exit_code = main(["analyze", str(log), "--format", "json", "--config", str(config), "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["policy"] == "default"
    assert report["detection_config"]["error_threshold"] == 3
    assert report["source_overrides"] == {"noisy": {"error_threshold": 100}}
    # noisy is silenced by its override; quiet trips the policy threshold of 3.
    messages = [finding["message"] for finding in report["findings"] if finding["rule"] == "elevated-errors"]
    assert messages == ["Elevated error-level event count [quiet]"]


def test_explicit_cli_flags_override_config_values(tmp_path, capsys):
    log = _log_with_sources(tmp_path)
    config = _write_config(tmp_path, "[policy.default]\nerror_threshold = 100\n")
    exit_code = main([
        "analyze", str(log), "--format", "json",
        "--config", str(config), "--error-threshold", "3", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["detection_config"]["error_threshold"] == 3
    assert len([f for f in report["findings"] if f["rule"] == "elevated-errors"]) == 2


def test_named_policy_selection(tmp_path, capsys):
    log = _log_with_sources(tmp_path)
    config = _write_config(tmp_path, """
[policy.default]
error_threshold = 100

[policy.strict]
error_threshold = 3
""")
    exit_code = main([
        "analyze", str(log), "--format", "json",
        "--config", str(config), "--policy", "strict", "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["policy"] == "strict"
    assert report["detection_config"]["error_threshold"] == 3


def test_unknown_policy_is_a_structured_error(tmp_path, capsys):
    log = _log_with_sources(tmp_path)
    config = _write_config(tmp_path, "[policy.default]\n")
    exit_code = main(["analyze", str(log), "--config", str(config), "--policy", "nope"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert captured.out == ""
    assert "loglens: ERROR:" in captured.err
    assert "'nope' is not defined" in captured.err


def test_policy_flag_requires_config(tmp_path, capsys):
    log = _log_with_sources(tmp_path)
    exit_code = main(["analyze", str(log), "--policy", "strict"])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert "--policy requires --config" in captured.err


def test_config_scoring_changes_report_scores(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("ERROR disk full\nERROR disk full\n", encoding="utf-8")
    config = _write_config(tmp_path, """
[policy.default.scoring]
medium_cutoff = 95
high_cutoff = 99
""")
    exit_code = main([
        "analyze", str(log), "--error-threshold", "2", "--repeat-threshold", "2",
        "--config", str(config), "--json",
    ])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scoring_config"]["medium_cutoff"] == 95
    assert report["scoring_config"]["high_cutoff"] == 99
    assert report["findings"]
    assert all(finding["severity"] == "low" for finding in report["findings"])


def test_default_run_reports_default_policy_and_scoring(tmp_path, capsys):
    log = tmp_path / "app.log"
    log.write_text("INFO ok\n", encoding="utf-8")
    exit_code = main(["analyze", str(log), "--json"])
    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["policy"] == "default"
    assert report["scoring_config"] == {
        "base_points": 50, "excess_points": 25, "prevalence_points": 25,
        "medium_cutoff": 60, "high_cutoff": 80, "max_finding_context": 240,
    }
    assert "source_overrides" not in report
    # detection_config keeps its historical shape for downstream consumers.
    assert report["detection_config"] == {
        "error_threshold": 5, "repeat_threshold": 5,
        "burst_threshold": 5, "burst_window_seconds": 60,
    }
