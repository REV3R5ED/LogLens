import json

from loglens.cli import main


def test_cli_rfc5424_format_normalizes_syslog_and_supports_filters(tmp_path, capsys):
    log = tmp_path / "syslog.log"
    log.write_text(
        '<11>1 2026-09-18T20:00:00Z edge-1 sshd 42 AUTH - authentication failed\n'
        '<14>1 2026-09-18T20:00:01Z edge-1 scheduler 43 JOB - healthy\n',
        encoding="utf-8",
    )

    exit_code = main([
        "analyze", str(log), "--format", "rfc5424", "--source", "sshd", "--json",
    ])

    assert exit_code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["input_events"] == 2
    assert report["matched_events"] == 1
    assert report["parse_errors"] == 0
    assert report["levels"] == {"ERROR": 1}
    assert report["source_health"][0]["source"] == "sshd"


def test_cli_rfc5424_strict_mode_counts_malformed_records(tmp_path, capsys):
    log = tmp_path / "syslog.log"
    log.write_text(
        '<14>1 2026-09-18T20:00:00Z edge-1 app 1 OK - healthy\n'
        'not an RFC5424 record\n',
        encoding="utf-8",
    )

    exit_code = main(["analyze", str(log), "--format", "rfc5424", "--json"])

    assert exit_code == 2
    report = json.loads(capsys.readouterr().out)
    assert report["input_events"] == 2
    assert report["matched_events"] == 1
    assert report["parse_errors"] == 1
