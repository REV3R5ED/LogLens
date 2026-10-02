"""python -m loglens must work as an alias for the console script."""

from __future__ import annotations

import subprocess
import sys

import loglens


def test_module_entry_point_reports_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "loglens", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == f"loglens {loglens.__version__}"
    assert result.stderr == ""


def test_module_entry_point_runs_analyze(tmp_path) -> None:
    log = tmp_path / "app.log"
    log.write_text("INFO healthy\n", encoding="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "loglens", "analyze", str(log)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "LogLens:" in result.stdout
