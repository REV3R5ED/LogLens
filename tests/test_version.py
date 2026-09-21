from __future__ import annotations

import subprocess
import sys
from importlib.metadata import version

import loglens


def test_runtime_version_matches_package_metadata() -> None:
    assert loglens.__version__ == version("loglens")


def test_portfolio_release_version() -> None:
    assert loglens.__version__ == "0.4.0"


def test_cli_version_reports_runtime_version() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "loglens.cli", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == f"loglens {loglens.__version__}"
    assert result.stderr == ""
