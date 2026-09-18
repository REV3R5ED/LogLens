from importlib.metadata import version

import loglens


def test_runtime_version_matches_package_metadata() -> None:
    assert loglens.__version__ == version("loglens")


def test_portfolio_release_version() -> None:
    assert loglens.__version__ == "0.3.0"
