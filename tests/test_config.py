"""TOML/JSON config files with named policies and per-source overrides."""

import json
import sys

import pytest

from loglens.config import ConfigError, load_policies, resolve_policy


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


_TOML_ONLY = pytest.mark.skipif(
    sys.version_info < (3, 11), reason="stdlib tomllib needs Python 3.11+"
)


@_TOML_ONLY
def test_toml_named_policies_load_with_defaults(tmp_path):
    path = _write(tmp_path, "loglens.toml", """
[policy.default]
error_threshold = 10

[policy.strict]
error_threshold = 1
repeat_threshold = 2
""")
    policies = load_policies(path)
    assert set(policies) == {"default", "strict"}
    assert policies["default"].error_threshold == 10
    assert policies["default"].repeat_threshold == 5  # builtin default preserved
    assert policies["strict"].repeat_threshold == 2


def test_json_config_uses_same_schema(tmp_path):
    path = _write(tmp_path, "loglens.json", json.dumps({
        "policy": {
            "default": {"error_threshold": 7, "burst_window_seconds": 30},
        }
    }))
    policies = load_policies(path)
    assert policies["default"].error_threshold == 7
    assert policies["default"].burst_window_seconds == 30


@_TOML_ONLY
def test_toml_scoring_section_is_parsed(tmp_path):
    path = _write(tmp_path, "loglens.toml", """
[policy.default]

[policy.default.scoring]
base_points = 40
high_cutoff = 90
max_finding_context = 100
""")
    scoring = load_policies(path)["default"].scoring
    assert scoring.base_points == 40
    assert scoring.high_cutoff == 90
    assert scoring.max_finding_context == 100
    assert scoring.medium_cutoff == 60  # untouched default


@_TOML_ONLY
def test_toml_per_source_overrides_are_parsed(tmp_path):
    path = _write(tmp_path, "loglens.toml", """
[policy.default.sources."payments-api"]
error_threshold = 100
repeat_threshold = 50
""")
    sources = load_policies(path)["default"].sources
    assert set(sources) == {"payments-api"}
    assert sources["payments-api"].error_threshold == 100
    assert sources["payments-api"].repeat_threshold == 50
    assert sources["payments-api"].burst_threshold is None


def test_resolve_policy_prefers_explicit_then_default_then_single():
    policies = {
        "default": _policy("default"),
        "strict": _policy("strict"),
    }
    assert resolve_policy(policies, "strict").name == "strict"
    assert resolve_policy(policies, None).name == "default"
    assert resolve_policy({"lonely": _policy("lonely")}, None).name == "lonely"
    with pytest.raises(ConfigError, match="not defined"):
        resolve_policy(policies, "nope")
    with pytest.raises(ConfigError, match="--policy is required"):
        resolve_policy({"a": _policy("a"), "b": _policy("b")}, None)


def _policy(name):
    from loglens.config import DetectionPolicy
    return DetectionPolicy(name=name)


@pytest.mark.parametrize("filename", ["loglens.yaml", "loglens.ini", "loglens.txt"])
def test_unsupported_extensions_are_rejected(tmp_path, filename):
    path = _write(tmp_path, filename, "policy = 1")
    with pytest.raises(ConfigError, match=r"\.toml or \.json"):
        load_policies(path)


def test_missing_config_file_is_rejected(tmp_path):
    with pytest.raises(ConfigError, match="cannot read config file"):
        load_policies(tmp_path / "missing.toml")


@_TOML_ONLY
def test_invalid_toml_is_rejected(tmp_path):
    path = _write(tmp_path, "loglens.toml", "[policy.default\nerror_threshold = ")
    with pytest.raises(ConfigError, match="invalid TOML"):
        load_policies(path)


def test_invalid_json_is_rejected(tmp_path):
    path = _write(tmp_path, "loglens.json", "{not json")
    with pytest.raises(ConfigError, match="invalid JSON"):
        load_policies(path)


def test_missing_policy_table_is_rejected(tmp_path):
    path = _write(tmp_path, "loglens.toml", 'title = "no policies here"')
    with pytest.raises(ConfigError, match="at least one"):
        load_policies(path)


def test_unknown_settings_are_rejected(tmp_path):
    path = _write(tmp_path, "loglens.toml", """
[policy.default]
error_treshold = 10
""")
    with pytest.raises(ConfigError, match="unknown setting"):
        load_policies(path)


@pytest.mark.parametrize("body", ["error_threshold = 0", "repeat_threshold = 1", "burst_window_seconds = -5"])
def test_out_of_range_thresholds_are_rejected(tmp_path, body):
    path = _write(tmp_path, "loglens.toml", f"[policy.default]\n{body}\n")
    with pytest.raises(ConfigError, match="must be an integer"):
        load_policies(path)


def test_invalid_scoring_values_are_rejected(tmp_path):
    path = _write(tmp_path, "loglens.toml", """
[policy.default.scoring]
medium_cutoff = 90
high_cutoff = 70
""")
    with pytest.raises(ConfigError, match="medium_cutoff must be below high_cutoff"):
        load_policies(path)


def test_blank_source_override_names_are_rejected(tmp_path):
    path = _write(tmp_path, "loglens.toml", """
[policy.default.sources."   "]
error_threshold = 10
""")
    with pytest.raises(ConfigError, match="must not be blank"):
        load_policies(path)
