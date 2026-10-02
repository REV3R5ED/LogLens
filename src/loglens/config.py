"""Named detection policies loaded from TOML or JSON config files.

A config file makes analyst-tuned detection reproducible: instead of
remembering a long ``loglens analyze`` command line, a team stores thresholds,
scoring weights, and per-source overrides in a versioned file and selects a
named policy with ``--policy``. Explicit CLI flags always override the values
coming from the config file.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .detection import ScoringConfig, SourceThresholds, _normalize_source


class ConfigError(ValueError):
    """Raised when a LogLens config file is missing, unreadable, or invalid."""


@dataclass(frozen=True, slots=True)
class DetectionPolicy:
    """One named set of detection thresholds, scoring weights, and overrides."""

    name: str
    error_threshold: int = 5
    repeat_threshold: int = 5
    burst_threshold: int = 5
    burst_window_seconds: int = 60
    scoring: ScoringConfig = field(default_factory=ScoringConfig)
    sources: dict[str, SourceThresholds] = field(default_factory=dict)


#: Policy used when no ``--config`` file is supplied; matches CLI defaults.
DEFAULT_POLICY = DetectionPolicy(name="default")


_POLICY_KEYS = frozenset({
    "error_threshold", "repeat_threshold", "burst_threshold",
    "burst_window_seconds", "scoring", "sources",
})
_SCORING_KEYS = frozenset({
    "base_points", "excess_points", "prevalence_points",
    "medium_cutoff", "high_cutoff", "max_finding_context",
})
_SOURCE_KEYS = frozenset({
    "error_threshold", "repeat_threshold", "burst_threshold", "burst_window_seconds",
})
_THRESHOLD_BOUNDS = {
    "error_threshold": 1,
    "repeat_threshold": 2,
    "burst_threshold": 2,
    "burst_window_seconds": 1,
}


def _read_mapping(path: Path) -> dict[str, Any]:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc}") from exc
    suffix = path.suffix.lower()
    if suffix == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ConfigError(f"invalid JSON in config file {path}: {exc}") from exc
    elif suffix == ".toml":
        try:
            import tomllib
        except ImportError:
            raise ConfigError(
                f"TOML config {path} requires Python 3.11 or newer; "
                "use a .json config file with the same schema instead"
            )
        try:
            data = tomllib.loads(text)
        except Exception as exc:
            raise ConfigError(f"invalid TOML in config file {path}: {exc}") from exc
    else:
        raise ConfigError(f"config file {path} must use a .toml or .json extension")
    if not isinstance(data, dict):
        raise ConfigError(f"config file {path} must contain a top-level object")
    return data


def _unknown_keys(mapping: Mapping[str, Any], known: frozenset[str], where: str) -> None:
    unknown = sorted(set(mapping) - known)
    if unknown:
        raise ConfigError(f"{where}: unknown setting(s) {', '.join(unknown)}; expected only {', '.join(sorted(known))}")


def _checked_int(value: Any, *, name: str, minimum: int, where: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ConfigError(f"{where}: {name} must be an integer >= {minimum}, got {value!r}")
    return value


def _parse_scoring(raw: Any, where: str) -> ScoringConfig:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: scoring must be an object")
    _unknown_keys(raw, _SCORING_KEYS, f"{where}.scoring")
    values: dict[str, int] = {}
    for key in _SCORING_KEYS:
        if key in raw:
            values[key] = _checked_int(raw[key], name=key, minimum=0, where=f"{where}.scoring")
    try:
        return ScoringConfig(**values)
    except ValueError as exc:
        raise ConfigError(f"{where}.scoring: {exc}") from exc


def _parse_source_thresholds(raw: Any, where: str) -> SourceThresholds:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: source overrides must be an object")
    _unknown_keys(raw, _SOURCE_KEYS, where)
    values: dict[str, int] = {}
    for key in _SOURCE_KEYS:
        if key in raw:
            values[key] = _checked_int(raw[key], name=key, minimum=_THRESHOLD_BOUNDS[key], where=where)
    try:
        return SourceThresholds(**values)
    except ValueError as exc:
        raise ConfigError(f"{where}: {exc}") from exc


def _parse_policy(name: str, raw: Any, path: Path) -> DetectionPolicy:
    where = f"{path}: policy {name!r}"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where} must be an object")
    _unknown_keys(raw, _POLICY_KEYS, where)
    scoring = _parse_scoring(raw.get("scoring", {}), where) if "scoring" in raw else ScoringConfig()
    sources: dict[str, SourceThresholds] = {}
    if "sources" in raw:
        raw_sources = raw["sources"]
        if not isinstance(raw_sources, dict):
            raise ConfigError(f"{where}: sources must be an object mapping source names to overrides")
        for source_name, overrides in raw_sources.items():
            normalized = _normalize_source(str(source_name))
            if not normalized:
                raise ConfigError(f"{where}: source override names must not be blank")
            if normalized in sources:
                raise ConfigError(f"{where}: duplicate source override for {normalized!r}")
            sources[normalized] = _parse_source_thresholds(overrides, f"{where}.sources[{normalized!r}]")
    thresholds = {
        key: _checked_int(raw[key], name=key, minimum=_THRESHOLD_BOUNDS[key], where=where)
        for key in _THRESHOLD_BOUNDS
        if key in raw
    }
    return DetectionPolicy(name=name, scoring=scoring, sources=sources, **thresholds)


def load_policies(path: Path | str) -> dict[str, DetectionPolicy]:
    """Load named detection policies from a TOML or JSON config file.

    TOML example::

        [policy.default]
        error_threshold = 10

        [policy.default.scoring]
        high_cutoff = 85

        [policy.default.sources."payments-api"]
        error_threshold = 100

    The JSON schema mirrors the TOML structure under a top-level
    ``{"policy": {...}}`` object.
    """
    config_path = Path(path)
    data = _read_mapping(config_path)
    raw_policies = data.get("policy")
    if not isinstance(raw_policies, dict) or not raw_policies:
        raise ConfigError(f"{config_path}: config must define at least one [policy.<name>] table")
    policies: dict[str, DetectionPolicy] = {}
    for name, raw in raw_policies.items():
        if name in policies:
            raise ConfigError(f"{config_path}: duplicate policy {name!r}")
        policies[name] = _parse_policy(str(name), raw, config_path)
    return policies


def resolve_policy(policies: Mapping[str, DetectionPolicy], name: str | None) -> DetectionPolicy:
    """Select the active policy: explicit ``--policy``, else ``default``, else the only policy."""
    if name is not None:
        if name not in policies:
            available = ", ".join(sorted(policies))
            raise ConfigError(f"policy {name!r} is not defined (available: {available})")
        return policies[name]
    if "default" in policies:
        return policies["default"]
    if len(policies) == 1:
        return next(iter(policies.values()))
    raise ConfigError("--policy is required: the config defines multiple policies and none is named 'default'")
