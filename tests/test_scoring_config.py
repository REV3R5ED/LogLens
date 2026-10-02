"""Scoring weights, severity cutoffs, and context bounds are tunable via config."""

import pytest

from loglens.detection import (
    ScoringConfig,
    SourceThresholds,
    detect_anomalies,
)
from loglens.model import LogEvent


def _events():
    return [
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="disk full", level="ERROR", source="api"),
        LogEvent(message="ok", level="INFO", source="api"),
    ]


def test_default_scoring_reproduces_historical_weights():
    scoring = ScoringConfig()
    assert (scoring.base_points, scoring.excess_points, scoring.prevalence_points) == (50, 25, 25)
    assert (scoring.medium_cutoff, scoring.high_cutoff) == (60, 80)
    assert scoring.max_finding_context == 240


def test_custom_weights_change_scores_transparently():
    default = detect_anomalies(_events(), error_threshold=2)[0]
    boosted = detect_anomalies(
        _events(), error_threshold=2, scoring=ScoringConfig(excess_points=50, prevalence_points=0)
    )[0]
    assert boosted.score != default.score
    # 3 errors vs threshold 2 from 4 events: 50 + min(50, round(50*1/2)) + 0 = 75
    assert boosted.score == 75


def test_custom_cutoffs_change_severity_labels():
    findings = detect_anomalies(_events(), error_threshold=2)
    assert findings[0].score == 81
    assert findings[0].severity == "high"
    strict = detect_anomalies(
        _events(), error_threshold=2, scoring=ScoringConfig(medium_cutoff=90, high_cutoff=95)
    )
    assert strict[0].score == findings[0].score
    assert strict[0].severity == "low"


def test_max_finding_context_is_tunable():
    long_message = "x" * 500
    events = [LogEvent(message=long_message, level="ERROR", source="api") for _ in range(3)]
    default = detect_anomalies(events, repeat_threshold=2)[0]
    assert default.message.endswith("...")
    assert len(default.message) > 100
    tight = detect_anomalies(events, repeat_threshold=2, scoring=ScoringConfig(max_finding_context=40))[0]
    assert tight.message.endswith("...")
    assert len(tight.message) == len("Repeated message [api]: ") + 40


@pytest.mark.parametrize(
    "kwargs",
    [
        {"base_points": -1},
        {"excess_points": -5},
        {"medium_cutoff": 0},
        {"high_cutoff": 101},
        {"medium_cutoff": 80, "high_cutoff": 80},
        {"medium_cutoff": 90, "high_cutoff": 70},
        {"max_finding_context": 0},
        {"base_points": True},
    ],
)
def test_invalid_scoring_configs_are_rejected(kwargs):
    with pytest.raises(ValueError):
        ScoringConfig(**kwargs)


def test_scoring_config_round_trips_through_dict():
    scoring = ScoringConfig(base_points=40, excess_points=30, prevalence_points=20,
                            medium_cutoff=55, high_cutoff=85, max_finding_context=100)
    assert ScoringConfig(**scoring.to_dict()) == scoring


def test_per_source_overrides_leave_other_sources_on_global_thresholds():
    events = [
        LogEvent(message="boom", level="ERROR", source="noisy"),
        LogEvent(message="boom", level="ERROR", source="noisy"),
        LogEvent(message="boom", level="ERROR", source="noisy"),
        LogEvent(message="boom", level="ERROR", source="quiet"),
        LogEvent(message="boom", level="ERROR", source="quiet"),
        LogEvent(message="boom", level="ERROR", source="quiet"),
    ]
    findings = detect_anomalies(
        events, error_threshold=5, source_overrides={"noisy": SourceThresholds(error_threshold=3)}
    )
    assert [finding.message for finding in findings] == ["Elevated error-level event count [noisy]"]


def test_per_source_repeat_override_applies_within_source_scope():
    events = [
        LogEvent(message="same", level="ERROR", source="chatty"),
        LogEvent(message="same", level="ERROR", source="chatty"),
        LogEvent(message="same", level="ERROR", source="chatty"),
        LogEvent(message="same", level="ERROR", source="calm"),
        LogEvent(message="same", level="ERROR", source="calm"),
        LogEvent(message="same", level="ERROR", source="calm"),
    ]
    findings = detect_anomalies(
        events, repeat_threshold=5, source_overrides={"chatty": SourceThresholds(repeat_threshold=3)}
    )
    rules = {(finding.rule, finding.message) for finding in findings}
    assert ("repeated-message", "Repeated message [chatty]: same") in rules
    assert not any(message.endswith("[calm]: same") for _, message in rules)


def test_source_threshold_bounds_are_validated():
    with pytest.raises(ValueError):
        SourceThresholds(error_threshold=0)
    with pytest.raises(ValueError):
        SourceThresholds(repeat_threshold=1)
    with pytest.raises(ValueError):
        SourceThresholds(burst_window_seconds=0)
    assert SourceThresholds(error_threshold=2).to_dict() == {"error_threshold": 2}
    assert SourceThresholds().to_dict() == {}


def test_no_overrides_matches_global_behavior_exactly():
    events = _events()
    assert detect_anomalies(events, error_threshold=2) == detect_anomalies(
        events, error_threshold=2, source_overrides={}
    )
