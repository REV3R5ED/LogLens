# Changelog

All notable changes to LogLens are documented in this file.

The project follows semantic versioning for portfolio releases. LogLens is a defensive analysis toolkit: findings are explainable triage signals, not incident verdicts.

## [Unreleased]

### Added
- Leading ISO-8601 timestamp recognition for unstructured text logs, allowing common timestamp-first application logs to participate in deterministic time-window baselines without guessing dates embedded later in messages.

### Planned
- Portfolio-ready tagged release after final CI and documentation review.

## [0.2.0] - 2026-09-15

### Added
- Analyst-configurable error and repeated-message detection thresholds with validation.
- Deterministic UTC time-window baselines with timestamp coverage metadata.
- Transparent 0-100 anomaly scoring and score-derived low/medium/high severity.
- Reusable deterministic JSON and long-form CSV report serializers.
- CSV preservation of detection configuration and time-window baseline context.
- CLI integration coverage for text, JSON and CSV reports, filtering, malformed strict-JSON input, and missing-file behavior.
- Optional `--fail-on-finding` CI gate that preserves the full report and returns exit code 3 when anomaly findings are emitted; parse errors retain precedence with exit code 2.

### Changed
- Detection and reporting operate on the explicitly filtered event set and retain effective analysis configuration for reproducibility.
- Reporting is separated from parsing and analysis so machine-readable output can be reused programmatically.

### Safety
- Analysis remains read-only and dependency-light.
- Detection uses visible deterministic thresholds and scoring rather than opaque or offensive behavior.
- Malformed input is treated as data and never executed.

## [0.1.0]

### Added
- Installable Python package and `loglens` CLI.
- Normalized log event model.
- Text and JSON parsers with automatic format detection.
- Case-insensitive level/message filtering and reusable aggregation.
- Explainable elevated-error and repeated-message anomaly rules.
- JSON summary and CSV report output.
- Unit tests and GitHub Actions CI.

[Unreleased]: https://github.com/REV3R5ED/LogLens/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/REV3R5ED/LogLens/releases/tag/v0.2.0
