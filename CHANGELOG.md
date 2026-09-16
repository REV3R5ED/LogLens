# Changelog

All notable changes to LogLens are documented in this file.

The project follows semantic versioning for portfolio releases. LogLens is a defensive analysis toolkit: findings are explainable triage signals, not incident verdicts.

## [Unreleased]

### Added
- Leading ISO-8601 timestamp recognition for unstructured text logs, allowing common timestamp-first application logs to participate in deterministic time-window baselines without guessing dates embedded later in messages.
- Bracketed leading ISO-8601 timestamps are recognized in both compact (`[YYYY-MM-DDTHH:MM:SSZ]`) and split (`[YYYY-MM-DD HH:MM:SS]`) forms, improving compatibility with common application-log layouts.
- Repeated-message anomaly detection now scopes identical messages by event source when source metadata is available, reducing cross-service false positives and exposing the source in finding context.

### Changed
- Repeated-message prevalence scoring now uses the matching source's event population, so unrelated services cannot dilute the severity of a concentrated source-local signal.
- Repeated-message detection now also scopes identical text by normalized severity level, preventing mixed INFO/WARN/ERROR events with the same message from being combined into a misleading repetition finding.
- Severity normalization now trims surrounding whitespace and canonicalizes common application/syslog labels (`WARNING` to `WARN`, `ERR` to `ERROR`, `FATAL`/`CRIT`/`ALERT`/`EMERG`/`EMERGENCY` to `CRITICAL`, and `INFORMATION`/`INFORMATIONAL` to `INFO`) across JSON and text inputs, preventing equivalent severities from fragmenting aggregates and anomaly analysis.

### Fixed
- Timestamp-first text logs using the common `YYYY-MM-DD HH:MM:SS` form now preserve their time-of-day (and optional UTC offset) instead of interpreting the leading date alone as midnight.

### Security
- CSV report serialization now neutralizes untrusted text beginning with spreadsheet formula prefixes (`=`, `+`, `-`, `@`) while preserving numeric values, reducing formula-injection risk when analysts open exported reports in spreadsheet applications.
- CSV formula-injection protection now also detects dangerous prefixes hidden behind leading spaces, tabs, carriage returns, or newlines while preserving benign whitespace.

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
