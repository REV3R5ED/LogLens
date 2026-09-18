# Changelog

All notable changes to LogLens are documented in this file.

The project follows semantic versioning for portfolio releases. LogLens is a defensive analysis toolkit: findings are explainable triage signals, not incident verdicts.

## [Unreleased]

### Added
- Local `.gz` log files are transparently decompressed during analysis, allowing rotated/compressed logs to be inspected without a manual extraction step while preserving normal parsing, filtering, detection, and reporting behavior.
- `loglens analyze -` reads logs from standard input, enabling safe Unix pipelines and container/CI workflows without temporary files; reports identify the input as `<stdin>` and preserve normal parse-error and finding exit-code semantics.
- `--fail-on-severity {low,medium,high}` lets CI and scripted defensive analysis fail only when a finding reaches an analyst-selected severity threshold; the existing `--fail-on-finding` behavior remains available as the equivalent of a low-severity gate.

## [0.3.0] - 2026-09-17

### Added
- JSON parsing recognizes OpenTelemetry `timeUnixNano` and `observedTimeUnixNano` timestamps supplied as integer or decimal-string nanoseconds, converting them to UTC while preserving canonical event-time precedence and rejecting malformed values safely.
- JSON parsing recognizes OpenTelemetry JSON camelCase `severityText` and `observedTimestamp` aliases, while preserving existing canonical/snake_case precedence and retaining unrelated telemetry context.
- JSON parsing recognizes OpenTelemetry-style `observed_timestamp` as an ISO-8601 event-time fallback, while preserving canonical timestamp precedence.
- JSON parsing recognizes OpenTelemetry-style `severity_text` and `body` aliases while preserving canonical `level`/`message` precedence and retaining unrelated telemetry context such as trace identifiers.
- JSON parsing recognizes nested ECS `log.level` objects and common flat ECS/logging aliases such as `@timestamp`, `ts`, and `log.level`, with explicit precedence rules.
- Leading and bracketed ISO-8601 timestamps are recognized in unstructured text logs, including compact and split timestamp forms.
- Repeated-message anomaly detection scopes identical messages by event source when source metadata is available, reducing cross-service false positives and exposing source context.
- Text parsing recognizes explicit logfmt-style `level=<value>` and `severity=<value>` fields, including canonical severity aliases.
- Text parsing recognizes explicit logfmt-style `ts=<ISO-8601>`, `timestamp=<ISO-8601>`, and `time=<ISO-8601>` fields for deterministic time-window analysis.

### Changed
- Time-window baseline sizing requires an actual integer from 1 to 1440 minutes; booleans, floats, strings, and null-like values fail clearly before aggregation.
- Anomaly thresholds require actual integer values in programmatic use so scoring remains deterministic and configuration mistakes fail clearly.
- Repeated-message prevalence scoring uses the same source-and-severity scope as repetition detection.
- Repeated-message detection scopes identical text by normalized severity level, preventing mixed-severity traffic from being combined into a misleading finding.
- Severity normalization trims surrounding whitespace and canonicalizes common application/syslog severity aliases across JSON and text inputs.

### Fixed
- Timestamp-first text logs using the common `YYYY-MM-DD HH:MM:SS` form preserve their time-of-day and optional UTC offset instead of interpreting the leading date alone as midnight.

### Security
- Analyst-facing repeated-message findings escape ASCII control characters in untrusted log messages and source labels so terminal/report presentation cannot be altered by embedded controls.
- CSV report serialization neutralizes untrusted text beginning with spreadsheet formula prefixes while preserving numeric values.
- CSV formula-injection protection detects dangerous prefixes hidden behind leading ASCII or Unicode whitespace.

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
- Installable Python package and CLI.
- Normalized log event model.
- Text and JSON parsers with automatic format detection.
- Case-insensitive level/message filtering and reusable aggregation.
- Explainable elevated-error and repeated-message anomaly rules.
- JSON summary and CSV report output.
- Unit tests and GitHub Actions CI.

[Unreleased]: https://github.com/REV3R5ED/LogLens/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/REV3R5ED/LogLens/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/REV3R5ED/LogLens/releases/tag/v0.2.0
