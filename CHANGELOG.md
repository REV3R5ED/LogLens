# Changelog

All notable changes to LogLens are documented in this file.

The project follows semantic versioning for portfolio releases. LogLens is a defensive analysis toolkit: findings are explainable triage signals, not incident verdicts.

## [Unreleased]

### Added
- JSON parsing now recognizes common flat ECS/logging aliases: `@timestamp` and `ts` for event time and `log.level` for severity, while preserving canonical-field precedence and retaining unrelated structured context.
- Leading ISO-8601 timestamp recognition for unstructured text logs, allowing common timestamp-first application logs to participate in deterministic time-window baselines without guessing dates embedded later in messages.
- Bracketed leading ISO-8601 timestamps are recognized in both compact (`[YYYY-MM-DDTHH:MM:SSZ]`) and split (`[YYYY-MM-DD HH:MM:SS]`) forms, improving compatibility with common application-log layouts.
- Repeated-message anomaly detection now scopes identical messages by event source when source metadata is available, reducing cross-service false positives and exposing the source in finding context.
- Text parsing now recognizes explicit logfmt-style `level=<value>` and `severity=<value>` fields, including canonical severity aliases, while ignoring unrelated key-value fields to avoid accidental severity classification.
- Text parsing now recognizes explicit logfmt-style `ts=<ISO-8601>`, `timestamp=<ISO-8601>`, and `time=<ISO-8601>` fields so structured text logs can participate in time-window baselines without treating unrelated timestamp-like fields as event time.

### Changed
- Time-window baseline sizing now requires an actual integer from 1 to 1440 minutes; booleans, floats, strings, and null-like values fail clearly before aggregation instead of relying on Python coercion or comparison behavior.
- Anomaly thresholds now require actual integer values in programmatic use; floats, non-finite numbers, booleans, and strings are rejected before analysis so scoring remains deterministic and configuration mistakes fail clearly.
- Repeated-message prevalence scoring now uses the same source-and-severity scope as repetition detection, so unrelated services or different-severity traffic cannot dilute a concentrated signal.
- Repeated-message detection now also scopes identical text by normalized severity level, preventing mixed INFO/WARN/ERROR events with the same message from being combined into a misleading repetition finding.
- Severity normalization now trims surrounding whitespace and canonicalizes common application/syslog labels (`WARNING` to `WARN`, `ERR` to `ERROR`, `FATAL`/`CRIT`/`ALERT`/`EMERG`/`EMERGENCY` to `CRITICAL`, and `INFORMATION`/`INFORMATIONAL` to `INFO`) across JSON and text inputs, preventing equivalent severities from fragmenting aggregates and anomaly analysis.

### Fixed
- Timestamp-first text logs using the common `YYYY-MM-DD HH:MM:SS` form now preserve their time-of-day (and optional UTC offset) instead of interpreting the leading date alone as midnight.

### Security
- Analyst-facing repeated-message findings now escape ASCII control characters in untrusted log messages and source labels, preventing embedded newlines, terminal escape bytes, NULs, and similar controls from altering terminal/report presentation while preserving them as visible escape notation.
- CSV report serialization now neutralizes untrusted text beginning with spreadsheet formula prefixes (`=`, `+`, `-`, `@`) while preserving numeric values, reducing formula-injection risk when analysts open exported reports in spreadsheet applications.
- CSV formula-injection protection now detects dangerous prefixes hidden behind leading ASCII or Unicode whitespace while preserving the original cell text, covering non-breaking, em, narrow no-break, and ideographic spaces in addition to spaces, tabs, carriage returns, and newlines.

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
- Read-only local-file analysis only; no network access or state-changing actions.
- Malformed records are handled deterministically and never interpreted as executable content.
