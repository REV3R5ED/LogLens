# Changelog

All notable changes to LogLens are documented in this file.

The project follows semantic versioning for portfolio releases. LogLens is a defensive analysis toolkit: findings are explainable triage signals, not incident verdicts.

## [Unreleased]

### Added
- OpenTelemetry JSON `body` AnyValues now normalize unambiguous `arrayValue` and `kvlistValue` payloads recursively into deterministic compact JSON messages, while malformed or ambiguous shapes remain preserved rather than guessed.
- JSON parsing recognizes nested `service.name` and OpenTelemetry resource `service.name` attributes as logical event sources, improving per-service filtering, aggregation, and source-scoped anomaly detection while preserving explicit source precedence and raw telemetry context.
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