# LogLens

Lightweight log analysis and anomaly detection for defensive operations.

> Status: active development / v0.4 release hardening

## Why LogLens

LogLens turns local text, JSON, RFC 5424, and common OpenTelemetry-style logs into deterministic, explainable defensive signals without requiring a heavyweight SIEM. Detection uses visible thresholds and reproducible scoring rather than opaque models, and JSON/CSV reports preserve the effective analysis configuration for later review.

**Reviewer path:** [run the reproducible portfolio demo](docs/portfolio-demo.md) for a short synthetic scenario, then see [related portfolio projects](docs/related-projects.md) for the broader defensive-security toolkit.

## Goals

LogLens helps analysts quickly turn raw logs into useful defensive signals without requiring a heavyweight SIEM stack.

Current capabilities:

- installable Python package, `loglens` CLI, and `python -m loglens` entry point
- normalized `LogEvent` records
- JSON log parsing with common field aliases, including OpenTelemetry `severityText`/`severityNumber` and Unix-nanosecond timestamps
- unstructured text parsing with level detection and leading ISO-8601 timestamp recognition
- strict RFC 5424 syslog parsing with normalized PRI severity, timestamp, source, and retained header metadata
- automatic JSON/text detection
- preservation of unknown JSON fields for later analysis
- case-insensitive level and message filtering
- reusable level/source aggregation and per-source health summaries
- deterministic anomaly rules for elevated errors, repeated messages, timestamp-aware error bursts, and never-before-seen (novel) messages
- analyst-configurable detection thresholds with safe validation, via CLI flags or versioned TOML/JSON config files with named policies and per-source overrides
- tunable 0-100 anomaly scoring weights and severity cutoffs
- deterministic UTC time-window baselines for timestamped events, plus baseline diffing against saved reference reports
- live `--follow`/`--watch` tail mode that emits findings as thresholds trip
- streaming parse→filter→detect pipeline (no full event list in memory) with `--progress` reporting
- structured `logging` diagnostics on stderr (`-v`/`--verbose`); reports stay on stdout
- reusable deterministic JSON and long-form CSV report serializers
- CSV preservation of effective detection configuration and time-window baselines
- CLI integration coverage for text, JSON, RFC 5424, CSV, filtering, parse failures, and operational errors
- automated tests across supported Python versions

## Quick start

```bash
python -m pip install -e .
loglens analyze /path/to/app.log
python -m loglens analyze /path/to/app.log   # module entry point also works
loglens analyze /path/to/events.jsonl --format json --json
loglens analyze /path/to/forwarded.log --format rfc5424 --json
loglens analyze /path/to/app.log --level ERROR --level WARN
loglens analyze /path/to/app.log --contains "database" --json
loglens analyze /path/to/app.log --error-threshold 10 --repeat-threshold 8 --json
loglens analyze /path/to/events.jsonl --window-minutes 5 --json
loglens analyze /path/to/events.jsonl --window-minutes 5 --csv > report.csv
loglens analyze /var/log/app.log --follow --fail-on-severity medium   # live tail
loglens analyze /path/to/app.log --config loglens.toml --policy strict --json
pytest -q
```

For a short end-to-end reviewer scenario, see the [reproducible portfolio demo](docs/portfolio-demo.md). It creates a local synthetic service log, triggers explainable findings, and exports JSON/CSV results without network access.

`--level` can be repeated and combined with `--contains`. Reports distinguish total input records from records matching the active filters, so filtering remains visible and auditable. Detection runs only on the matched event set. `--json` and `--csv` are mutually exclusive report formats.

Detection thresholds can be tuned per analysis with `--error-threshold` and `--repeat-threshold`. The defaults remain 5 and 5. Error thresholds must be at least 1 and repeat thresholds at least 2, preventing nonsensical configurations. Machine-readable reports include the effective detection configuration so saved results remain reproducible and auditable.

For repeatable runs, thresholds (plus scoring weights and per-source overrides) can live in a versioned TOML or JSON config file with named policies: `loglens analyze app.log --config loglens.toml --policy strict`. Explicit CLI flags always override config file values. See [Detection policies](docs/configuration.md).

### RFC 5424 syslog

Use `--format rfc5424` when the input contract is RFC 5424 syslog. LogLens normalizes PRI severity, timestamp, and logical source while retaining common syslog header metadata. Parsing is deliberately strict: malformed records count as parse errors rather than being silently reinterpreted as generic text, and `--max-parse-errors N` can bound known input noise. See [RFC 5424 syslog analysis](docs/rfc5424.md) for examples and parser behavior.

### OpenTelemetry JSON compatibility

LogLens recognizes common OpenTelemetry LogRecord fields without adding an SDK dependency. `severityText` is preferred when present; otherwise `severityNumber` values 1-24 are mapped by the standard TRACE, DEBUG, INFO, WARN, ERROR, and FATAL ranges, with the FATAL range normalized to LogLens `CRITICAL`. Invalid or out-of-range numbers remain `UNKNOWN` rather than being guessed. `timeUnixNano` and `observedTimeUnixNano` are converted to UTC timestamps, while unrelated telemetry context remains available in `fields`.

### Source health summaries

`loglens.analysis.summarize_sources()` provides a reusable per-source view of event volume, error-level event count, error rate, and level distribution. This makes it easier to distinguish a broadly noisy dataset from errors concentrated in one service or component without turning the observation into an incident verdict. Missing or blank source values remain visible as `<unknown>`, error rates are deterministic to four decimal places, and results are sorted by source for stable downstream reporting.

### Time-window baselines

Use `--window-minutes N` to group matched, timestamped events into fixed UTC windows from 1 minute through 24 hours. Each window records its start/end, total event count, error-level count, and deterministic level distribution. Windows align to Unix-epoch boundaries, making repeated analyses comparable even when input ordering changes. Events without a parsed timestamp remain part of the normal summary and detection flow but are explicitly excluded from the baseline; the report records `timestamped_events` so that coverage is visible. Offset-less ISO timestamps are interpreted as UTC for deterministic cross-system behavior.

Timestamp coverage is available for both structured JSON logs and common text logs that begin with an ISO-8601 timestamp, for example `2026-09-15T10:00:00Z ERROR database unavailable`. Text parsing intentionally considers only the leading token so dates mentioned later in free-form messages are not guessed to be event timestamps.

Time windows are descriptive baselines rather than incident verdicts. They provide a stable foundation for scoring while keeping analysis transparent and reproducible.

### Anomaly scoring

Every finding includes a deterministic score from 0 to 100. A rule that reaches its configured threshold starts at 50 points. Up to 25 additional points reflect how far the observed count exceeds the threshold, and up to 25 reflect the finding's prevalence across the matched event set. Scores below 60 are `low`, 60-79 are `medium`, and 80 or above are `high`. This is deliberately simple and explainable: the score is a triage aid, not a probability or incident verdict.

The weights (50/25/25), cutoffs (60/80), and finding-context bound are tunable per policy in a [config file](docs/configuration.md); JSON reports record the effective `scoring_config`.

### Detection policies

`--config loglens.toml` (or `.json`) loads named detection policies so runs are reproducible without long command lines. Policies set global thresholds, scoring weights, and per-source threshold overrides — for example, raising `error_threshold` for one noisy service instead of weakening detection globally. `--policy <name>` selects a policy; explicit CLI flags always override file values. See [Detection policies](docs/configuration.md).

### Live tail mode

`loglens analyze /var/log/app.log --follow` (alias `--watch`) tails a growing file and emits findings as thresholds trip, reusing the detector and `--fail-on-severity` exit semantics. Text mode prints findings as they appear; `--json` emits one JSON object per scan (JSONL). Truncation restarts from the beginning; `--watch-timeout` bounds the run. See [Live analysis](docs/live-analysis.md).

### Baseline diff

`--baseline-diff reference.json` (with `--window-minutes`) compares the current run's deterministic UTC windows against a saved report and emits `baseline-drift` findings when a window's absolute error-rate delta reaches `--baseline-diff-threshold` (default 0.2). Drift scores reuse the transparent scale, and new windows with errors produce low-severity `baseline-new-window` findings. See [Live analysis](docs/live-analysis.md).

### Novelty detection

`--novelty-store corpus.json` enables the `novel-message` rule, which flags `(source, level, message)` combinations never observed in a persisted JSON corpus — the complement to `repeated-message`. Bootstrap with `--novelty-learn` (updates the store, emits no findings); detection runs never mutate the store. See [Live analysis](docs/live-analysis.md).

### Streaming analysis

Parsing, filtering, and detection run as a single lazy pass — the full event list is never materialized, so multi-gigabyte logs stay bounded by distinct sources/messages rather than total record count. Rule semantics are identical to the list-based path. `--progress` logs input progress to stderr, and `-v`/`--verbose` enables debug diagnostics; reports always stay on stdout.

### Reusable reports

JSON and CSV output share reusable serializers in `loglens.reporting`, keeping formatting separate from parsing and detection. JSON is deterministic and human-readable. CSV uses the stable long-form columns `record_type,name,value,severity,score,message`; in addition to summaries, aggregates, and findings, it preserves the effective detection thresholds and time-baseline metadata. Time-window rows carry the window start, event count, error-event count, and a deterministic JSON level distribution so spreadsheet exports do not silently lose baseline context. Log-derived commas and quotes are escaped by Python's standard CSV writer.

Example JSON lines input:

```json
{"timeUnixNano":"1789466400000000000","severityNumber":17,"body":"disk full","host":"web-1"}
```

LogLens normalizes the timestamp, severity, message and source while retaining fields such as `host` for future filtering and detection rules.

## Built-in anomaly rules

The detector intentionally favors explainability over opaque scoring. It reports an `elevated-errors` finding when a logical source reaches the configured number of ERROR/CRITICAL/FATAL events, a `repeated-message` finding when the same non-empty message reaches its configured threshold within a source/level scope, an `error-burst` finding when timestamped error events from one source cluster inside the configured burst window, and a `novel-message` finding when a `(source, level, message)` combination was never observed in the `--novelty-store` reference corpus. Burst timestamps are normalized to UTC before comparison, including explicit offsets; offset-less timestamps are treated as UTC consistently with LogLens baseline behavior. `--baseline-diff` adds `baseline-drift` and `baseline-new-window` findings that compare error rates against a saved reference report. Findings include rule name, severity, score, explanation, and observed count in machine-readable reports. These are triage signals, not claims that an incident occurred.

## Defensive Scope

LogLens focuses on detection, troubleshooting, observability, and incident-analysis workflows. It does not provide exploitation, credential theft, persistence, or offensive payload functionality.

## Roadmap

### v0.1 — Foundation
- [x] Python package and CLI skeleton
- [x] normalized event model
- [x] text and JSON parsers
- [x] filtering and aggregation
- [x] basic anomaly rules
- [x] JSON summary output
- [x] CSV report output
- [x] unit tests and CI

### v0.2 — Analysis
- [x] configurable detection rules
- [x] time-window baselines
- [x] richer anomaly scoring
- [x] reusable report formats

### Release hardening
- [x] expand CLI integration coverage
- [x] add changelog and release notes
- [x] parse leading ISO timestamps from common text logs
- [x] normalize OpenTelemetry severity numbers
- [x] document RFC 5424 CLI support
- [x] add a reproducible end-to-end portfolio demo
- [x] add a guarded tag-triggered GitHub Release workflow
- [ ] tag a portfolio-ready release

Release history and notable changes are maintained in [CHANGELOG.md](CHANGELOG.md).

## Design notes

Parsing is deliberately deterministic and dependency-light. Malformed records do not become executable content, and unknown structured fields are retained rather than silently discarded. Strict JSON and RFC 5424 modes report malformed records while automatic mode remains conservative about input contracts. Filtering is read-only and explicit; aggregation and detection operate only on normalized events selected by the analyst. Detection rules use visible thresholds and a documented scoring formula so findings are reproducible and easy to audit. Machine-readable reports record effective configuration and finding scores. Time-window aggregation is descriptive, UTC-normalized, and excludes untimestamped records without discarding them from other analysis. The analysis pipeline streams parse→filter→detect without materializing the event list, and diagnostics go through the `logging` module on stderr so reports on stdout stay machine-readable. Report serialization is kept separate from analysis and preserves configuration and baseline context across reusable JSON and CSV formats.

## Development

The project favors readable Python, deterministic behavior, useful tests, and documentation that makes every detection understandable. CLI integration tests exercise the public command surface without network access, including report formats, filters, malformed strict-mode input, and missing-file behavior.

## Related projects

LogLens is part of the [REV3R5ED defensive-security portfolio](docs/related-projects.md), alongside SentinelKit for IOC/authentication triage, NetScope for bounded network diagnostics, and AutoOPS for safe IT operations automation.

## License

LogLens is released under the [MIT License](LICENSE).
