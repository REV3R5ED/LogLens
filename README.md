# LogLens

Lightweight log analysis and anomaly detection for defensive operations.

> Status: active development / v0.2

## Goals

LogLens helps analysts quickly turn raw logs into useful defensive signals without requiring a heavyweight SIEM stack.

Current capabilities:

- installable Python package and `loglens` CLI
- normalized `LogEvent` records
- JSON log parsing with common field aliases
- unstructured text parsing with level detection
- automatic JSON/text detection
- preservation of unknown JSON fields for later analysis
- case-insensitive level and message filtering
- reusable level/source aggregation
- deterministic anomaly rules for elevated errors and repeated messages
- analyst-configurable detection thresholds with safe validation
- deterministic UTC time-window baselines for timestamped events
- human-readable, JSON, and CSV summary output with explainable findings
- automated tests across supported Python versions

## Quick start

```bash
python -m pip install -e .
loglens analyze /path/to/app.log
loglens analyze /path/to/events.jsonl --format json --json
loglens analyze /path/to/app.log --level ERROR --level WARN
loglens analyze /path/to/app.log --contains "database" --json
loglens analyze /path/to/app.log --error-threshold 10 --repeat-threshold 8 --json
loglens analyze /path/to/events.jsonl --window-minutes 5 --json
loglens analyze /path/to/app.log --csv > report.csv
pytest -q
```

`--level` can be repeated and combined with `--contains`. Reports distinguish total input records from records matching the active filters, so filtering remains visible and auditable. Detection runs only on the matched event set. `--json` and `--csv` are mutually exclusive report formats.

Detection thresholds can be tuned per analysis with `--error-threshold` and `--repeat-threshold`. The defaults remain 5 and 5. Error thresholds must be at least 1 and repeat thresholds at least 2, preventing nonsensical configurations. JSON reports include the effective `detection_config` so saved results remain reproducible and auditable.

### Time-window baselines

Use `--window-minutes N` to group matched, timestamped events into fixed UTC windows from 1 minute through 24 hours. Each window records its start/end, total event count, error-level count, and deterministic level distribution. Windows align to Unix-epoch boundaries, making repeated analyses comparable even when input ordering changes. Events without a parsed timestamp remain part of the normal summary and detection flow but are explicitly excluded from the baseline; the report records `timestamped_events` so that coverage is visible. Offset-less ISO timestamps are interpreted as UTC for deterministic cross-system behavior.

Time windows are descriptive baselines rather than incident verdicts. They provide a stable foundation for later scoring while keeping current analysis transparent and reproducible.

CSV reports use a stable long-form schema (`record_type,name,value,severity,message`) that keeps summary metrics, level/source aggregates, and anomaly findings easy to inspect in spreadsheets or feed into downstream defensive workflows. CSV escaping is handled by Python's standard CSV writer so log-derived commas and quotes remain data rather than structure.

Example JSON lines input:

```json
{"timestamp":"2026-09-15T10:00:00Z","level":"error","message":"disk full","host":"web-1"}
```

LogLens normalizes the timestamp, level, message and source while retaining fields such as `host` for future filtering and detection rules.

## Built-in anomaly rules

The detector intentionally favors explainability over opaque scoring. It reports an `elevated-errors` finding when the configured number of matched events are ERROR/CRITICAL/FATAL, and a `repeated-message` finding when the same non-empty message reaches its configured threshold. Findings include rule name, severity, explanation, and observed count in terminal, JSON, and CSV reports. These are triage signals, not claims that an incident occurred.

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
- [ ] richer anomaly scoring
- [ ] reusable report formats

## Design notes

Parsing is deliberately deterministic and dependency-light. Malformed records do not become executable content, and unknown structured fields are retained rather than silently discarded. Strict JSON mode reports malformed records while automatic mode can safely treat malformed JSON-looking lines as plain text. Filtering is read-only and explicit; aggregation and detection operate only on normalized events selected by the analyst. Detection rules use visible thresholds so findings are reproducible and easy to audit, and machine-readable reports record the effective configuration. Time-window aggregation is descriptive, UTC-normalized, and excludes untimestamped records without discarding them from other analysis. Report serialization is kept separate from analysis so additional safe output formats can be added without changing detection behavior.

## Development

The project favors readable Python, deterministic behavior, useful tests, and documentation that makes every detection understandable.

## License

LogLens is released under the [MIT License](LICENSE).
