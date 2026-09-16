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
- transparent 0-100 anomaly scoring with severity derived from score
- reusable deterministic JSON and long-form CSV report serializers
- CSV preservation of effective detection configuration and time-window baselines
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
loglens analyze /path/to/events.jsonl --window-minutes 5 --csv > report.csv
pytest -q
```

`--level` can be repeated and combined with `--contains`. Reports distinguish total input records from records matching the active filters, so filtering remains visible and auditable. Detection runs only on the matched event set. `--json` and `--csv` are mutually exclusive report formats.

Detection thresholds can be tuned per analysis with `--error-threshold` and `--repeat-threshold`. The defaults remain 5 and 5. Error thresholds must be at least 1 and repeat thresholds at least 2, preventing nonsensical configurations. Machine-readable reports include the effective detection configuration so saved results remain reproducible and auditable.

### Time-window baselines

Use `--window-minutes N` to group matched, timestamped events into fixed UTC windows from 1 minute through 24 hours. Each window records its start/end, total event count, error-level count, and deterministic level distribution. Windows align to Unix-epoch boundaries, making repeated analyses comparable even when input ordering changes. Events without a parsed timestamp remain part of the normal summary and detection flow but are explicitly excluded from the baseline; the report records `timestamped_events` so that coverage is visible. Offset-less ISO timestamps are interpreted as UTC for deterministic cross-system behavior.

Time windows are descriptive baselines rather than incident verdicts. They provide a stable foundation for scoring while keeping analysis transparent and reproducible.

### Anomaly scoring

Every finding includes a deterministic score from 0 to 100. A rule that reaches its configured threshold starts at 50 points. Up to 25 additional points reflect how far the observed count exceeds the threshold, and up to 25 reflect the finding's prevalence across the matched event set. Scores below 60 are `low`, 60-79 are `medium`, and 80 or above are `high`. This is deliberately simple and explainable: the score is a triage aid, not a probability or incident verdict.

### Reusable reports

JSON and CSV output now share reusable serializers in `loglens.reporting`, keeping formatting separate from parsing and detection. JSON is deterministic and human-readable. CSV uses the stable long-form columns `record_type,name,value,severity,score,message`; in addition to summaries, aggregates, and findings, it preserves the effective detection thresholds and time-baseline metadata. Time-window rows carry the window start, event count, error-event count, and a deterministic JSON level distribution so spreadsheet exports do not silently lose baseline context. Log-derived commas and quotes are escaped by Python's standard CSV writer.

Example JSON lines input:

```json
{"timestamp":"2026-09-15T10:00:00Z","level":"error","message":"disk full","host":"web-1"}
```

LogLens normalizes the timestamp, level, message and source while retaining fields such as `host` for future filtering and detection rules.

## Built-in anomaly rules

The detector intentionally favors explainability over opaque scoring. It reports an `elevated-errors` finding when the configured number of matched events are ERROR/CRITICAL/FATAL, and a `repeated-message` finding when the same non-empty message reaches its configured threshold. Findings include rule name, severity, score, explanation, and observed count in machine-readable reports. These are triage signals, not claims that an incident occurred.

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
- [ ] expand CLI integration coverage
- [ ] add changelog and release notes
- [ ] tag a portfolio-ready release

## Design notes

Parsing is deliberately deterministic and dependency-light. Malformed records do not become executable content, and unknown structured fields are retained rather than silently discarded. Strict JSON mode reports malformed records while automatic mode can safely treat malformed JSON-looking lines as plain text. Filtering is read-only and explicit; aggregation and detection operate only on normalized events selected by the analyst. Detection rules use visible thresholds and a documented scoring formula so findings are reproducible and easy to audit. Machine-readable reports record effective configuration and finding scores. Time-window aggregation is descriptive, UTC-normalized, and excludes untimestamped records without discarding them from other analysis. Report serialization is kept separate from analysis and preserves configuration and baseline context across reusable JSON and CSV formats.

## Development

The project favors readable Python, deterministic behavior, useful tests, and documentation that makes every detection understandable.

## License

LogLens is released under the [MIT License](LICENSE).
