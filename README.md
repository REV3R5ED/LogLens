# LogLens

Lightweight log analysis and anomaly detection for defensive operations.

> Status: early development / v0.1

## Goals

LogLens helps analysts quickly turn raw logs into useful defensive signals without requiring a heavyweight SIEM stack.

Current foundation:

- installable Python package and `loglens` CLI
- normalized `LogEvent` records
- JSON log parsing with common field aliases
- unstructured text parsing with level detection
- automatic JSON/text detection
- preservation of unknown JSON fields for later analysis
- case-insensitive level and message filtering
- reusable level/source aggregation
- human-readable and JSON summary output
- automated tests across supported Python versions

## Quick start

```bash
python -m pip install -e .
loglens analyze /path/to/app.log
loglens analyze /path/to/events.jsonl --format json --json
loglens analyze /path/to/app.log --level ERROR --level WARN
loglens analyze /path/to/app.log --contains "database" --json
pytest -q
```

`--level` can be repeated and combined with `--contains`. Reports distinguish total input records from records matching the active filters, so filtering remains visible and auditable.

Example JSON lines input:

```json
{"timestamp":"2026-09-15T10:00:00Z","level":"error","message":"disk full","host":"web-1"}
```

LogLens normalizes the timestamp, level, message and source while retaining fields such as `host` for future filtering and detection rules.

## Defensive Scope

LogLens focuses on detection, troubleshooting, observability, and incident-analysis workflows. It does not provide exploitation, credential theft, persistence, or offensive payload functionality.

## Roadmap

### v0.1 — Foundation
- [x] Python package and CLI skeleton
- [x] normalized event model
- [x] text and JSON parsers
- [x] filtering and aggregation
- [ ] basic anomaly rules
- [x] JSON summary output
- [ ] CSV event/report output
- [x] unit tests and CI

### v0.2 — Analysis
- [ ] configurable detection rules
- [ ] time-window baselines
- [ ] richer anomaly scoring
- [ ] reusable report formats

## Design notes

Parsing is deliberately deterministic and dependency-light. Malformed records do not become executable content, and unknown structured fields are retained rather than silently discarded. Strict JSON mode reports malformed records while automatic mode can safely treat malformed JSON-looking lines as plain text. Filtering is read-only and explicit; aggregation operates only on normalized events selected by the analyst.

## Development

The project favors readable Python, deterministic behavior, useful tests, and documentation that makes every detection understandable.

## License

A project license will be finalized before the first stable release.
