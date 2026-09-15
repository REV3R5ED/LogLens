# LogLens

Lightweight log analysis and anomaly detection for defensive operations.

> Status: early development / v0.1 roadmap

## Goals

LogLens is intended to help analysts quickly turn raw logs into useful defensive signals without requiring a heavyweight SIEM stack.

Planned capabilities include:

- streaming and file-based log ingestion
- normalized event records
- common text/JSON log parsing
- filtering and aggregation
- lightweight anomaly heuristics
- concise terminal summaries
- JSON/CSV report export

## Defensive Scope

LogLens focuses on detection, troubleshooting, observability, and incident-analysis workflows. It does not provide exploitation, credential theft, persistence, or offensive payload functionality.

## Roadmap

### v0.1 — Foundation
- [ ] Python package and CLI skeleton
- [ ] normalized event model
- [ ] text and JSON parsers
- [ ] filtering and aggregation
- [ ] basic anomaly rules
- [ ] JSON/CSV output
- [ ] unit tests and CI

### v0.2 — Analysis
- [ ] configurable detection rules
- [ ] time-window baselines
- [ ] richer anomaly scoring
- [ ] reusable report formats

## Development

The project favors readable Python, deterministic behavior, useful tests, and documentation that makes every detection understandable.

## License

A project license will be finalized before the first stable release.
