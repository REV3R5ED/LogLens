# Reviewer guide

LogLens is a dependency-light defensive log analysis toolkit designed to turn local log files into explainable, reproducible triage signals.

## Five-minute review

```bash
python -m pip install -e .
loglens --version
pytest -q
```

Then run the documented end-to-end scenario in [`portfolio-demo.md`](portfolio-demo.md). The demo is local-only and produces deterministic JSON/CSV output without network access.

## What to inspect

A reviewer can evaluate the project along four boundaries:

1. **Parsing** — normalized events from text, JSON/OpenTelemetry-compatible records, and strict RFC 5424 syslog.
2. **Analysis** — explicit filtering, source/level aggregation, source-health summaries, and UTC time-window baselines.
3. **Detection** — deterministic elevated-error, repeated-message, and timestamp-aware error-burst rules with visible thresholds and explainable scores.
4. **Reporting** — deterministic human-readable, JSON, and CSV output that retains effective detection configuration and baseline context.

## Useful commands

```bash
# Human-readable analysis
loglens analyze sample.log

# Machine-readable report
loglens analyze sample.jsonl --format json --json

# Strict syslog parsing
loglens analyze forwarded.log --format rfc5424 --json

# Auditable threshold tuning
loglens analyze sample.jsonl --format json --error-threshold 10 --repeat-threshold 8 --json

# Fixed UTC baseline windows
loglens analyze sample.jsonl --format json --window-minutes 5 --json
```

## Design and safety signals

- Detection is deterministic and explainable rather than probabilistic or opaque.
- Malformed strict-format records are counted as parse errors instead of silently reinterpreted.
- Unknown structured fields are retained for later defensive analysis.
- Source identities are normalized conservatively so structural whitespace does not concatenate visible source tokens.
- Findings are triage signals, not claims that an incident occurred.
- The project does not provide exploitation, credential theft, persistence, payload delivery, or destructive behavior.

## Verification

Before treating a commit as release-ready, follow [`release-verification.md`](release-verification.md). CI exercises the supported Python matrix, while the portfolio demo provides a reproducible public-surface smoke test.

For implementation history and notable behavior changes, see [`../CHANGELOG.md`](../CHANGELOG.md).
