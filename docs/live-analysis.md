# Live analysis: watch mode, baseline diff, and novelty detection

## Watch mode (`--follow` / `--watch`)

`--follow` tails a growing log file, re-scans on file growth, and emits
findings as thresholds trip — reusing the same detector and
`--fail-on-severity` exit semantics as `analyze`:

```bash
loglens analyze /var/log/app.log --follow --fail-on-severity medium
loglens analyze /var/log/app.log --follow --watch-interval 0.5 --watch-timeout 300 --json
```

- Each scan cycle processes only newly appended lines; findings are emitted
  once each (deduplicated by rule and message) as they trip.
- Text mode prints new findings as they appear; `--json` emits one JSON
  object per scan (JSONL), so the stream can be piped to `jq`.
- File truncation/rotation restarts reading from the beginning; a trailing
  partial line is held back until its newline arrives.
- Exit codes mirror `analyze`: `2` when the parse-error budget is exceeded,
  `3` when a finding reaches `--fail-on-severity`, `0` otherwise.
- `--follow` runs until interrupted (Ctrl-C exits cleanly) or
  `--watch-timeout` seconds elapse.
- Not supported with `--follow`: stdin (`-`), `.gz` files, `--csv`,
  `--window-minutes`, `--baseline-diff`, and `--novelty-learn` (novelty
  *detection* works; learning does not, since the store would churn forever).

## Baseline diff (`--baseline-diff`)

Compare the current run against a saved reference report and flag error-rate
drift per deterministic UTC window:

```bash
loglens analyze today.jsonl --format json --window-minutes 5 --json > today.json
loglens analyze yesterday.jsonl --format json --window-minutes 5 \
  --baseline-diff today.json --baseline-diff-threshold 0.2 --json
```

- The reference is a LogLens JSON report saved with `--window-minutes`, or a
  bare `{"windows": [...]}` file. Requires `--window-minutes` on the current
  run; a window-size mismatch logs a warning but still compares.
- A `baseline-drift` finding is emitted per window whose absolute error-rate
  delta reaches `--baseline-diff-threshold` (default `0.2`, i.e. 20 percentage
  points). Drift scores reuse the transparent scale as
  `min(100, round(50 + 50 * |delta|))`, so a threshold-sized drift lands
  exactly on the medium boundary — no new opaque formula.
- Windows present only in the current run that contain errors produce a
  low-severity `baseline-new-window` finding. Windows that vanished are
  recorded in the `baseline_diff.deltas` report section without a finding.
- Drift findings participate in `--fail-on-severity` like any other finding.

## Novelty detection (`--novelty-store`)

The `novel-message` rule complements `repeated-message`: it flags messages
*never observed* in a reference corpus, scoped by `(source, level, message)`
with the same normalization as the other rules. The corpus is a plain JSON
file — no database dependency — so it can be versioned next to detection
policies.

```bash
# Bootstrap the corpus from known-good logs (no findings emitted):
loglens analyze known-good.log --novelty-store corpus.json --novelty-learn

# Flag anything never seen before:
loglens analyze current.log --novelty-store corpus.json --json
```

- A missing store starts empty; corrupt stores fail with a structured error.
- Detection never mutates the store; `--novelty-learn` updates it (recording
  first-seen timestamps and occurrence counts) without emitting findings.
- Novelty scoring reuses the transparent formula with an effective threshold
  of 1: any unseen message starts at base points, with excess and prevalence
  points added exactly as for the other count rules.
- The report's `novelty` section records the store path, mode
  (`detect`/`learn`), and corpus size for auditability.

## Streaming and progress

Parsing, filtering, and detection run as a single lazy pass: the full event
list is never materialized, so multi-gigabyte logs stay bounded by distinct
sources/messages rather than total record count. Rule semantics are identical
to the list-based path. `--progress` logs input progress to stderr (safe for
cron/CI since reports stay on stdout):

```bash
loglens analyze huge.log --progress --json
# loglens: INFO: processed 1000 input lines (982 matched, 0 parse errors)
```

## Diagnostics

`-v` / `--verbose` enables debug diagnostics on stderr via the standard
`logging` module; without it, only warnings and errors are shown. Parser
failures per line are counted (and visible with `--verbose`) instead of
raising tracebacks, and unexpected operational failures exit `1` with a
structured `loglens: ERROR:` message. `python -m loglens` works as an alias
for the `loglens` console script.
