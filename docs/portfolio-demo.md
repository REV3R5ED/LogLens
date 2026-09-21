# Portfolio demo: triaging a noisy service

This walkthrough gives reviewers a short, reproducible way to exercise LogLens as a defensive analyst tool. It uses only local synthetic log records and does not contact external systems.

## Scenario

An API service is healthy for several minutes, then begins returning repeated database errors. The analyst wants to answer three questions:

1. Which source is producing the errors?
2. Is the behavior concentrated enough to trigger an explainable finding?
3. Can the result be exported in a machine-readable format for later review?

## Create the sample log

```bash
cat > /tmp/loglens-demo.log <<'EOF'
2026-09-20T18:00:00Z INFO api request completed
2026-09-20T18:00:10Z INFO api request completed
2026-09-20T18:01:00Z ERROR api database unavailable
2026-09-20T18:01:05Z ERROR api database unavailable
2026-09-20T18:01:10Z ERROR api database unavailable
2026-09-20T18:01:15Z ERROR api database unavailable
2026-09-20T18:01:20Z ERROR api database unavailable
EOF
```

## Run the analysis

From an editable installation of the repository:

```bash
loglens analyze /tmp/loglens-demo.log --window-minutes 1 --json
```

The default thresholds are sufficient for this dataset: five error events from the same logical source and five repetitions of the same message. The JSON report should therefore make the input/matched counts auditable, show the `api` source and its level distribution, include one-minute UTC baseline windows, and emit explainable anomaly findings with deterministic scores.

For a spreadsheet-friendly artifact:

```bash
loglens analyze /tmp/loglens-demo.log --window-minutes 1 --csv > /tmp/loglens-demo.csv
```

The CSV preserves summary records, effective detection configuration, findings, and time-window baseline context rather than reducing the result to a single alert.

## Analyst interpretation

The findings are triage signals, not incident verdicts. In a real investigation, the next defensive steps would be to correlate the affected service with deployment, database-health, and request telemetry; verify whether the errors are expected; and retain the exported report with the case notes.

## What this demonstrates

- deterministic parsing of timestamped text logs
- source and severity aggregation
- explainable threshold-based anomaly detection
- fixed UTC time-window baselines
- reproducible JSON/CSV reporting
- a defensive, non-destructive workflow suitable for local validation or portfolio review
