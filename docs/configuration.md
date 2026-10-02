# Detection policies

LogLens thresholds, scoring weights, and per-source overrides can live in a
versioned TOML or JSON config file instead of a long command line. Named
policies make runs reproducible across analysts, CI jobs, and cron schedules:
the same file plus `--policy <name>` always produces the same effective
configuration, and JSON reports record the active policy, scoring weights, and
overrides for later audit.

## Quick example

`loglens.toml`:

```toml
[policy.default]
error_threshold = 10
repeat_threshold = 8

[policy.default.scoring]
high_cutoff = 85

# One noisy service stops forcing global threshold changes.
[policy.default.sources."payments-api"]
error_threshold = 100
repeat_threshold = 50

[policy.strict]
error_threshold = 1
repeat_threshold = 2
```

```bash
loglens analyze /var/log/app.log --config loglens.toml --json
loglens analyze /var/log/app.log --config loglens.toml --policy strict --json
```

JSON uses the same schema under a top-level `policy` object:

```json
{"policy": {"default": {"error_threshold": 10,
                        "sources": {"payments-api": {"error_threshold": 100}}}}}
```

TOML configs require Python 3.11+ (`tomllib`); JSON configs work on every
supported Python.

## Policy selection

- `--policy <name>` selects a policy explicitly.
- Without `--policy`, the policy named `default` is used.
- If the file defines exactly one policy, it is used regardless of its name.
- `--policy` without `--config` is an error.

## Precedence

Explicit CLI flags always win over config file values:

```
CLI flag  >  [policy.<name>] value  >  built-in default (5/5/5/60)
```

Per-source overrides apply only to the named source; every other source keeps
the effective global thresholds. Source names are normalized exactly like
event sources, so `"Payments-API"` in the file matches `payments-api` events.

## Tunable scoring

The `[policy.<name>.scoring]` table tunes the transparent 0-100 formula:

| Key                  | Default | Meaning                                              |
|----------------------|---------|------------------------------------------------------|
| `base_points`        | 50      | points awarded for reaching the threshold            |
| `excess_points`      | 25      | points for how far the count exceeds the threshold   |
| `prevalence_points`  | 25      | points for prevalence across the matched set         |
| `medium_cutoff`      | 60      | score at or above this is `medium`                   |
| `high_cutoff`        | 80      | score at or above this is `high`                     |
| `max_finding_context`| 240     | bounds untrusted text embedded in finding messages   |

Cutoffs must satisfy `1 <= medium_cutoff < high_cutoff <= 100`.
The effective `scoring_config` is preserved in JSON reports.

## Validation

Unknown settings are rejected (typos fail loudly rather than being silently
ignored), thresholds keep their CLI bounds (`error_threshold >= 1`,
`repeat/burst >= 2`, burst window `>= 1`), and blank source names are
rejected. Config problems exit with code 1 and a `loglens: ERROR:` message on
stderr, never a traceback.
