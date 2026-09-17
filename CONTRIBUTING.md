# Contributing to LogLens

Thanks for helping improve LogLens. The project is intentionally small, deterministic, dependency-light, and focused on defensive log analysis.

## Development setup

LogLens supports Python 3.10 and newer.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
pytest -q
```

Before opening a pull request, also exercise the installed command surface when your change affects CLI behavior:

```bash
loglens --version
loglens analyze /path/to/sample.log
```

## Change expectations

Keep changes focused and explain the analyst-facing behavior they add or modify. New parser behavior, detection rules, report fields, exit-code behavior, and bug fixes should include regression tests. Prefer deterministic output so repeated analysis of the same input produces comparable results.

Use synthetic fixtures in tests and examples. Do not commit production logs, credentials, tokens, customer data, personal information, or other sensitive telemetry.

When changing machine-readable output, preserve stable JSON/CSV semantics where practical and document intentional compatibility changes. Detection logic should remain explainable: findings must be traceable to visible inputs, thresholds, and rules rather than opaque claims.

## Defensive scope

Contributions must support authorized defensive workflows such as log parsing, observability, troubleshooting, detection engineering, incident triage, and reproducible reporting.

Do not add exploitation, credential theft, persistence, destructive payloads, evasion tooling, unauthorized access, or functionality intended to conceal malicious activity. Log content must always be treated as untrusted data and never executed.

## Pull requests

A good pull request should:

- describe the problem and why the change is useful;
- keep the implementation narrowly scoped;
- include tests for new behavior and regressions;
- update README or other documentation when the public interface changes;
- avoid unrelated formatting or generated-file churn; and
- pass the repository's CI checks.

Small, reviewable changes are preferred over broad rewrites. If a change affects detection meaning or scoring, document the reasoning so an analyst can understand and reproduce the result.
