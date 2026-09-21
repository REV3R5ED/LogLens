# Release verification checklist

Use this checklist before publishing a LogLens portfolio release. It keeps the release claim tied to reproducible checks rather than repository activity alone.

## 1. Verify the candidate

From a clean checkout of the candidate commit:

```bash
python -m pip install -e .
python -m pytest -q
loglens --version
```

The CLI version must match the package version in `pyproject.toml` and `loglens.__version__`.

## 2. Exercise the public workflow

Run the documented [portfolio demo](portfolio-demo.md) from a clean temporary directory. Confirm that:

- the synthetic log parses without unexpected parse errors;
- explainable findings are produced for the documented scenario;
- JSON output is valid and includes effective detection configuration;
- CSV output preserves summary, configuration, baseline, and finding records;
- no network access or privileged operations are required.

## 3. Verify supported CI

The candidate commit must have a successful GitHub Actions CI run across every Python version declared by the project. Do not publish a release from a commit whose required test job is failed, cancelled, or still pending.

## 4. Review defensive scope

Confirm that the release remains focused on parsing, filtering, aggregation, anomaly detection, reporting, troubleshooting, and incident analysis. The release must not introduce exploitation, credential theft, persistence, destructive actions, or offensive payload functionality.

## 5. Review release metadata

Before creating the tag:

- move completed user-visible changes out of the changelog's `Unreleased` section as appropriate;
- ensure `docs/releases/vX.Y.Z.md` describes the shipped behavior;
- ensure the README status reflects the candidate/released version;
- confirm the working tree contains no generated reports, credentials, local logs, or environment-specific files.

## 6. Tag only the validated commit

Create the version tag only after the checks above pass. The tag must point at the exact commit that passed CI and the portfolio demo. After publication, verify that the release page and tag resolve to that same commit.

This checklist is intentionally conservative: a small validated release is preferable to a larger release containing unverified changes.
