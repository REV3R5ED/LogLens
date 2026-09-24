# Release readiness

This checklist turns LogLens release preparation into a repeatable, auditable process. It complements the guarded tag-triggered workflow in `.github/workflows/release.yml`; it does not replace CI.

## 1. Lock the candidate

- Choose one exact commit on `main` and record its full SHA in the release tracking issue.
- Confirm `pyproject.toml` declares the intended version and the planned tag is exactly `v<version>`.
- If `main` advances, do not silently move the candidate. Validate the replacement SHA and update the tracker explicitly.

## 2. Validate the candidate

Require successful CI on the exact candidate SHA. Before tagging, confirm the release workflow still provides these gates:

- tag/package-version parity;
- the full automated test suite;
- wheel and source-distribution builds;
- `twine check` on built distributions;
- installation and smoke testing of the built wheel rather than only an editable checkout; and
- preservation of validated artifacts for the publish job.

Review `CHANGELOG.md`, README examples, and release notes against the candidate so documentation does not claim behavior absent from the tagged code.

## 3. Preserve the defensive boundary

Release review and smoke tests must use synthetic or sanitized logs. Confirm the candidate remains focused on defensive analysis, troubleshooting, observability, and incident triage. Do not introduce credential collection, exploitation, persistence, destructive actions, private production logs, or claims that deterministic findings prove an incident occurred.

For structured-field analysis, verify reports preserve aggregate explainability without exposing raw sensitive field values.

## 4. Tag the validated commit

Create `v<version>` from the exact recorded candidate SHA only. The tag-triggered workflow must complete its `validate` job before the `publish` job can create the GitHub Release.

Do not retarget an existing release tag to a newer commit. If the candidate changes before publication, repeat the validation process and record the replacement SHA first.

## 5. Verify publication

After the workflow succeeds:

- confirm the GitHub Release points to the intended tag and commit;
- confirm the expected wheel and source-distribution assets are attached;
- install the published wheel in a clean environment and run `loglens --help` plus a small synthetic-log analysis;
- confirm release notes accurately describe the shipped behavior and known limitations; and
- update README status/install guidance so it no longer describes a successfully published version as only a release candidate.

Only then close the release tracking issue.