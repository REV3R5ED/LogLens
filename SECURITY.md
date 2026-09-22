# Security Policy

LogLens is a defensive log-analysis toolkit. It parses untrusted log content, summarizes events, and reports anomalies; it is not intended to execute log data, probe systems, or provide offensive capabilities.

## Supported version

Security fixes are applied to the current `main` branch and the latest published release. Older snapshots may not receive backports.

## Reporting a vulnerability

Please do not publish an exploit or sensitive reproduction data in a public issue. Use GitHub's private vulnerability reporting for this repository when available. If private reporting is unavailable, open a minimal issue that states a security concern exists without including secrets, production logs, credentials, exploit payloads, or other sensitive details.

A useful report includes:

- affected LogLens version or commit;
- the parser, analyzer, detector, reporter, or CLI path involved;
- the smallest sanitized input that demonstrates the behavior;
- expected and observed behavior;
- security impact and any safe mitigation already identified.

## Defensive design expectations

Contributions should preserve these boundaries:

- Treat log input and metadata as untrusted data.
- Never execute, import, evaluate, or shell-expand content taken from logs.
- Prefer bounded, deterministic parsing and analysis behavior.
- Fail safely on malformed input and avoid destructive side effects.
- Keep exported reports machine-readable and reject values that cannot be represented reliably.
- Do not add credential harvesting, exploitation, persistence, evasion, destructive actions, or other offensive functionality.
- Use synthetic or sanitized fixtures in tests and examples; never commit production secrets or private logs.

## Security validation

Security-relevant changes should include regression coverage for the failure mode and pass the repository's supported Python CI matrix before merge. Parser changes should test malformed or adversarially shaped data where practical without embedding harmful payloads.

These constraints are part of the project's portfolio contract: LogLens should demonstrate secure engineering around defensive telemetry, not merely produce anomaly findings.
