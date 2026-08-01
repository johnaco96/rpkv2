# Security Policy

## Project status

`rpkv2` is a research prototype. It has not received an independent security
audit and must not be treated as production-ready validator software. The
current security assumptions and known limits are documented in
[docs/threat-model.md](docs/threat-model.md) and
[docs/tls-rpk-security-review.md](docs/tls-rpk-security-review.md).

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability.

Use GitHub's private **Report a vulnerability** flow from the repository's
Security tab. If that option is unavailable, contact the repository maintainer
through their GitHub profile before sharing technical details publicly.

Include enough information to reproduce and assess the issue:

- affected commit and build features;
- operating system and relevant configuration with secrets removed;
- expected and observed behavior;
- a minimal reproducer or packet trace with credentials and identities
  redacted;
- your assessment of impact and exploitability.

The maintainer will acknowledge a complete report, investigate it, and
coordinate disclosure based on severity and available remediation time. No
specific response or remediation deadline is guaranteed for this research
project.

## Supported versions

Security fixes are made only on the current `main` branch. Historical commits,
benchmark baselines, and unreleased local builds are not supported versions.
