# Production Readiness Review Gate

Review date: 2026-07-04

Scope: current repository state at the review date

Decision: **NO-GO**

This document records a production-readiness gate for the current prototype.
It is intentionally conservative: any unmet item
blocks a production-readiness claim.

## Sign-Off

I reviewed the checklist below against the current repository documentation,
tests, and runbooks. The branch may continue as a hardened prototype and release
candidate baseline, but it must not be described as production ready while any
blocking item remains open.

## Gate Checklist

| Gate item | Status | Evidence | Production claim impact |
| --- | --- | --- | --- |
| All CI passing | Pending remote confirmation | CI config exists in `.github/workflows/ci.yml` for formatting, build, tests, Ed25519 feature build/test, clippy, and secret marker scan. Local equivalents have passed during ticket work, but this gate requires the remote CI result for the final commit. | Blocks until remote CI is green. |
| Production-mode guardrails passing | Pass locally | `docs/runtime-modes.md`; `runtime_mode::tests::*`; negative check `server --mode production --check-config` fails with `production mode requires --config`. | Does not block by itself. |
| Crypto tests passing | Pass locally | `cargo test` and `cargo test --features ed25519` include Ed25519 verification, malformed key/signature, invalid signature, and mixed batch tests. | Does not block by itself. |
| RPK identity tests passing | Pass locally | Tests cover wrong SPKI, unknown validator, mutual inbound RPK authentication, TLS 1.3 negotiation, raw public key requirement, end-to-end X.509 fallback rejection, verifier-level certificate fallback rejection, and duplicate SPKI config. | Does not block by itself. |
| Replay tests passing | Pass locally | Replay tests cover duplicates, per-validator nonce behavior, slot eviction, capacity bounds, and high-volume no-false-positive final decision behavior. | Does not block by itself. |
| Soak test completed | Not met | `docs/soak-test.md` defines one-hour and longer soak requirements. No completed one-hour or 24-hour production-like soak artifact is recorded with a release candidate. | Blocks production claim. |
| Benchmark targets met | Not met | `docs/production-scale-targets.md` defines targets, and benchmark tooling exists, but no release-candidate benchmark evidence proves the target table is met. | Blocks production claim. |
| No blocking TLS/RPK findings | Pass locally | `docs/tls-rpk-security-review.md` closes TLS-RPK-001 and TLS-RPK-002 with direct end-to-end tests. | Does not block by itself; broader release security review is still required. |
| Rollback plan exists | Pass | `docs/operator-runbook.md` contains rollback commands and preservation guidance. | Does not block by itself. |
| Operator runbook reviewed | Pass | `docs/operator-runbook.md` covers build, feature flags, config, key provisioning, peer registry setup, firewall, metrics, logs, startup, shutdown, rotation, rollback, revocation, and benchmark procedure. | Does not block by itself. |
| Known risks documented | Pass | `docs/threat-model.md`, `docs/tls-rpk-security-review.md`, `docs/storage-contract.md`, `docs/dependency-secret-audit.md`, and `docs/release-artifacts.md` document current limitations and risks. | Does not block by itself. |

## Blocking Items

Production readiness is blocked by the following items:

1. Remote CI must pass for the exact release-candidate commit.
2. A one-hour soak result must be completed and attached to a release candidate.
3. A longer production-like soak, ideally 24 hours or more, must be completed
   before any real production claim.
4. Benchmark targets in `docs/production-scale-targets.md` must be met and
   stored with the release candidate.
5. The configured runtime must be reviewed as a composed validator path, with
   current benchmark, soak, replay, fork-choice, blockstore, and protocol
   compatibility evidence tied to the release candidate commit.

## Required Evidence For Future GO

A future production-readiness sign-off must include:

- remote CI run URL or equivalent CI evidence for the exact commit;
- `server --version` release output showing crate version, git commit, features,
  and release profile;
- signed benchmark summary JSON and source CSV/metadata files;
- soak summary JSON and host telemetry archive;
- security review update showing zero blocking findings;
- reviewed config with secrets redacted;
- rollback commit and operator procedure;
- explicit statement of accepted nonblocking risks.

## Final Determination

Current determination: **NO-GO**

The project has materially stronger guardrails, documentation, tests, metrics,
and operational workflows than the starting point. It is still not production
ready and must not be used to make a production blockchain validator claim until
the blocking items above are closed.
