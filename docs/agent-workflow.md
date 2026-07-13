
# AI Agent Workflow for `rpkv2`

This document defines a docs-first workflow for AI-generated contributions in `rpkv2`.

## Scope and framing

`rpkv2` is a Rust validator ingress/networking prototype focused on:

- QUIC + raw public key TLS (RPK)
- pinned SPKI verification
- validator-style packet verification and replay protection
- batched Ed25519 verification
- slot-based batching and PoH/shred/storage/fanout experiments

Do not claim production readiness in AI-authored branches or reviews.

## Branch lifecycle

1. Start from the current milestone integration branch:
   - `benchmark-2node-signed`
2. Create a single-purpose AI branch:
   - `codex/<short-task-name>`
3. Keep branch scope narrow (one task family per branch).
4. Open PR into `benchmark-2node-signed` unless maintainers direct otherwise.

## Required PR metadata (all AI branches)

Every AI-authored PR must include:

- **Changed files**: exact file list
- **Why changed**: intent and scope
- **Tests run**: exact commands and outcomes
- **Known risks**: uncertainty, assumptions, and follow-up work

## Testing policy

### Docs-only changes

If no Rust/code paths are changed, Rust tests may be skipped. PR must explicitly state:

- that changes are docs-only
- that Rust tests were not run because no code changed

### Code changes

If any code is changed, PR must include outputs for:

- `cargo build`
- `cargo test`
- `cargo build --features ed25519`
- `cargo test --features ed25519`

`cargo fmt --check` may currently fail due to pre-existing unrelated formatting. Do not include broad formatting churn in unrelated PRs.

## Review gating

Reviewers should reject or request cleanup when:

- branch includes unexpected edits under `src/`, `Cargo.toml`, or `Cargo.lock` for docs/process tasks
- branch mixes unrelated changes (large multi-purpose patch)
- test/reporting section is missing or ambiguous
- claims imply production readiness

## Human clean-branch policy

If AI output is stale, contaminated, or based on the wrong base branch, create a human clean branch and re-apply only validated commits.

## Performance roadmap guardrail

Treat AF_XDP/DPDK as **future directions** only unless implemented and benchmarked in-tree with reproducible data.

