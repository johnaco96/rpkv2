
# Agent Task Template

Use this template for `codex/*` task PR descriptions.

## Task

- **Title**:
- **Branch**: `codex/...`
- **Target**: `benchmark-2node-signed`
- **Type**: docs-only | code

## Context

Describe how this task supports `rpkv2` goals (QUIC/RPK/SPKI/validator-ingress benchmarking focus).

## Planned changes

- [ ] Change 1
- [ ] Change 2

## Changed files

- `path/to/file1`
- `path/to/file2`

## Why these changes

- Reason 1
- Reason 2

## Tests run

### Docs-only

- Rust tests skipped (no code changed).

### Code changes

- [ ] `cargo build`
- [ ] `cargo test`
- [ ] `cargo build --features ed25519`
- [ ] `cargo test --features ed25519`

## Known risks / follow-ups

- Risk 1
- Follow-up 1

## Reviewer checks

- [ ] No unexpected `src/`, `Cargo.toml`, or `Cargo.lock` changes for docs-only tasks.
- [ ] No production-readiness claims.
- [ ] AF_XDP/DPDK framed as future work unless benchmarked in-tree.

