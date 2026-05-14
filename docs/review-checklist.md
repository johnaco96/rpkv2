
# Review Checklist (AI and Human Branches)

Use this checklist for PRs targeting `benchmark-2node-signed`.

## 1) Branch and scope

- [ ] Branch purpose is single-task and clearly named.
- [ ] Base/target branch is correct (`benchmark-2node-signed` unless otherwise specified).
- [ ] No unrelated file churn.

## 2) Required PR sections

- [ ] Changed files are listed explicitly.
- [ ] Why changed is clear and bounded.
- [ ] Tests run are listed with exact commands.
- [ ] Known risks and follow-ups are documented.

## 3) File safety checks

- [ ] For docs-only/process tasks, no unexpected edits in `src/`, `Cargo.toml`, or `Cargo.lock`.
- [ ] No credentials, wallet files, private keys, or PEM artifacts were added.

## 4) Test policy enforcement

### Docs-only PRs

- [ ] PR explicitly states docs-only scope.
- [ ] Rust test suite is intentionally skipped and rationale is provided.

### Code-change PRs

- [ ] `cargo build`
- [ ] `cargo test`
- [ ] `cargo build --features ed25519`
- [ ] `cargo test --features ed25519`

Notes:
- `cargo fmt --check` may fail due to existing unrelated formatting; do not require broad rustfmt churn in unrelated PRs.

## 5) Claims and roadmap discipline

- [ ] No production-readiness claims.
- [ ] AF_XDP/DPDK is framed as future investigation unless implemented and benchmarked.
- [ ] Benchmark assertions are backed by artifacts/logs.

