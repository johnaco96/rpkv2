# Contributing

Thanks for your interest in `rpkv2`. This repository is a research prototype,
so contributions should make its behavior easier to verify without implying
production readiness or compatibility with an existing blockchain network.

## Before opening a change

- Keep changes focused and explain the protocol, safety, or maintainability
  reason for them.
- Do not commit private keys, certificates, `.env` files, wallets, cloud
  credentials, benchmark host identifiers, or other operational secrets.
- Discuss wire-format and authentication changes before implementing them.
  Existing encoded formats are versioned compatibility contracts.
- Report suspected security vulnerabilities through the process in
  [SECURITY.md](SECURITY.md), not through a public issue.

## Required checks

Run the same core checks as CI:

```bash
cargo fmt --check
cargo build --all-targets
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
```

Changes involving cryptographic verification must also exercise the relevant
feature configurations described in [docs/crypto-build-modes.md](docs/crypto-build-modes.md).

Benchmark changes must emit machine-readable CSV or JSON and document the
exact command, commit, build profile, host assumptions, and measurement scope.

## Pull requests

A useful pull request includes:

- what changed and why;
- the checks that were run;
- any wire-format, security, compatibility, or performance risk;
- updated tests and documentation when behavior changes.

Keep generated build output and local benchmark results out of commits unless
they are intentionally reviewed evidence under `benchmarks/results/`.
