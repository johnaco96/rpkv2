# Release Artifacts and Versioning

This document defines how to build a release candidate and tie it to a commit,
binary version output, and benchmark evidence. It documents the current
current prototype and is not a production-readiness claim.

## Binary Version Output

Every maintained binary accepts `--version` or `-V` and prints:

- crate version;
- git commit captured at build time;
- build features compiled into the binary;
- build profile, reported as `debug` or `release`.

Example:

```bash
cargo run --bin server -- --version
```

Expected shape:

```text
rpkv2 0.1.0
git_commit: <short_commit>
build_features: ed25519
build_profile: debug
```

Release binaries should show `build_profile: release`.

## Release Build

Build the default secure feature set:

```bash
git status --short --branch
cargo build --release
cargo test --features ed25519
cargo clippy --all-targets -- -D warnings
```

Optional explicit feature build:

```bash
cargo build --release --features ed25519
```

Do not build release candidates with `--no-default-features` or
`--features insecure_demo`.

## Capture Release Identity

Set an operator-chosen release candidate name:

```bash
RC_NAME=rc-$(git rev-parse --short=12 HEAD)
mkdir -p releases/$RC_NAME
git rev-parse HEAD > releases/$RC_NAME/git-commit.txt
cargo run --release --bin server -- --version > releases/$RC_NAME/server-version.txt
cargo run --release --bin fast_rx -- --version > releases/$RC_NAME/fast-rx-version.txt
cargo run --release --bin fast_tx -- --version > releases/$RC_NAME/fast-tx-version.txt
```

On PowerShell:

```powershell
$Commit = git rev-parse --short=12 HEAD
$RcName = "rc-$Commit"
New-Item -ItemType Directory -Force -Path "releases/$RcName"
git rev-parse HEAD | Set-Content "releases/$RcName/git-commit.txt"
cargo run --release --bin server -- --version | Set-Content "releases/$RcName/server-version.txt"
cargo run --release --bin fast_rx -- --version | Set-Content "releases/$RcName/fast-rx-version.txt"
cargo run --release --bin fast_tx -- --version | Set-Content "releases/$RcName/fast-tx-version.txt"
```

## Benchmark Evidence

Run the repeatable two-node benchmark from `docs/operator-runbook.md` or
`docs/runbook-2node.md`. Store the benchmark outputs with the release candidate:

```bash
cp benchmarks/results/two-node/sender.csv releases/$RC_NAME/
cp benchmarks/results/two-node/receiver.csv releases/$RC_NAME/
cp benchmarks/results/two-node/sender.meta.json releases/$RC_NAME/
cp benchmarks/results/two-node/receiver.meta.json releases/$RC_NAME/
cp benchmarks/results/two-node/summary.json releases/$RC_NAME/
```

On PowerShell:

```powershell
Copy-Item benchmarks/results/two-node/sender.csv "releases/$RcName/"
Copy-Item benchmarks/results/two-node/receiver.csv "releases/$RcName/"
Copy-Item benchmarks/results/two-node/sender.meta.json "releases/$RcName/"
Copy-Item benchmarks/results/two-node/receiver.meta.json "releases/$RcName/"
Copy-Item benchmarks/results/two-node/summary.json "releases/$RcName/"
```

The release candidate is not complete until it has:

- `git-commit.txt`;
- at least one binary `--version` capture;
- benchmark CSV files;
- benchmark metadata JSON files;
- benchmark `summary.json`.

## Manifest Template

Create a small manifest after benchmark collection:

```json
{
  "schema": "rpkv2.release_candidate.v1",
  "release_candidate": "rc-<short_commit>",
  "git_commit": "<full_commit>",
  "crate_version": "0.1.0",
  "build_profile": "release",
  "build_features": ["ed25519"],
  "benchmark_summary": "summary.json",
  "production_ready_claim": false
}
```

Do not include private keys, PEM contents, wallet files, `.env` files, cloud
credentials, or seed material in a release candidate directory.

## Windows and Linux Differences

The git commit comes from `git rev-parse --short=12 HEAD` during build. If Git is
not available in the build environment, binaries print `git_commit: unknown`.

The build profile is inferred from Rust debug assertions. Standard `cargo build`
prints `debug`; standard `cargo build --release` prints `release`.
