# Dependency and Secret Audit

This audit records the dependency and secret-scanning baseline for the
current repository. It is an audit artifact, not a production-readiness
claim.

## Dependency Audit

- `cargo audit --version` was attempted locally and failed because
  `cargo-audit` is not installed in this workspace.
- `cargo deny --version` was attempted locally and failed because `cargo-deny`
  is not installed in this workspace.
- The dependency lockfile is present as `Cargo.lock`, so future audit tools can
  evaluate exact resolved versions.

Accepted risk: there is no vulnerability database check in this repository yet.
Before any production deployment, install and run `cargo-audit` or `cargo-deny`
in CI and record the output with the release artifact.

## Secret Scan Result

Tracked files were scanned for high-confidence private key and cloud credential
markers:

- PEM private key headers.
- AWS access key variable names.
- AWS secret access key variable names.

Result: no tracked private key material or cloud credential markers were found.
The only lower-confidence secret-related matches were documentation warnings
that tell operators not to commit wallets, keys, seed phrases, `.env` files, or
cloud credentials.

## Ignore Rules

`.gitignore` excludes generated secrets and operational artifacts:

- `.env` and `.env.*`, except `.env.example`.
- `secrets/`, `credentials/`, `wallets/`, `stores/`, `certs/`.
- Nested `private_keys/`, `keys/`, `credentials/`, `wallets/`, and `stores/`.
- Private key and certificate file extensions, including `.key`, `.pem`, `.der`,
  `.crt`, `.p12`, `.pfx`, `.jks`, `.keystore`, and `.wallet`.
- Benchmark CSV, JSON, JSONL, TXT, and log output under `benchmarks/`.
- Ledger shred files and fuzzing artifacts.

The repository intentionally tracks fixed benchmark configuration files under
`configs/benchmark/*.env`. These files contain benchmark settings only and must
not contain secrets.

## CI Coverage

CI now includes a lightweight tracked-file secret marker scan. It fails if a
tracked file contains a private key PEM header or common AWS credential marker.

This does not replace a full secret scanner. Recommended follow-up: add a
dedicated tool such as Gitleaks, TruffleHog, `cargo-audit`, or `cargo-deny` once
the deployment environment can install those tools reliably.
