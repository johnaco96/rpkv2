# Dependency and Secret Audit

This audit records the dependency and secret-scanning baseline for the
current repository. It is an audit artifact, not a production-readiness
claim.

## Dependency Audit

- The root application and fuzz harness both retain `Cargo.lock` files so
  audits evaluate exact resolved versions.
- `.github/workflows/security-audit.yml` runs the official RustSec audit action
  when a Cargo manifest or lockfile changes, on manual request, and weekly
  against the current default branch.
- GitHub vulnerability alerts are enabled for repository-level dependency
  monitoring. Dependency upgrades remain deliberate, reviewed changes so the
  repository keeps its two-branch structure.

Accepted risk: an advisory scan covers published RustSec advisories; it is not
an independent source review, license-policy audit, or guarantee that every
dependency is vulnerability-free.

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

CI includes a lightweight tracked-file secret marker scan. It fails if a
tracked file contains a private key PEM header or common AWS credential marker.

This does not replace a full secret scanner. Recommended follow-up: add a
dedicated history-aware tool such as Gitleaks or TruffleHog when the deployment
environment can install it reliably.
