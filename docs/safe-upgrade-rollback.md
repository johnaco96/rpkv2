# Safe Upgrade And Rollback

Ticket 14.4 defines the compatibility and operator process for upgrading an
rpkv2 validator without corrupting consensus or ledger state.

This document is a guardrail, not a production readiness claim. Any unmet
compatibility item blocks a production upgrade.

## Compatibility Matrix

| Surface | Current Version | Compatibility Rule | Current Enforcement |
| --- | ---: | --- | --- |
| Packet wire protocol | `1` | Nodes accept only `PACKET_VERSION = 1`. Header layout or signing-preimage changes require a new version and a coordinated network upgrade. | `Header::validate` rejects unsupported packet versions. |
| Consensus message wire protocol | `1` | Nodes accept only `CONSENSUS_MESSAGE_VERSION = 1`. Message kind, signing preimage, or field meaning changes require a new version. | `ConsensusMessage::decode` rejects unsupported versions. |
| Transaction format | `1` | Nodes accept only `TRANSACTION_VERSION = 1`. Serialization, validity, fee, nonce, or signature semantics changes require a new version. | `Transaction::decode` rejects unsupported versions. |
| Ledger format | `1` | Blocks, entries, transaction batches, and shreds use `LEDGER_VERSION = 1`. Format or hash-domain changes require a new version and replay migration plan. | Ledger object decoders reject unsupported versions. |
| Snapshot format | `1` | Nodes accept only `SNAPSHOT_VERSION = 1`. Snapshot state, validator set, consensus safety, hash, or signature changes require a new version. | `LedgerSnapshot::decode` rejects unsupported versions. |
| Production config format | `1` | Configs use `format_version = 1`. Missing version defaults to `1` for backward compatibility with existing test configs. Future config changes that alter meaning must bump this field. | `ProductionConfig::validate` rejects unsupported `format_version`. |
| Blockstore record format | `1` | Durable blockstore log records use `BLOCKSTORE_RECORD_VERSION = 1`. Record header/payload changes require a migration tool or clean rebuild from ledger/snapshot. | `Blockstore::open` rejects unsupported record versions. |
| Demo shred storage format | `1` | Pilot/demo append files use `STORAGE_RECORD_VERSION = 1`. This is not validator-grade durable storage. | Storage scanner rejects unsupported record versions. |
| Database schema | none | No schema migration framework exists yet. Any database/storage schema change must add a migration plan and tests before production use. | No migration runner is present. |

## Pre-Upgrade Checklist

1. Confirm all CI checks pass on the release candidate branch.
2. Capture binary version:

```powershell
cargo run --bin nodectl -- version
cargo run --bin server -- --version
```

3. Confirm config validates:

```powershell
cargo run --bin nodectl -- validate-config --config nodes/validator-a/production.toml
```

4. Confirm ledger/storage scans clean:

```powershell
cargo run --bin nodectl -- repair-ledger --storage-dir nodes/validator-a/storage --policy fail-startup
```

5. Capture current health, readiness, and metrics:

```powershell
curl http://127.0.0.1:9100/health
curl http://127.0.0.1:9100/ready
curl http://127.0.0.1:9100/metrics
```

6. Record the current finalized root, latest slot, git commit, config checksum,
   storage directory, snapshot path, and rollback binary path in the deployment
   notes.

## Required Backups

Before upgrading, preserve:

- current binary or release artifact;
- `production.toml`;
- validator identity public export;
- private keys in the existing secure key store;
- blockstore/storage directory or storage volume snapshot;
- latest validated snapshot file, if present;
- metrics and logs around the upgrade window.

Never copy private keys into the repo, release bundle, chat transcript, ticket,
or monitoring system.

## Upgrade Procedure

1. Stop new traffic at the load balancer or peer routing layer if available.
2. Stop the node using the service supervisor. `nodectl stop` only handles PID
   files and is not a process killer.
3. Take required backups.
4. Install the new binary beside the old binary, not over it.
5. Run version and config validation with the new binary.
6. Run storage repair in `fail-startup` mode.
7. Start with a dry run:

```powershell
cargo run --bin nodectl -- start --config nodes/validator-a/production.toml
```

8. Start through the service supervisor or explicitly with `--exec` only after
   the dry run is correct.
9. Watch `/ready`, `/health`, queue metrics, storage errors, replay drops, bad
   signatures, fork divergence, and consensus vote failures.
10. Re-enable traffic only after readiness is stable and slot/finality progress
    is observed.

## Rollback Dry Run

Before a live upgrade, rehearse rollback without touching production state:

```powershell
cargo run --bin nodectl -- validate-config --config nodes/validator-a/production.toml
cargo run --bin nodectl -- repair-ledger --storage-dir nodes/validator-a/storage --policy fail-startup
cargo run --bin nodectl -- start --config nodes/validator-a/production.toml
```

The dry run must prove:

- the old binary is still available;
- the old config is still available;
- the backed-up ledger or snapshot validates;
- the start command is known;
- operators know which service-supervisor command will restart the old binary.

## Rollback Procedure

Rollback is allowed only if the previous binary can read the current ledger,
snapshot, config, and storage versions. If any version changed incompatibly,
rollback must restore the matching backup taken before upgrade.

1. Remove node from traffic.
2. Stop the new binary.
3. Preserve logs, metrics, and storage state for investigation.
4. Check compatibility matrix against the old binary.
5. If versions are unchanged, restart the old binary with the previous config.
6. If versions changed, restore the pre-upgrade storage/snapshot/config backup
   before starting the old binary.
7. Validate `/ready`, `/health`, storage scan, and replay progress.
8. Keep the node isolated until it catches up and matches the expected finalized
   root.

## Incompatible Version Behavior

The node must refuse incompatible formats rather than attempting partial reads:

- unsupported config `format_version` fails validation before network start;
- unsupported ledger object versions fail decode/replay;
- unsupported snapshot versions fail decode/restore;
- unsupported blockstore record versions fail `Blockstore::open`;
- unsupported demo storage record versions appear as storage scan issues and
  must trigger fail-startup or quarantine according to policy.

## Schema Migrations

There are no database schema migrations in this release. Adding a storage or
database schema migration requires:

- an explicit source version and destination version;
- idempotent migration behavior;
- backup-before-migration instructions;
- rollback decision tree;
- tests for upgrade from the previous test version;
- tests for incompatible version rejection;
- rollback dry-run documentation.

Until that exists, format-changing releases must be treated as incompatible and
must rely on backups, snapshots, or full replay according to the compatibility
matrix.
