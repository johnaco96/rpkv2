# Account State Database

This document defines the initial account/state database abstraction. It is a
deterministic execution foundation, not a complete production ledger database.

## Account Model

Each account has:

- `address`: 32-byte account id;
- `owner`: 32-byte program id;
- `lamports`: unsigned balance;
- `data`: opaque account data bytes;
- `nonce`: account version/nonce.

All-zero addresses and all-zero owners are rejected. Account data is capped at
1 MiB in this initial model.

## API

`StateDb` provides:

- deterministic reads by account address;
- insertion with duplicate-address rejection;
- full account writes;
- in-place account updates;
- deterministic account iteration;
- snapshot hooks;
- checkpoint hooks;
- stable state-hash calculation.

The implementation uses sorted account-address ordering so all honest nodes with
the same state compute the same account iteration order and state hash.

## Genesis Format

Genesis state can be loaded from TOML:

```toml
[[accounts]]
address_hex = "<32-byte-account-address-hex>"
owner_hex = "<32-byte-program-id-hex>"
lamports = 1000000
data_hex = "010203"
nonce = 0
```

Duplicate account addresses fail genesis loading.

## State Hash

The state hash is BLAKE3 over:

```text
rpkv2.state.v1
account_count
for each account in sorted address order:
  address
  owner
  lamports
  nonce
  data_length
  data
```

This hash is stable across insertion order and changes when any account field
changes.

## Account Locking

The initial lock rules are:

- many readers may hold the same account concurrently;
- a writer conflicts with any reader or writer for the same account;
- a lock request cannot mark the same account as both readonly and writable;
- non-overlapping accounts do not conflict.

The lock manager is an execution-scheduling primitive. It does not yet define
parallel execution batches or rollback behavior.

## Remaining Work

This abstraction does not yet implement:

- durable storage;
- account rent or minimum balances;
- program execution;
- rollback/journaling;
- ledger-backed checkpoints;
- Merkle proofs or light-client state proofs.

Those remain production blockers for a complete blockchain validator.
