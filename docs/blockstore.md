# Production Blockstore

Ticket 12.2 introduces a durable queryable blockstore backed by a custom
append-log plus deterministic in-memory indexes.

## Backend Choice

The first implementation uses a custom append-log instead of RocksDB or another
new dependency. This keeps the patch small and reviewable while the ledger
format, consensus, fork choice, and replay requirements are still moving.

The backend is one file:

```text
blockstore.log
```

Each committed write batch is stored as one checksummed log record. Indexes are
rebuilt by scanning the full log on startup.

## Record Format

```text
magic       4 bytes  RPBS
version     1 byte   1
kind        1 byte   1=batch
length      u32      payload length, big endian
checksum    32 bytes BLAKE3 over magic, version, kind, length, payload
payload     bytes
```

Unknown versions, unknown record kinds, truncated records, oversized records,
and checksum mismatches are rejected during open.

## Atomic Write Batches

`BlockstoreBatch` can contain:

- shreds;
- blocks;
- votes;
- execution results;
- state roots.

The blockstore writes the whole batch as a single length-delimited record,
flushes it, and calls `sync_all()` before applying the batch to live indexes.
A process crash after a successful batch write can recover by reopening and
rescanning the log.

## Indexes

The blockstore rebuilds these query indexes on open:

- shred by `(slot, block_hash, shred_index)`;
- block by block hash;
- blocks by slot;
- votes by block hash;
- execution result by `(slot, transaction_id)`;
- state root by slot;
- metadata counts and latest indexed slot.

Duplicate identical shreds, blocks, execution results, state roots, and votes
are idempotent. Conflicting duplicates are rejected.

## Tests

The blockstore test suite covers:

- write/read of shreds, blocks, votes, execution results, and state roots;
- reopen after a simulated process crash;
- duplicate shred idempotence;
- corrupted log detection.

## Remaining Production Work

This blockstore is a production-oriented foundation, but it is not yet a full
validator blockstore. Remaining blockers include:

- finalized-root tracking and pruning policy;
- crash recovery for a torn trailing record with deterministic truncate/repair;
- erasure coding and repair indexes;
- fork-choice and replay integration;
- block signature verification during recovery;
- compaction or snapshotting for large long-running deployments;
- file and directory fsync policy review on every target OS.
