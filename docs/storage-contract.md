# Storage Durability Contract

This document defines what `stored` means for the current project state and what
must change before validator-grade production storage exists.

## Current Backend

The current `Storage` tile writes append-only files named
`slot-000000000001.shred`. Each record is:

```text
4-byte magic: RPSR
u8 record_version
u64 slot
u16 shred_index
u8 last_flag
u32 data_len
64-byte signature
32-byte BLAKE3 checksum over header fields, signature, and data
data bytes
```

This backend is acceptable for local demos, benchmarks, and tightly scoped
pilots only. It is not validator-grade block storage.

Production config refuses to use this backend unless the operator explicitly
sets:

```toml
[storage]
directory = "store"
allow_unsafe_demo_storage = true
recovery_policy = "fail_startup"
flush_interval_records = 1
flush_interval_ms = 1
sync_data = true
```

`flush_interval_records` and `flush_interval_ms` bound buffered write batches.
`sync_data=true` requests an operating-system data sync for each flushed batch.
The production default remains one synced record per batch. Larger batches
improve throughput but widen the acknowledged-loss window unless completion is
reported only after the batch sync, as the QUIC benchmark does.

The flag is an acknowledgement, not a production readiness claim.

## Meaning Of Stored

For the current demo backend, a shred is considered stored only after the write
calls for the full record have returned and the file handle has been flushed.
This does not guarantee durable persistence across power loss because the code
does not call file or directory `fsync`.

For validator-grade storage, `stored` must mean:

- the full record is written atomically or recovered by a journal;
- file data and required metadata are durably synced according to policy;
- corruption can be detected before replay or serving;
- recovery can rebuild the latest consistent slot/blockstore state after crash.

## Crash Consistency

Current behavior:

- A process crash can leave a partial trailing record.
- A power loss can lose recently flushed but unsynced data.
- Startup scanning detects partial or corrupt records, but there is no manifest,
  journal, checkpoint, or finalized-slot marker.

Required production behavior:

- Recover to the last complete committed record or checkpoint.
- Detect and truncate incomplete trailing records.
- Preserve finalized data across process crash and host reboot.
- Never present partially written data as valid ledger data.

## Fsync Policy

Current behavior:

- `Storage` calls `flush()` after each record.
- It does not call `sync_data`, `sync_all`, or directory fsync.

Required production behavior:

- Define whether durability is per record, per batch, per slot, or per finalized
  root.
- Call file fsync according to that policy.
- Sync directory metadata when creating new files.
- Surface fsync failures as unhealthy storage errors.

## Corruption Detection

Current behavior:

- Records have magic, version, slot, index, last flag, length, signature, and a
  BLAKE3 checksum.
- Startup scanning validates every `slot-*.shred` file and reports the first
  partial or corrupt record in deterministic file and offset order.
- Signatures are included in the checksum envelope, but the storage tile does
  not cryptographically verify signatures on recovery.

Required production behavior:

- Version every on-disk record.
- Include record length, checksum, and preferably a slot/index footer.
- Validate all records during recovery or background scrub.
- Quarantine or truncate corrupt trailing data deterministically.

## Retention

Current behavior:

- No retention policy.
- Files grow until manually removed.

Required production behavior:

- Define retention by finalized slot/root, disk budget, and operator policy.
- Prevent unbounded disk growth.
- Never delete data needed for fork choice, replay, repair, or audit.

## Recovery

Current behavior:

- Startup scans storage files before the storage tile accepts new records.
- Clean startup reconstructs the latest known `(slot, shred_index)` from valid
  records.
- With `recovery_policy = "fail_startup"`, any partial or corrupt file prevents
  startup and reports the first bad path.
- With `recovery_policy = "quarantine_corrupt"`, files with detected issues are
  moved into `storage/quarantine/`, then the active directory is scanned again.
- Recovery is deterministic: files are scanned in sorted path order and records
  in byte-offset order.

Required production behavior:

- Scan storage directory on startup.
- Rebuild slot indexes and latest durable root.
- Detect partial/corrupt records.
- Refuse startup or enter repair mode on unrecoverable corruption.

## Decision

Demo append files must be replaced for a complete production blockchain
validator. They may remain behind explicit opt-in for local testing and
non-critical pilots, but they must not be the default production storage
backend.
