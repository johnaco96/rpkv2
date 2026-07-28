# Snapshots And Fast Catch-Up

Ticket 12.4 adds a deterministic local snapshot format and a fast catch-up
replay path.

## Snapshot Contents

A snapshot contains:

- slot and block hash at the checkpoint;
- full account state;
- state root;
- validator identity records;
- consensus-safety records needed to preserve local safety context;
- snapshot integrity hash;
- snapshot signature field.

The signature field is required to be non-empty. The current implementation
stores and validates signature presence, while cryptographic verification of
distributed snapshots remains a future trust-policy task.

## Format

Snapshot records use:

```text
magic        4 bytes  RPSN
version      1 byte   1
payload      deterministic state, validator, and consensus records
hash         32 bytes BLAKE3("rpkv2.snapshot.v1" || unsigned payload)
signature    64 bytes
```

Unknown versions, trailing bytes, truncated bytes, empty signatures, invalid
validator sets, and state-root/hash mismatches are rejected.

## Fast Catch-Up

Fast catch-up works as:

1. Decode and validate the snapshot.
2. Restore the snapshot state.
3. Use the snapshot block hash as the replay parent.
4. Replay canonical blockstore blocks after the snapshot slot.
5. Verify each later block's stored state root.

The result must match full replay from genesis over the same ledger.

## Tests

The test suite covers:

- snapshot encode/decode integrity;
- corrupt snapshot rejection;
- full replay versus snapshot replay equivalence;
- restart from encoded snapshot;
- continued rejection of corrupt blocks, wrong state roots, and missing votes.

## Remaining Production Work

Snapshots are a trust boundary. Before accepting snapshots from peers or
operators, the project still needs:

- finalized snapshot signing preimage and cryptographic verification;
- snapshot provenance and validator quorum policy;
- snapshot file fsync/atomic publish workflow;
- snapshot compression and chunking;
- fork-choice/finality integration;
- retention policy for old snapshots.
