# Ledger Data Model

This document defines the first versioned ledger data model. It replaces the
old idea of anonymous demo shreds with explicit block, entry, transaction
batch, and shred records.

This is a format contract, not yet a validator-grade blockstore. The existing
append-only demo storage remains documented separately in
`docs/storage-contract.md`.

## Versioning

All ledger objects use version `1`.

Object magic values:

- `RPLT`: transaction batch
- `RPLE`: ledger entry
- `RPLB`: ledger block
- `RPLS`: ledger shred

Unknown versions are rejected. Changing field order, field meaning, hash
domains, or integer encoding requires a new version.

All integer fields in the ledger model use big-endian encoding.

## Transaction Batch

A transaction batch groups already-serialized transactions.

```text
magic              4 bytes  RPLT
version            1 byte   1
batch_index        u32
transaction_count  u16
transactions       repeated length-prefixed bytes
batch_hash         32 bytes BLAKE3(domain || unsigned batch bytes)
```

The batch hash domain is `rpkv2.ledger.batch.v1`.

## Entry

An entry chains transaction batches and records the previous entry or parent
block hash.

```text
magic              4 bytes  RPLE
version            1 byte   1
entry_index        u32
previous_hash      32 bytes
batch_count        u16
batches            repeated length-prefixed transaction batch encodings
entry_hash         32 bytes BLAKE3(domain || unsigned entry bytes)
```

The entry hash domain is `rpkv2.ledger.entry.v1`.

Entry indices must be sequential within a block. Batch indices must be
sequential within an entry. The first entry's `previous_hash` must equal the
block parent hash. Each later entry's `previous_hash` must equal the previous
entry hash.

## Block

A block groups entries for a leader slot and references its parent block.

```text
magic              4 bytes  RPLB
version            1 byte   1
epoch              u64
slot               u64
parent_hash        32 bytes
producer_id        u16 length + UTF-8 validator id
entry_count        u16
entries            repeated length-prefixed entry encodings
block_hash         32 bytes BLAKE3(domain || unsigned block bytes)
signature          64 bytes
```

The block hash domain is `rpkv2.ledger.block.v1`.

The block signature field is reserved for the producer's consensus signing key.
Signature verification is handled by consensus/block proposal validation, not
by the pure serialization decoder.

## Shred

A shred carries one chunk of a serialized block. Coding shreds are versioned in
the model but are not reconstructable yet.

```text
magic              4 bytes  RPLS
version            1 byte   1
epoch              u64
slot               u64
block_hash         32 bytes
shred_index        u32
shred_count        u32
kind               u8       0=data, 1=coding
payload            u32 length + bytes
payload_hash       32 bytes BLAKE3(domain || payload)
signature          64 bytes
```

The shred payload hash domain is `rpkv2.ledger.shred.payload.v1`.

Block reconstruction requires:

- a non-empty set of data shreds;
- exactly `shred_count` shreds;
- sequential shred indices starting at zero;
- matching slot, block hash, shred count, and kind;
- valid payload hashes;
- a decoded block whose slot and block hash match the shred headers.

## Integrity Checks

Decoders reject:

- unsupported versions;
- truncated or trailing bytes;
- invalid hash fields;
- non-sequential entry, batch, or shred indices;
- entry chains that do not connect to the parent block hash;
- incomplete or inconsistent shred sets;
- coding shreds in reconstruction until erasure coding is implemented.

## Production Blockers

This ticket does not yet implement:

- durable blockstore indexes;
- finalized-root tracking;
- erasure coding and repair;
- block signature verification inside ledger recovery;
- fork-choice integration;
- replay from ledger into state.

Those remain production blockers for a complete blockchain validator.
