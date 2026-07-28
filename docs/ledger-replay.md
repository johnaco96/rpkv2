# Ledger Replay From Genesis

Ticket 12.3 adds deterministic replay from genesis state through canonical
ledger blocks stored in the blockstore.

## Replay Inputs

Replay requires:

- a genesis state config;
- a blockstore containing canonical blocks;
- votes for each block;
- a stored state root for each replayed block.

The first block must reference the all-zero genesis parent hash. Each later
block must reference the previous replayed block hash.

## Replay Order

Blocks are replayed in ascending `(epoch, slot)` order. A slot containing more
than one stored block is rejected as ambiguous instead of choosing a fork.

Within each block, transactions are replayed in this order:

1. block entries;
2. transaction batches inside each entry;
3. serialized transactions inside each batch.

## Validation

Replay validates:

- block hash and entry-chain integrity;
- parent hash continuity;
- non-empty block signature field;
- at least one vote for each block;
- vote slot and block hash match the replayed block;
- non-empty vote signature field;
- transaction decoding and deterministic execution;
- stored state root matches the replayed state root.

The current ledger block format does not yet define a consensus signing
preimage for the block signature field, so replay enforces signature presence
but does not cryptographically verify the block producer signature. Consensus
message verification remains the source of cryptographic proposal and vote
validation until block signatures are formally bound to a signing preimage.

## Progress

Replay returns progress snapshots after each block:

- blocks replayed;
- transactions replayed;
- latest slot;
- current state root.

This gives operators a deterministic progress signal for startup and recovery.

## Stop Conditions

Replay stops safely and returns an error on:

- ambiguous slot/fork data;
- missing block parent;
- missing votes;
- malformed transactions;
- failed transaction execution;
- missing state root;
- wrong state root;
- corrupted block integrity.

## Remaining Production Work

Replay still needs:

- cryptographic block-signature verification after the ledger signing preimage
  is finalized;
- fork-choice integration instead of rejecting all ambiguous slots;
- finalized-root checkpoints;
- replay resume from snapshots;
- full validator-set and vote-quorum validation.
