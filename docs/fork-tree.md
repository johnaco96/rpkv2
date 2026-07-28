# Fork Tree

Ticket 13.1 adds an in-memory fork tree that can be rebuilt from blockstore
blocks.

## Model

The fork tree stores blocks by:

- block hash;
- parent hash;
- slot;
- direct children;
- missing parent;
- local block weight;
- cumulative connected-chain weight.

The all-zero genesis parent hash is treated as the initial root. Blocks whose
parent is unknown are retained as orphans and connected automatically when the
missing parent arrives.

## Best Fork

The best-known fork is the connected tip with the highest cumulative weight.
Ties are broken deterministically by slot and block hash.

The weight input is supplied by the caller. Today this is a generic `u64` so the
fork tree can be driven by vote/stake accounting once finality and fork-choice
rules are finalized.

## Finalized Root

The tree exposes a finalized root hash and allows it to be advanced to a known
block. Finality policy is not implemented in this ticket; this module only
stores and exposes the selected root.

## Rebuild

The fork tree can be rebuilt from blockstore blocks. Rebuild sorts blocks by
slot and hash before insertion so the result is deterministic even if blockstore
log order differs.

## Tests

Coverage includes:

- linear chain descendant tracking;
- competing fork representation and best-tip selection;
- missing-parent/orphan handling;
- rebuild from blockstore after restart.

## Remaining Production Work

This module does not yet implement:

- vote-lockout fork choice;
- quorum/finality calculation;
- finalized-root pruning;
- slashing/equivocation policy integration;
- durable fork-tree checkpoints.

Fork-choice errors can cause invalid finality or discard valid blocks, so the
final production fork-choice policy must be reviewed separately.
