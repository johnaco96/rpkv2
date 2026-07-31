# Fork Tree

The project includes an in-memory fork tree that can be rebuilt from blockstore
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
block. The separate `fork_choice` module applies the prototype weighted finality
rule, advances the root, and prunes forks that are no longer descendants of it.

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

The composed prototype does not yet implement:

- production vote lockouts;
- a formally analyzed consensus/finality protocol;
- slashing/equivocation policy integration;
- durable fork-tree checkpoints.

Fork-choice errors can cause invalid finality or discard valid blocks, so the
final production fork-choice policy must be reviewed separately.
