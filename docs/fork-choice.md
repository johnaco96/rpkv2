# Fork Choice Rule

Ticket 13.2 defines the first deterministic fork-choice rule for the validator
prototype. This is not a final production consensus proof; it is the rule all
nodes must run while replay and consensus are being completed.

## Inputs

- The fork tree of connected ledger blocks.
- The active validator set and each validator's voting weight at the vote slot.
- The latest accepted vote per validator.
- The block cumulative weight tracked by the fork tree.

Votes must be validated by consensus message verification before they are given
to fork choice. Same-slot conflicting votes are not allowed to move fork-choice
weight; they remain safety/equivocation evidence for the consensus layer.

## Comparison Order

Connected fork tips are compared in this exact order:

1. Highest voted stake on the tip's ancestor chain.
2. Latest vote slot on that chain.
3. Highest fork-tree cumulative block weight.
4. Highest tip slot.
5. Lexicographically highest block hash as the final deterministic tie-breaker.

The final hash tie-breaker is intentionally explicit so two nodes with identical
inputs cannot split because of map iteration order or local timing.

## Vote Updates

Fork choice stores one latest vote per validator:

- first valid vote counts;
- duplicate latest vote is ignored;
- older vote is stale and ignored;
- same-slot vote for a different block is conflicting and ignored;
- newer vote moves that validator's weight from the old block to the new block.

Validator voting weight is read from the validator set at the vote slot and is
stored with the latest vote so later weight changes do not corrupt removal of
old vote weight.

## Replay Integration

`ForkChoice::canonical_chain()` returns the selected block hashes from the
finalized root toward the selected tip. Ledger replay should use this ordered
chain when reconstructing canonical state from a blockstore.

## Finality And Rooting

The default finality threshold is rounded-up two-thirds of active stake at the
candidate block's slot. A block is finalizable when the latest votes for blocks
on or below that block meet the threshold. `ForkChoice::try_finalize()` advances
the finalized root to the deepest finalizable block on the current canonical
chain.

After the root advances:

- fork choice rejects new blocks that would roll back before the finalized root;
- votes for pruned non-root forks are removed from the in-memory vote view;
- old non-root forks are pruned from the in-memory fork tree;
- durable blockstore data is not deleted by this in-memory pruning step.

## Leader Schedule Integration

`ForkChoice::insert_authorized_block()` checks block production against the
leader schedule before the block enters the fork tree. Callers that have already
performed leader authorization may use `insert_block()` directly.

## Known Risks

- This rule assumes vote validation and equivocation handling are enforced
  before fork choice receives votes.
- The rule does not yet implement full finality or slashing.
- Production readiness still requires end-to-end integration with replay,
  storage, networking, and validator operations.
