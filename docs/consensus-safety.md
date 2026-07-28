# Consensus Safety Rules

This document describes the initial local consensus-safety implementation. It
is a conservative safety layer, not a complete fork-choice or finality protocol.

## Local Lockout Rule

The current rule is a strict single-chain lockout:

- a validator may cast its first vote for any known valid block;
- later votes by that validator must advance to a higher epoch/slot;
- later votes must build on the validator's previous voted block;
- switching to a fork that does not descend from the previous vote is rejected.

This rule is intentionally conservative until full fork choice, lockouts,
quorum, and finality are implemented.

## Proposal State

Before a vote is accepted or created, the block must be known through a valid
block proposal. Proposal validation still requires:

- active proposer;
- scheduled leader authorization;
- nonzero block and payload hashes;
- consensus voting-key signature verification;
- known parent block unless the parent is the all-zero genesis/root hash.

## Vote State

The safety state tracks:

- known blocks by block hash;
- one vote per `(epoch, slot, validator_id)`;
- latest vote per validator;
- retained equivocation evidence.

Valid duplicate votes for the same slot and block are treated as duplicates.
Conflicting same-slot votes for different blocks are recorded as
`EquivocationEvidence`.

Votes that reference unknown blocks, are signed by the wrong consensus key, come
from inactive validators, or switch to an unsafe fork are rejected.

## Persistence

Safety-critical state is saved to a deterministic text file with header:

```text
rpkv2.consensus_safety.v1
```

The file records known blocks, votes, and equivocation evidence. Writes use a
temporary file and `sync_all` before rename so a restart can reconstruct prior
vote state before creating or accepting more votes.

## Remaining Work

This does not yet implement:

- BFT fork choice;
- vote lockout expiration;
- optimistic confirmation or finality;
- quorum aggregation;
- ledger/blockstore-backed state transition replay;
- network propagation of equivocation evidence.

Those remain production blockers.
