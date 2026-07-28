# Leader Schedule

This document describes the initial leader-schedule implementation. It is a
consensus building block, not a complete fork-choice or finality protocol.

## Rule

For each `EpochSlot`, nodes compute the active validator set at that boundary.
Validators are iterated in deterministic `validator_id` order and selected by
active `voting_weight`.

The schedule index is:

```text
epoch * 1_000_000_007 + slot
```

The leader is the validator whose cumulative active voting-weight range contains
`schedule_index % total_active_weight`.

This is a deterministic weighted round-robin rule. It does not require local
wall-clock time, random node-local state, or network messages. Nodes with the
same validator-set artifact compute the same leader for the same epoch/slot.

## Authorization

`LeaderSchedule::authorize_production` rejects block or shred production from a
validator that is not the computed leader for the requested epoch/slot.

Rejected non-leader production increments:

```text
rpkv2_non_leader_production_rejections_total
```

Consensus, banking, and networking code must call this authorization check
before accepting locally produced or remotely proposed block/shred data.

## Boundaries

Validator activation is inclusive and deactivation is exclusive, matching
`ValidatorSet` behavior. Leader changes caused by activation, deactivation, or
weight changes occur only at the configured epoch/slot boundary represented in
the validator set.

## Remaining Work

This schedule does not yet implement:

- fork choice;
- vote lockouts;
- quorum/finality;
- ledger-governed validator-set updates;
- slashing or equivocation handling;
- production block/shred message validation.

Those remain blocking validator-consensus tasks before a production-readiness
claim.
