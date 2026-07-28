# Consensus Messages

This document describes the initial consensus-message layer. It is not a full
consensus protocol and does not make the validator production-ready by itself.

## Wire Envelope

Consensus messages use a deterministic binary envelope:

```text
magic             4 bytes  "RPKC"
version           1 byte   1
message_kind      1 byte   1 = block proposal, 2 = vote
epoch             8 bytes  big-endian u64
slot              8 bytes  big-endian u64
validator_id_len  2 bytes  big-endian u16
validator_id      N bytes  UTF-8
message_fields    variable
signature         64 bytes Ed25519
```

The signing preimage uses the fixed domain separator
`rpkv2.consensus.v1`, followed by the same version, kind, slot identity, and
message fields. The wire magic and signature bytes are excluded from the signed
preimage.

## Block Proposal

`message_kind = 1`

```text
parent_hash   32 bytes
block_hash    32 bytes
payload_hash  32 bytes
signature     64 bytes
```

Validation requires:

- proposer exists in the validator set;
- proposer is active for the proposal epoch/slot;
- proposer is the scheduled leader for the proposal epoch/slot;
- block hash and payload hash are nonzero;
- signature verifies with the proposer's consensus voting key.

## Vote

`message_kind = 2`

```text
block_hash  32 bytes
signature   64 bytes
```

Validation requires:

- voter exists in the validator set;
- voter is active for the vote epoch/slot;
- block hash is nonzero;
- signature verifies with the voter's consensus voting key.

## Vote Replay And Equivocation

The replay state tracks one vote per `(epoch, slot, validator_id)`.

- First valid vote for a tuple is counted.
- Repeated vote for the same block hash is a duplicate.
- Vote for a different block hash at the same tuple records
  `EquivocationEvidence`.

The initial evidence record is internal state containing validator id, slot,
first block hash, and conflicting block hash. Network propagation of
equivocation evidence remains future consensus work.

## Not Yet Implemented

Timeout/no-vote messages, network broadcast of equivocation evidence, fork
choice, lockouts, quorum/finality, and ledger/blockstore integration remain
blocking consensus tasks.
