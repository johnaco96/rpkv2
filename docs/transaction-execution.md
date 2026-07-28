# Deterministic Transaction Execution

This document defines the initial deterministic execution engine. It is a small
execution foundation, not a general-purpose virtual machine.

## Pipeline

For each ordered transaction, execution performs:

1. Decode transaction bytes if using the encoded entrypoint.
2. Validate transaction structure, expiration, and signatures.
3. Load all referenced accounts.
4. Check fee-payer nonce and balance.
5. Reject replayed transactions.
6. Charge fee and increment fee-payer nonce.
7. Execute instructions with compute metering.
8. Commit state changes on success.
9. Roll back instruction changes on execution failure while retaining fee and
   nonce effects.
10. Return an execution receipt.

Validation failures before fee charging have no state effects. Execution
failures after fee charging keep the fee and fee-payer nonce increment, but
discard instruction writes.

## Built-In Program

The initial built-in system program id is:

```text
0x0101010101010101010101010101010101010101010101010101010101010101
```

Supported opcodes:

- `0`: noop, costs 1 compute unit.
- `1`: transfer, costs 10 compute units.

Transfer instruction data is:

```text
opcode: 1 byte = 1
amount: 8 bytes big-endian u64
```

Transfer account indices are:

```text
[from, to]
```

The `from` account must be a required transaction signer.

## Fees And Nonces

The first required signer is the fee payer. The fee payer account nonce must
match the transaction nonce. When a transaction passes signature/expiration/load
checks and is not a replay, the fee is charged and the fee-payer nonce is
incremented before instruction execution.

Replay rejections do not charge a second fee.

## Compute Metering

Compute is deterministic per opcode. If an instruction would take total compute
above the transaction compute limit, execution fails with
`ComputeLimitExceeded`; fee and nonce effects remain, but instruction writes are
rolled back.

## Receipts

Each execution returns:

- transaction id;
- status;
- fee charged;
- compute used;
- pre-state hash;
- post-state hash.

Malformed encoded input returns a failed receipt and does not panic.

## Execution Policy

The first production-target policy is ordered execution. Transactions are
committed in the exact consensus input order, and account conflicts are reported
for observability instead of being scheduled in parallel.

See `docs/execution-policy.md` for the full policy and metrics.

## Remaining Work

This engine does not yet implement:

- arbitrary program loading;
- account ownership enforcement beyond transfer signer checks;
- rent or fee distribution;
- durable nonce accounts;
- production parallel scheduler batches;
- rollback journal persistence;
- ledger/blockstore integration.

Those remain production blockers.
