# Execution Policy

The first production-target execution policy is ordered execution.

## Policy

Transactions are committed in the exact order supplied by consensus. Thread
scheduling, queue scheduling, and conflict-detection order must not affect the
committed state root or receipt order.

Parallel account-lock execution and optimistic parallel execution are not
enabled for production mode yet. They remain future work because an incorrect
parallel scheduler can create consensus divergence.

## Conflict Detection

The executor derives a deterministic account lock set for each structurally
valid transaction:

- required signers are writable;
- instruction account indices are writable;
- all other account keys are readonly.

Before ordered execution, the batch planner reports account conflicts between
transactions in input order:

- `WriteWrite` when two transactions both write the same account;
- `ReadWrite` when one transaction reads an account another transaction writes.

In ordered mode, conflicts are not rejected by the planner. They are recorded so
operators can measure how much parallelism a future scheduler would need to
serialize. Transaction validity and execution errors are still enforced by the
normal deterministic execution pipeline.

Malformed transactions that cannot produce a valid lock set are skipped by
conflict detection and then fail execution deterministically with a validation
receipt.

## Metrics

Execution adds these Prometheus-style counters:

- `rpkv2_execution_batches_total`
- `rpkv2_execution_transactions_total`
- `rpkv2_execution_conflicts_total`

These counters are intentionally low-cardinality. They do not include account
addresses, transaction ids, or signer keys.

## Future Parallel Mode Requirements

Any future parallel execution policy must prove:

- committed receipts are emitted in consensus input order;
- account conflicts are resolved deterministically;
- failed worker threads cannot partially commit state;
- repeated runs over the same ordered transaction fixture produce the same
  state root;
- conflict and throughput metrics remain available.
