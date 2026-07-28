# Transaction Format

This document defines the initial executable transaction format. It is a
compatibility contract for the prototype execution layer, not a complete virtual
machine or account-state implementation.

## Wire Envelope

Transactions use deterministic binary serialization:

```text
magic                 4 bytes  "RPKT"
version               1 byte   1
account_key_count     2 bytes  big-endian u16
account_keys          N * 32 bytes Ed25519 verify keys
required_signer_count 2 bytes  big-endian u16
required_signers      N * 2 bytes account-key indices
signature_count       2 bytes  big-endian u16
signatures            N * (signer_index:2 + signature:64)
recent_blockhash      32 bytes
nonce                 8 bytes  big-endian u64
fee                   8 bytes  big-endian u64
compute_limit         8 bytes  big-endian u64
expiration_slot       8 bytes  big-endian u64
instruction_count     2 bytes  big-endian u16
instructions          variable
```

Each instruction is:

```text
program_id_index      2 bytes account-key index
account_index_count   2 bytes
account_indices       N * 2 bytes account-key indices
data_length           4 bytes big-endian u32
data                  N bytes
```

## Signing Preimage

Signatures cover a canonical preimage:

```text
rpkv2.transaction.v1 || version || transaction fields without signatures
```

The signature list is excluded because signatures cannot sign themselves.
Required signer indices, account keys, recent blockhash, nonce, fees, compute
limit, expiration, and instructions are all signed.

## Validity Rules

Before execution, a transaction is valid only if:

- account keys are nonempty and within the configured maximum;
- required signer indices are nonempty, unique, and point to account keys;
- signatures exactly match the required signer set;
- each signature verifies against its account key over the canonical preimage;
- recent blockhash is not all zeros;
- fee is greater than zero;
- compute limit is greater than zero and not above the configured maximum;
- expiration slot is not older than the current slot;
- instructions are nonempty and within configured limits;
- every program and instruction account index points to an account key;
- the transaction id has not already been accepted by replay state.

The transaction id is the BLAKE3 hash of the canonical signing preimage.

## Limits

The initial limits are intentionally conservative:

- account keys: 64
- required signers: 64
- signatures: 64
- instructions: 64
- accounts per instruction: 64
- instruction data: 4096 bytes
- compute limit: 10,000,000

## Remaining Work

This ticket defines format and pre-execution validity. It does not implement:

- account balances;
- fee charging;
- program execution;
- state reads/writes;
- durable nonce accounts;
- blockhash queue integration;
- ledger-backed replay state.

Those are execution-engine and ledger/blockstore tasks that remain production
blockers.
