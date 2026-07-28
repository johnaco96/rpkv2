# Validator Set Management

This document describes the initial validator-set implementation. It is a
foundation for consensus work, not a production readiness claim.

## Source Of Truth

Validator sets are loaded deterministically from a TOML genesis/config artifact
through `ValidatorSet::from_toml_str` or `ValidatorSet::from_config`.

Example:

```toml
[[validators]]
validator_id = "validator-a"
tls_spki_hex = "76616c696461746f722d612d73706b69"
packet_signing_key_hex = "<32-byte-ed25519-verify-key-hex>"
consensus_voting_key_hex = "<32-byte-ed25519-verify-key-hex>"
voting_weight = 10
activation_epoch = 0
activation_slot = 0
deactivation_epoch = 10
deactivation_slot = 0
```

`deactivation_epoch` and `deactivation_slot` are optional, but must be supplied
together if either is supplied.

## Identity Roles

Each validator has separate identity material for:

- TLS SPKI transport authentication;
- packet signing verification;
- consensus voting verification.

Duplicate validator ids, duplicate TLS SPKIs, duplicate packet keys, duplicate
consensus voting keys, and packet/consensus key reuse are rejected during
loading. This prevents one role from silently impersonating another.

## Activation Boundaries

Activation is inclusive. A validator is active at its configured
`activation_epoch` and `activation_slot`.

Deactivation is exclusive. A validator is no longer active at its configured
`deactivation_epoch` and `deactivation_slot`.

Stake/weight changes should be represented as validator-set transitions at
defined epoch/slot boundaries. Applying transitions from ledger state remains a
future consensus task.

## Internal APIs

The validator set exposes:

- deterministic validator id iteration;
- active validator lookup at an `EpochSlot`;
- produce/vote authorization checks;
- active voting weight and total active weight;
- reverse lookup by TLS SPKI, packet signing key, and consensus voting key.

Unknown or inactive validators cannot produce or vote through these APIs.

## Remaining Work

This ticket does not implement ledger-governed validator-set transitions,
leader scheduling, fork choice, vote processing, or finality. Those remain
blocking consensus tasks before any production validator claim.
