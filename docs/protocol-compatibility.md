# External Protocol Compatibility

Ticket 15.1 defines which external network protocol this validator is intended
to speak. This document is a design contract and not a production-readiness
claim.

## Compatibility Target

The current target is a **custom rpkv2 validator network**.

rpkv2 is not currently Solana/Agave-compatible, Firedancer-compatible, or
Frankendancer-compatible. It also does not currently plug into an existing chain
client as a drop-in validator component.

This decision matches `docs/consensus-target.md`: the project is a standalone,
permissioned blockchain validator prototype. If the target changes to an
existing external protocol, this document and the consensus target must be
updated before implementation starts.

## Compatibility Status

| Target | Status | Decision |
| --- | --- | --- |
| Solana/Agave validator protocol | Unsupported | rpkv2 does not implement Solana gossip, TPU/QUIC transaction ingress semantics, repair, vote accounts, PoH recorder compatibility, shred format compatibility, snapshot format, RPC, or bank runtime. |
| Firedancer/Frankendancer components | Unsupported | rpkv2 does not expose compatible component boundaries, packet formats, tile ABI, ledger, or replay interfaces for Firedancer/Frankendancer integration. |
| Custom rpkv2 validator network | Supported as the design target | rpkv2 may define its own transaction ingress, peer registry, signed packet format, consensus messages, blockstore, snapshots, and operator tooling. |

## External Protocol Surfaces

Every external protocol surface must be classified as supported, unsupported, or
future work before it is exposed to operators.

| Surface | Current status | Compatibility contract |
| --- | --- | --- |
| Transaction ingress | Supported for custom rpkv2 validation layer; network adapters future work | Uses rpkv2 transaction serialization, canonical signing preimages, replay protection, source rate limiting, and interface labels for QUIC, UDP, RPC, and local submissions. It is not Solana TPU or RPC compatible. |
| Gossip | Future work | No production gossip protocol is currently defined. Peer discovery, validator set propagation, vote propagation, snapshot advertisement, and repair discovery require a versioned rpkv2 gossip design before production use. |
| Repair | Supported for custom rpkv2 validation layer; network service future work | Signed rpkv2 repair request/response messages exist for missing shred recovery. A background repair server/client is still future work. |
| Block/shred propagation | Supported for custom rpkv2 validation layer; network service future work | rpkv2 defines signed block and shred propagation envelopes over QUIC datagrams, UDP packets, or streams. It is not Solana shred-compatible. Background fanout service integration is still future work. |
| Vote propagation | Supported for custom rpkv2 consensus messages only | Votes are rpkv2 consensus messages signed by consensus voting keys. They are not Solana vote transactions or vote-account updates. Broadcast/gossip delivery remains future work. |
| Snapshot distribution | Future work | Snapshot format exists for local restore semantics. Network distribution, trust policy, signing, advertisement, download, and verification flows are not production protocol surfaces yet. |
| RPC | Future work | The ingress layer reserves an rpkv2-native RPC source type, but no public RPC server/API compatibility target is implemented. If added, RPC must be explicitly scoped as rpkv2-native or compatible with a named external API. |
| Metrics and health | Supported as operator HTTP endpoints | Metrics, health, and readiness are operational endpoints, not chain protocol compatibility surfaces. Keep them protected from public access. |

## Required rpkv2 Protocol Rules

Custom rpkv2 protocol surfaces must follow these rules:

- every message family has an explicit version;
- every signed message has a canonical signing preimage and domain separator;
- validator identity separates transport SPKI, packet signing key, and consensus
  voting key;
- unknown versions are rejected, not guessed;
- unsupported critical flags are rejected;
- ledger, snapshot, blockstore, and config formats are covered by upgrade and
  rollback rules;
- peer-facing protocol changes require compatibility tests and release notes.

## Compatibility Test Strategy

The implemented v1 conformance suite lives in
`tests/fixtures/conformance/v1/` and is exercised by the ordinary `cargo test`
CI gate. Compatibility failures in this suite are release blocking.

The minimum compatibility test strategy is:

1. Golden fixtures for every externally visible rpkv2 message format.
2. Decode rejection tests for unknown versions and unsupported critical flags.
3. Cross-node fixture tests proving two nodes with the same genesis/config
   compute the same validator set, leader schedule, fork choice, finalized root,
   and state root.
4. Signed-message compatibility tests for transaction ingress, block proposals,
   votes, snapshots, and repair messages when those surfaces exist.
5. Negative tests proving Solana/Agave/Firedancer wire formats are not silently
   accepted unless a future compatibility ticket explicitly implements them.
6. Upgrade tests proving old supported rpkv2 versions are accepted or rejected
   according to `docs/safe-upgrade-rollback.md`.
7. Interop tests between the release candidate and the previous supported rpkv2
   release before any live network upgrade.

## Production Blockers

The following remain blockers for any claim that rpkv2 is compatible with an
external production validator protocol:

- claiming Solana/Agave compatibility without implementing and testing all
  required Solana protocol surfaces;
- claiming Firedancer/Frankendancer compatibility without a defined component
  interface and fixture suite;
- exposing gossip, repair, snapshot distribution, or RPC as production surfaces
  before their message formats, authentication, authorization, replay behavior,
  and compatibility tests exist;
- accepting foreign protocol messages as if they were rpkv2-native messages;
- changing any external rpkv2 protocol surface without versioning and upgrade
  documentation.

## Design Review Checklist

Before implementing or exposing a network protocol surface, reviewers must
confirm:

- Is the target still custom rpkv2?
- Is compatibility with Solana/Agave, Firedancer/Frankendancer, or another
  external implementation required?
- Is the surface listed in this document?
- Is its status supported, unsupported, or future work?
- Does the implementation reject unknown or incompatible versions?
- Are golden fixtures and negative compatibility tests present?
- Does the operator runbook describe how to deploy or disable the surface?
