# Consensus Protocol Target

This document defines the consensus target for future validator work. It is a
design target, not an implemented consensus protocol and not a production
readiness claim.

## Target Decision

The current validator target is a **new standalone blockchain validator
prototype**.

It is **not Solana-compatible** and does not currently plug into an existing
Solana or other blockchain client. The codebase provides validator networking,
packet authentication, replay protection, metrics, health, storage,
consensus-component, and benchmark experiments. Validator-set,
leader-schedule, signed-message, fork-choice, finality, and replay components
exist and are tested in isolation, but they are not composed into a valid
production blockchain consensus protocol.

Compatibility with an existing chain is not required for the first consensus
prototype release. If future work changes this decision, this document must be
updated before implementation begins because wire format, vote format, fork
choice, ledger, blockstore, replay, and peer compatibility requirements would
change materially.

## First Production-Release Scope

The first production release must be scoped as a **standalone, permissioned
validator network** unless a later design review changes this target.

In scope for the first production release:

- deterministic validator-set loading from a genesis/config artifact;
- deterministic leader schedule derived from the validator set and voting
  weight;
- signed block/proposal messages;
- signed vote messages;
- fork tracking and fork choice;
- quorum/finality rules;
- equivocation detection;
- ledger/blockstore integration sufficient to restart and replay safely;
- operator runbooks for validator onboarding, rotation, revocation, rollback,
  and incident response.

Out of scope for the first production release:

- Solana protocol compatibility;
- Ethereum or other existing chain compatibility;
- public permissionless validator admission;
- dynamic stake delegation markets;
- slashing with automatic economic penalties;
- light-client proof support;
- bridge or cross-chain compatibility.

## Consensus Assumptions

| Area | Target assumption | Status |
| --- | --- | --- |
| Network model | Partially synchronous network. Safety must hold during partitions; liveness may require eventual timely delivery among enough honest voting weight. | Target only. |
| Validator set | Permissioned validator set loaded deterministically from genesis/config and later ledger-governed state transitions. Unknown validators cannot propose or vote. | Prototype component implemented; ledger-governed transitions remain. |
| Voting weight | Stake-weighted voting is the target. Equal-weight voting may be used only for early local tests and must not be presented as production consensus unless explicitly chosen in a later design review. | Static configured weights implemented; economic stake lifecycle is not. |
| Leader schedule | Deterministic leader schedule derived from validator set, voting weight, epoch/slot, and stable randomness or deterministic seed. All honest nodes must compute the same leader for every slot. | Deterministic weighted prototype implemented and tested. |
| Block/slot timing | Fixed slot duration must be defined before implementation. Slot source must be consensus-aware, not only local wall clock. Clock skew tolerance must be specified. | Production timing model not implemented. |
| Proposal messages | A leader proposes a block or batch for a slot. The proposal must include parent/fork reference, slot, proposer identity, payload commitment, and signature. | Signed prototype message implemented and tested. |
| Vote messages | Validators vote on block/fork candidates with signed vote messages that include validator id, slot, block/fork id, lockout/finality data, and signature. | Signed prototype message implemented and tested; runtime integration remains. |
| Quorum threshold | Finality target is at least two-thirds of active voting weight, unless a later protocol design chooses a different BFT threshold with justification. | Weighted prototype rule implemented and tested; formal analysis and runtime integration remain. |
| Fork choice | Fork choice must be deterministic and must never finalize conflicting forks with honest two-thirds voting weight. | Deterministic prototype implemented and tested; production protocol validation remains. |
| Slashing/equivocation | Equivocation evidence must be detected and recorded. Automatic economic slashing is out of scope for the first release, but equivocation must block or quarantine the offending validator according to a documented policy. | Detection and evidence retention implemented; automated response policy is not. |

## Safety Assumptions

Consensus safety requires:

- all honest nodes use the same genesis/config validator set;
- all honest nodes use the same leader schedule algorithm and slot/epoch
  parameters;
- validators have separate, unambiguous identities for TLS SPKI, packet signing,
  and consensus voting;
- votes are signed over canonical preimages that include domain separation,
  network/cluster id, slot, block/fork id, and vote type;
- no more than one-third of active voting weight violates the protocol in a way
  that can sign conflicting votes;
- finalized blocks are never rewritten after the finality rule is satisfied.

If any of these assumptions are not true, the system must not claim consensus
safety.

## Liveness Assumptions

Consensus liveness requires:

- more than two-thirds of active voting weight is online and able to communicate
  within the network timing assumptions;
- the scheduled leader or a recovery/fallback leader can produce data for each
  live slot;
- honest validators can receive proposals, verify them, vote, and gossip or
  otherwise deliver votes before timeout;
- storage and replay can restart without losing finalized state;
- rate limiting and backpressure do not permanently starve honest validators.

During network partitions, liveness may halt. The protocol must prefer halting
over finalizing conflicting histories.

## Required Message Families

The validator packet format alone is not enough to be a production consensus
protocol. The prototype defines several signed message families, but a complete
runtime must integrate and validate at least:

- `BlockProposal`: implemented prototype leader proposal for a slot/fork;
- `Vote`: implemented prototype validator vote for a proposal or fork state;
- `Timeout` or `NoVote`: optional evidence that a slot did not complete;
- `EquivocationEvidence`: implemented prototype evidence for conflicting votes;
- `ValidatorSetUpdate`: deterministic activation/deactivation or weight update;
- `LedgerRepair`: safe recovery/repair messages if repair is in scope.

Each message family must have canonical signing bytes, domain separation, replay
rules, versioning, and compatibility rules before use on a live network.

## Unsupported Production Behavior

The following are **blockers**, not accepted production risks:

- claiming Solana compatibility without implementing Solana consensus, ledger,
  vote, shred, repair, and network protocol compatibility;
- accepting blocks from a validator that is not in the active validator set;
- accepting votes without stake/voting weight validation;
- finalizing a block without a defined quorum/finality threshold;
- running without fork choice;
- running without deterministic validator-set and leader-schedule agreement;
- running without ledger/blockstore recovery for finalized state;
- treating local replay protection as a substitute for consensus finality;
- treating the current append-file storage experiment as validator-grade
  ledger/blockstore;
- launching without a documented equivocation policy.

The following may be accepted only for local demos or benchmarks:

- equal-weight voting;
- single-validator operation;
- fixed hard-coded leader;
- local wall-clock slot timing;
- no-op slashing/equivocation response;
- non-durable demo storage.

## Design Review Checklist

Before implementing consensus behavior, reviewers must confirm:

- Is this still a standalone protocol target?
- Is any existing-chain compatibility required?
- Are validator identities separated for transport, packet signing, and
  consensus voting?
- Is validator-set loading deterministic?
- Is leader selection deterministic for every node?
- Are vote and proposal preimages canonical and domain-separated?
- Is the quorum/finality rule defined and tested?
- Is fork choice defined and tested?
- Is equivocation evidence generated, stored, and acted on?
- Can a node restart and reconstruct finalized state?

## Security Review Notes

Consensus design must be reviewed together with:

- `docs/threat-model.md`;
- `docs/tls-rpk-security-review.md`;
- `docs/signed-packet-format.md`;
- `docs/storage-contract.md`;
- `docs/production-readiness-review.md`.

The current production-readiness decision remains **NO-GO** until the tested
consensus, fork-choice, finality, validator-set, and ledger/blockstore components
are integrated into one multi-node runtime and validated with release evidence.
