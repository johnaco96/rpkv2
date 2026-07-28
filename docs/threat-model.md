# Threat Model

This threat model describes what the current research prototype is
intended to defend against and where risk is explicitly accepted. It is a design
review artifact, not a claim that the system is production ready.

## Protected Assets

- Validator identity and packet-signing keys.
- Peer identity bindings: validator id, TLS SPKI pin, and Ed25519 packet
  verification key.
- Validator packet authenticity and integrity.
- Replay state and accepted packet stream.
- Queue capacity and tile liveness under load.
- Stored shred records and recovery state.
- Metrics, health, readiness, and structured logs used by operators.

## Trust Boundaries

- Local process memory is trusted only while the host is uncompromised.
- Local config files are trusted only when provisioned out of band and reviewed.
- Configured validator peers are trusted to possess their declared keys, but may
  still be faulty or malicious at the protocol edge.
- The network is untrusted.
- Benchmark nodes are untrusted disposable infrastructure.
- Storage media may lose, corrupt, or partially write data.

## Assumptions

- Operators protect private keys, config files, and SPKI pin material outside of
  this repository.
- Production-like builds use the default `ed25519` feature and do not use
  `insecure_demo`.
- Operators configure a stable cluster id before any real network launch.
- Validator clocks are synchronized enough for SPKI validity windows and slot
  freshness decisions.
- The current append-file storage backend is pilot/demo storage only.

## Threats

| Threat | Current mitigation | Accepted risk or design gap |
| --- | --- | --- |
| Trusted validators act honestly but may fail | Peer config binds `validator_id` to TLS SPKI pins and Ed25519 verify keys. Health/readiness endpoints and tile supervision expose worker failure. | There is no complete consensus, fork choice, slashing, or validator-set governance layer yet. A trusted validator can still send bad-but-validly-signed protocol data that this prototype cannot fully adjudicate. |
| Untrusted network observes, delays, drops, or injects packets | QUIC/RPK paths pin peer TLS SPKI. Validator packets carry Ed25519 signatures over a canonical preimage with domain and cluster separation. Replay protection rejects duplicate `(slot, nonce, validator)` tuples. | Network availability is not guaranteed. Traffic analysis, DDoS, routing attacks, and partition handling require deployment controls and future consensus/network protocol work. |
| Malicious configured peer sends validly signed harmful traffic | Per-peer rate limiting tracks packet, byte, malformed, invalid-signature, and replay rates. Replay state and queue backpressure constrain resource use. Structured logs and metrics identify the peer and reason. | Application-level semantic validation is incomplete. A peer with a valid key can consume its allowed rate budget and can sign syntactically valid but economically or consensus-invalid data until higher layers reject it. |
| Key compromise: TLS private key, packet signing key, or config material leaks | TLS SPKI pin rotation supports validity windows. Revoked SPKI pins are rejected even when otherwise active. Production binaries require real Ed25519 support. Docs require out-of-band key handling and no committed secrets. | Packet signing key rotation/revocation is less complete than TLS SPKI rotation. A compromised packet-signing key can sign valid packets until config is updated and nodes restart. No HSM/KMS integration exists. No automatic compromise detection exists. |
| Replay attacker reuses old packets | Signatures cover slot, nonce, key id, message type, flags, domain, cluster id, and payload hash. Deterministic replay state rejects duplicates inside the active slot window and rejects stale slots. Bloom is only a front-filter hint. | Replay protection is memory-bounded. Very old replay behavior depends on slot-window policy. Clock/slot skew and finality semantics are not yet tied to a full consensus clock. |
| Packet flooder overwhelms queues or CPU | Per-peer packet/byte limits throttle abusive peers. Queue push failures increment metrics and follow explicit backpressure policy. Overload suite exercises queue-full and drop metrics. Health/readiness expose degraded/unhealthy state. | Host/network DDoS can still saturate NIC, kernel queues, or CPU before application logic runs. Multi-peer distributed floods require upstream filtering and deployment controls. |
| Malformed packet attacker sends arbitrary bytes | `Header::decode_from` validates length, version, message type, and flags. Fuzz target and deterministic malformed parser tests cover empty, short, exact, oversized, and random inputs. Verification rejects malformed pubkey/signature bytes without panicking. | Full datagram ingestion fuzzing is limited. Future message types and payload parsers need the same no-panic treatment. |
| Invalid signature attacker sends packets with bad signatures | Ed25519 verification is mandatory for production-labeled binaries. Bad signatures are counted and rejected. Per-peer invalid-signature rate can throttle abusive peers. | Verification still consumes CPU before rejection. Batch verification and peer throttling reduce but do not eliminate CPU exhaustion risk. |
| Disk corruption or partial writes | Stored records include magic, version, length, signature, and BLAKE3 checksum. Startup scanning detects partial/corrupt records. Recovery policy can fail startup or quarantine corrupt files deterministically. Storage errors are measured. | Current storage uses append files with `flush()` but no fsync policy, journal, manifest, finalized-root tracking, or validator-grade blockstore. It is explicitly pilot/demo storage only. |
| Node restart during traffic | Coordinated shutdown and worker supervision exist. Storage recovery scans on startup. Health/readiness stays non-ready until required checks pass. Overload suite includes receiver restart during traffic. | In-flight packets can be lost during restart. There is no consensus replay/fork-choice recovery path. Storage recovery does not rebuild a complete ledger/blockstore state. |
| Clock or slot skew | SPKI validity windows are explicit Unix seconds. Replay slot window rejects stale slots relative to observed head. Docs require NTP and rotation overlap larger than expected skew. | Slot source is not consensus-derived. Excessive clock skew can reject valid SPKI windows or allow expired pins until restart. Slot skew policy is not yet network-wide or finality-aware. |
| Metrics/log disclosure | Startup logs avoid private keys and PEM contents. Structured logs use stable fields and rate limiting. Docs require artifact secret review before sharing benchmark output. | Metrics and health endpoints are unauthenticated in the simple local HTTP listener. Deployments must bind them to localhost or protect them with network controls. |
| Unsafe demo/stub crypto use | Production binaries fail to build without `ed25519`. Stub crypto is only behind explicit `insecure_demo` for demo-style builds. Docs label it insecure. | Humans can still run demo-only modes in inappropriate environments. Release packaging should make secure profiles obvious and prevent accidental insecure deployment. |

## Current Design Gaps

The following gaps must be closed before this can be considered a complete
production blockchain validator:

- Consensus, fork choice, validator voting, and slashing/equivocation handling.
- Validator-grade ledger/blockstore with fsync policy, indexes, finalized roots,
  repair, retention, and audit tooling.
- Packet-signing key rotation and revocation equivalent to TLS SPKI rotation.
- Authenticated or network-protected operations endpoints.
- Full multi-node chaos testing for partitions, restarts, packet loss, and
  adversarial peers.
- Runtime percentile metrics for p99/p999 latency rather than max/sum/count
  approximations.
- Clear mainnet/testnet/devnet cluster-id configuration and compatibility
  process.

## Review Checklist

For every production-readiness change, reviewers should ask:

- Which protected asset does this touch?
- Which trust boundary does it cross?
- Does it alter signed bytes, identity binding, replay state, storage recovery,
  or operational observability?
- Does it add a new unauthenticated surface?
- Does it create a new failure mode that must appear in metrics, health, or
  structured logs?
- Is the risk mitigated in code, documented as accepted risk, or opened as a
  follow-up ticket?
