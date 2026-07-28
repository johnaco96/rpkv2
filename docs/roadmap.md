# Roadmap

This document records the remaining work that materially separates the current
research prototype from a production-quality validator. It is a statement of
known limits, not a production-readiness claim.

## Runtime integration

- Compose consensus messages, fork choice, deterministic execution,
  propagation, snapshots, and blockstore recovery into one configured
  multi-node runtime.
- Add process-level integration tests that restart nodes and exercise catch-up,
  reorganization, key rotation, overload, and graceful shutdown.
- Replace the pilot append-only shred storage path in the benchmark pipeline
  with the blockstore transaction model where appropriate.

## Protocol and security

- Obtain an independent review of the RPK trust model, wire formats, replay
  rules, consensus safety, and operator key lifecycle.
- Add property-based and coverage-guided tests for all untrusted decoders, not
  only the packet header.
- Define protocol negotiation and a compatibility policy before changing any
  on-wire format.
- Exercise malformed, replayed, delayed, reordered, and equivocation traffic
  across real multi-process nodes.

## Performance evidence

- Run the documented two-node benchmark matrix on dedicated Linux hosts.
- Retain exact-commit CSV/JSON results with CPU, RSS, NIC, queue, drop, latency,
  and storage measurements.
- Complete the one-hour and longer soak requirements.
- Profile before introducing kernel-bypass networking or other platform-specific
  fast paths.

## Engineering and release hygiene

- Publish remote CI evidence for release candidates.
- Add dependency vulnerability and license checks to CI.
- Choose and add an explicit repository license before accepting external use
  or contributions.
- Keep the README's implementation and limitation lists synchronized with
  executable tests.
