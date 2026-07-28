# Backpressure Policy

Queue overload is handled explicitly. Production-style packet pipelines must use
`push_with_policy` for bounded `ArrayQueue` stage handoff.

## Policies

| Stage | Queue | Policy |
| --- | --- | --- |
| QUIC ingress | `quic_ingress_to_dedupe` | reject newest |
| Deduper to verifier | `dedupe_to_verify` | spin briefly, then drop newest |
| Verifier to pack | `verify_to_pack` | spin briefly, then drop newest |
| Pack to bank | `pack_to_bank` | spin briefly, then drop newest |
| Bank to PoH | `bank_to_poh` | spin briefly, then drop newest |
| PoH to shredder | `poh_to_shred` | spin briefly, then drop newest |
| Shredder to signer | `shred_to_sign` | spin briefly, then drop newest |
| Signer to storage | `sign_to_storage` | spin briefly, then drop newest |

Ingress rejects the newest packet when the raw queue is full. Internal stages
yield briefly to absorb short bursts. If the downstream queue remains full, the
newest item for that stage is dropped. This keeps worker threads alive and
bounded, but it can lose data under sustained overload.

## Metrics

Each full queue event and resulting action is measurable:

```text
rpkv2_queue_full_total{stage="verify_to_pack",policy="spin_then_drop_newest:64"} 1
rpkv2_queue_dropped_total{stage="verify_to_pack",policy="spin_then_drop_newest:64"} 1
rpkv2_queue_accepted_after_spin_total{stage="verify_to_pack",policy="spin_then_drop_newest:64"} 0
```

Logs are rate-limited per stage to once per second while counters keep
increasing for every event.

## Risk

Blocking indefinitely is avoided because it can hide overload as latency spikes
and deadlock shutdown. Dropping newest preserves bounded memory and liveness,
but callers must treat nonzero drop counters as an unhealthy capacity signal.
