# QUIC Runtime Proof

This document records the current proof that the configured validator networking
path is a working Rust implementation of the rpkv2 mutual-RPK QUIC pipeline. It
is not a production-readiness claim.

## Integration Proof

`tests/quic_runtime_proof.rs` starts real Quinn endpoints with the repository
TLS/RPK configuration helpers and the real `ServerPipeline`.

The test proves:

- a valid configured peer connects over mutual RPK QUIC;
- an unknown inbound client SPKI fails;
- a client pinning the wrong server SPKI fails;
- a signed validator packet enters QUIC and reaches:
  `ingress -> rate limit -> dedupe -> verify -> pack -> bank -> PoH -> shred -> sign -> storage`.

Run it with:

```text
cargo test --test quic_runtime_proof -- --nocapture
```

## Benchmark Evidence

`quic_pipeline_bench` runs a local mutual-RPK QUIC benchmark against the same
configured runtime path. It sends signed validator packets, waits for ingress
acks, waits for downstream storage quiescence, and writes CSV/JSON evidence.

Run it with:

```text
cargo run --release --bin quic_pipeline_bench -- \
  --packets 500 \
  --payload-bytes 256 \
  --out-dir benchmarks/results/quic-runtime
```

The current checked artifact is:

- `benchmarks/results/quic-runtime/summary.csv`
- `benchmarks/results/quic-runtime/summary.json`

The JSON schema is `rpkv2.quic_pipeline_benchmark.v1` and includes:

- git commit captured by the built binary;
- crate version;
- build features;
- build profile;
- Rust version;
- OS, CPU count, and architecture;
- benchmark config;
- sent, acked, accepted, stored-record, drop, and error counts;
- packet rate;
- p50/p90/p99/p999 latency.

## Scope

The benchmark latency measures local QUIC datagram send to server pipeline
ingress acknowledgement. `stored_records` proves the downstream tile pipeline
completed storage work, but storage records are shreds, not one record per
input packet.

Use the two-node benchmark runbook for network, NIC, and cross-host claims.
