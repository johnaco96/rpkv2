# Structured Metrics

The demo and server expose Prometheus-style text metrics over HTTP.

```text
cargo run --bin demo -- --txns 10 --metrics-addr 127.0.0.1:9100
curl http://127.0.0.1:9100/metrics
```

Production config uses:

```toml
[metrics]
bind_address = "127.0.0.1:9100"
```

## Exported Signals

Core counters and gauges:

- `rpkv2_packets_received_total`
- `rpkv2_packets_accepted_total`
- `rpkv2_malformed_packets_total`
- `rpkv2_replay_drops_total`
- `rpkv2_stale_slot_drops_total`
- `rpkv2_bad_signatures_total`
- `rpkv2_unknown_peer_drops_total`
- `rpkv2_active_connections`
- `rpkv2_shreds_written_total`
- `rpkv2_storage_errors_total`
- `rpkv2_non_leader_production_rejections_total`
- `rpkv2_execution_batches_total`
- `rpkv2_execution_transactions_total`
- `rpkv2_execution_conflicts_total`

Histogram-like summaries:

- `rpkv2_verification_batch_size_count/sum/max`
- `rpkv2_verification_latency_us_count/sum/max`
- `rpkv2_packet_latency_us_count/sum/max`

Queue metrics:

- `rpkv2_queue_depth{tile="raw"}`
- `rpkv2_queue_full_total{stage="verify_to_pack",policy="spin_then_drop_newest:64"}`
- `rpkv2_queue_dropped_total{stage="verify_to_pack",policy="spin_then_drop_newest:64"}`
- `rpkv2_queue_accepted_after_spin_total{stage="verify_to_pack",policy="spin_then_drop_newest:64"}`

Per-peer metrics:

- `rpkv2_peer_packets_total{peer="..."}`
- `rpkv2_peer_bytes_total{peer="..."}`
- `rpkv2_peer_malformed_total{peer="..."}`
- `rpkv2_peer_invalid_signatures_total{peer="..."}`
- `rpkv2_peer_replays_total{peer="..."}`
- `rpkv2_peer_throttled_total{peer="..."}`

## Label Policy

Labels are intentionally limited to stable tile/stage names and the current peer
key. The demo uses remote socket address as the peer key; production validator
paths should switch this to authenticated validator id to avoid address churn
and label-cardinality surprises.
