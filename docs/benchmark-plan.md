# Two-Node Signed UDP Benchmark

This benchmark preserves the unmerged two-node signed UDP work for the current
current prototype. It exercises the raw packet fast path, not the
QUIC/RPK validator server.

## Binaries

### `fast_tx`

Arguments:

- `--target <addr>`: receiver UDP address, default `127.0.0.1:9000`
- `--pps <number>`: requested send rate, default `200000`
- `--payload <bytes>`: payload size, default `256`, minimum `16`
- `--duration-secs <seconds>`: bounded run duration, default `10`
- `--signing on|off`: Ed25519 packet signing, default `on`
- `--out-csv <path>`: one-row summary CSV path

`fast_tx` writes sequence and send timestamp metadata into the payload prefix
and signs the current canonical `Header::signing_preimage(payload)` when
signing is enabled.

### `fast_rx`

Arguments:

- `--bind <addr>`: UDP bind address, default `0.0.0.0:9000`
- `--workers <number>`: accepted for runbook compatibility; aggregate CSV uses
  one receiver loop in this implementation
- `--verify on|off`: Ed25519 verification, default `on`
- `--dedupe on|off`: replay filtering, default `on`
- `--idle-timeout-secs <seconds>`: exit after this much idle time once packets
  have been received
- `--out-csv <path>`: one-row summary CSV path

### `bench_summary`

Usage:

```text
cargo run --bin bench_summary -- \
  --tx sender.csv \
  --rx receiver.csv \
  --sender-meta sender.meta.json \
  --receiver-meta receiver.meta.json \
  --out summary.json
```

The parser reads `fast_tx` and `fast_rx` CSV outputs and reports packet counts,
estimated loss, effective packet rates, throughput, and latency quantiles. When
metadata sidecars are provided, the parser embeds them into the summary JSON.

## Fixed Configs and Scripts

- Sender config: `configs/benchmark/sender.env`
- Receiver config: `configs/benchmark/receiver.env`
- Sender setup: `scripts/setup_sender.sh`
- Receiver setup: `scripts/setup_receiver.sh`
- Sender run: `scripts/run_sender.sh`
- Receiver run: `scripts/run_receiver.sh`
- Result collection: `scripts/collect_results.sh`

The run scripts write CSV plus metadata JSON sidecars under
`benchmarks/results/two-node` by default. Use `CONFIG=/path/to/custom.env` to
run a recorded variant without editing the checked-in configs.

## Output Files

- Sender CSV: `target`, `pps_requested`, `payload_bytes`, `duration_secs`,
  `signing`, `packets_sent`, `bytes_sent`, `achieved_pps`, `achieved_mbps`
- Receiver CSV: `bind`, `workers`, `verify`, `dedupe`, `received_packets`,
  `verified_packets`, `signature_failures`, `duplicate_replay_drops`,
  `malformed_packets`, `expected_packets`, `estimated_loss`, `loss_pct`,
  `p50_us`, `p90_us`, `p99_us`, `p999_us`, `throughput_mbps`,
  `run_duration_secs`
- Parser JSON: `tx_packet_count`, `rx_packet_count`, estimated loss, effective
  packet rates, throughput, and latency quantiles
- Sender metadata JSON: schema id, role, timestamp, hardware, OS, kernel, Rust
  version, Cargo version, git commit, branch, features, network interface,
  configured duration, packet size, offered load, accepted-load pointer, drop
  pointer, and latency pointer
- Receiver metadata JSON: same environment fields plus receiver config and
  pointers to accepted load, drops, and latency in the receiver CSV

## Output Schema Validation

A valid repeatable benchmark result contains these files:

```text
sender.csv
receiver.csv
sender.meta.json
receiver.meta.json
summary.json
```

`summary.json` must include:

- `tx_packet_count`
- `rx_packet_count`
- `estimated_loss_count`
- `estimated_loss_percent`
- `effective_tx_pps`
- `effective_rx_pps`
- `throughput_mbps`
- `latency_p50_us`
- `latency_p90_us`
- `latency_p99_us`
- `latency_p999_us`
- `sender_metadata`
- `receiver_metadata`

The metadata objects must use schema
`rpkv2.two_node_benchmark_metadata.v1`.

## Known Limits

- The benchmark is for synthetic fast-path measurement only.
- `fast_rx --workers` is currently parsed for compatibility but aggregates in a
  single receiver loop.
- Signatures use deterministic synthetic benchmark keys. Do not use production
  validator keys.
