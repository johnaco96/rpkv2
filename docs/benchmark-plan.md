# 2-Node Signed UDP Benchmark (v1)

## Scope

This v1 benchmark adds a direct UDP transmitter/receiver pair for early fastpath measurements without touching QUIC/RPK authentication paths.

## Binaries

### `fast_tx`

Arguments:
- `--target <addr>` (default `127.0.0.1:9000`)
- `--pps <number>` (default `200000`)
- `--payload <bytes>` (default `256`, minimum `16`)
- `--duration-secs <seconds>` (default `10`)
- `--signing on|off` (default `off`)
- `--out-csv <path>` (default `fast_tx_summary.csv`)

Behavior:
- Encodes benchmark metadata in payload prefix:
  - `seq` (`u64`)
  - `send_timestamp_unix_ns` (`u64`)
- Uses header nonce as packet sequence mirror for dedupe compatibility.
- When signing is enabled, signs `header_core || payload` with Ed25519.

### `fast_rx`

Arguments:
- `--bind <addr>` (default `0.0.0.0:9000`)
- `--workers <number>` (default `1`; parsed now, single-thread runtime in v1)
- `--verify on|off` (default `off`)
- `--dedupe on|off` (default `on`)
- `--out-csv <path>` (default `fast_rx_summary.csv`)

Behavior:
- Parses header + benchmark metadata from each packet.
- Optional replay/duplicate filtering via existing replay filter.
- Optional Ed25519 signature verification for signed packets.
- Auto-stops after idle period once packets have been observed.


### `bench_summary`

Usage:
- `cargo run --bin bench_summary -- --tx sender.csv --rx receiver.csv`
- Optional: `--payload 256` to infer throughput when missing, and `--out summary.json` to write machine-readable output.

Behavior:
- Loads one-row summaries from `fast_tx` and `fast_rx` CSV outputs.
- Reports packet counts, estimated loss, duration, effective PPS, throughput Mbps, and latency quantiles when present.
- Handles missing optional columns by reporting `n/a`; errors clearly on missing files or malformed required columns.

## CSV Outputs

`fast_tx` summary:
- target
- requested pps
- payload bytes
- actual duration
- signing mode
- packets sent
- bytes sent
- achieved pps
- achieved Mbps

`fast_rx` summary:
- bind
- workers
- verify mode
- dedupe mode
- received packets
- verified packets
- signature failures
- duplicate/replay drops
- expected packets (from min/max seq)
- estimated loss + loss percent
- latency p50/p90/p99/p999 (microseconds)
- throughput Mbps
- run duration seconds

## Known Limitations (v1)

- `workers` is currently accepted but processing is single-threaded in this first implementation.
- Signature verification requires building with `--features ed25519`; otherwise verify mode records failures.
- Loss estimate depends on contiguous seq range and may overestimate loss if sender restarts sequence.
