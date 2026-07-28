# Sustained Soak Test

The soak harness is a signed UDP loopback test intended to expose leaks,
deadlocks, sustained drop behavior, storage growth, and latency degradation.
It is not a substitute for a multi-node production soak, but it gives operators
a repeatable first-pass command.

## Command

Default one-hour run:

```text
powershell -ExecutionPolicy Bypass -File scripts/run_soak.ps1
```

Direct Rust command:

```text
cargo run --release --features ed25519 --bin soak_bench -- \
  --duration-secs 3600 \
  --pps 10000 \
  --payload 256 \
  --sample-interval-secs 10 \
  --storage-dir benchmarks/results/soak/store \
  --out-json benchmarks/results/soak/soak-summary.json
```

Short validation run:

```text
cargo run --features ed25519 --bin soak_bench -- \
  --duration-secs 5 \
  --pps 100 \
  --payload 64 \
  --sample-interval-secs 1 \
  --storage-dir target/tmp/soak-store \
  --out-json target/tmp/soak-summary.json
```

## Output

The summary JSON uses schema `rpkv2.soak_summary.v1` and includes:

- configured duration, packet rate, and packet size
- sent, received, verified, malformed, replay, and bad-signature counts
- estimated drops
- latency p50/p90/p99/p999
- storage growth bytes
- RSS growth bytes when the platform exposes process RSS
- CPU seconds when the platform exposes process CPU time
- per-sample counters
- `unbounded_memory_growth`
- `dead_tile_detected`
- drop explanation text

## Pass Criteria

For the initial one-hour soak:

- `unbounded_memory_growth` is `false`
- `dead_tile_detected` is `false`
- `bad_signatures`, `malformed_packets`, and `replay_drops` are `0`
- any nonzero `estimated_drops` are explained by configured offered load,
  host UDP buffering, or an intentionally overloaded run
- storage growth is monotonic and bounded by received packet count

Longer production soaks should run for 24 hours or more and include external
host telemetry in addition to this summary.

## Known Limits

The current soak command is single-process loopback. It is useful for finding
local leaks and degradation, but network, peer, and QUIC behavior still require
separate multi-node soak coverage.
