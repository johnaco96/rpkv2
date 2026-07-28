# Overload and Recovery Tests

The overload suite intentionally pushes known failure and recovery paths. It is
designed to prove graceful degradation, not maximum throughput.

## Command

Default suite:

```text
powershell -ExecutionPolicy Bypass -File scripts/run_overload_suite.ps1
```

Direct Rust command:

```text
cargo run --release --features ed25519 --bin overload_suite -- \
  --work-dir benchmarks/results/overload \
  --out-json benchmarks/results/overload/overload-summary.json
```

Short validation run:

```text
cargo run --features ed25519 --bin overload_suite -- \
  --work-dir target/tmp/overload-suite \
  --out-json target/tmp/overload-summary.json \
  --offered-packets 1000 \
  --replay-packets 100 \
  --invalid-signature-packets 100
```

## Scenarios

The suite currently covers:

- Offered load above queue capacity.
- Peer sends invalid signatures.
- Peer sends a replay storm.
- Storage path is temporarily unavailable and then restored.
- Receiver restarts while traffic is in flight.

## Output

The summary JSON uses schema `rpkv2.overload_recovery_suite.v1`.

Each scenario includes:

- `name`
- `passed`
- `bottleneck`
- scenario-specific metrics

Metrics are intentionally named after production-facing signals where possible,
for example queue-full/drop counters, peer invalid-signature counters, peer
throttle counters, replay drops, storage recovery result, and restart-gap drops.

## Pass Criteria

The suite passes when:

- no scenario panics or crashes the process,
- queue overload is visible through queue-full/drop metrics,
- invalid signatures are counted and throttle the abusive peer,
- replay storms accept only the first unique packet and count subsequent drops,
- unavailable storage fails startup/recovery and succeeds after restoration,
- receiver restart resumes traffic after the restart gap.

Any nonzero drop count must be explained by the scenario's configured load,
backpressure policy, replay rejection, storage unavailability, or restart gap.

## Known Limits

These tests are local deterministic stress scenarios. They do not replace
multi-node chaos testing, network partition testing, or full validator
consensus recovery tests.
