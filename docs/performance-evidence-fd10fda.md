# Local Performance Evidence: fd10fda594fc

## Scope

This evidence was generated from commit `fd10fda594fc` with a release build and
the `dalek_batch` feature. It is a Windows loopback engineering run, not a
two-node production benchmark and not evidence of physical-NIC performance.

The run exercised mutual-RPK QUIC datagrams through:

`ingress -> rate limit -> dedupe -> verify -> pack -> bank -> PoH -> shred -> sign -> storage`

Storage used 256-record buffered flushes, a 10 ms flush deadline, and
`sync_data=true`. The receiver used four verification workers, true Ed25519
batch verification, and four signing workers.

## Exact Run

| Measurement | Result |
| --- | ---: |
| Offered packets | 100,000 |
| Sender offered rate | 99,934 packets/sec |
| Received | 100,000 |
| Ingress accepted | 100,000 |
| Deduplicated | 100,000 |
| Verified | 100,000 |
| Banked | 100,000 |
| Completed | 100,000 |
| Durably acknowledged | 100,000 |
| Shred records written | 20,857 |
| Storage growth | 28,019,412 bytes |
| Receiver durable rate | 97,693 transactions/sec |
| Sampled ingress RTT p50 | 410 us |
| Sampled ingress RTT p90 | 679 us |
| Sampled ingress RTT p99 | 960 us |
| Sampled ingress RTT p999 | 1,324 us |
| Recorded drops/errors | 0 |

The largest observed queue high-water marks were 1,471 of 101,024 at raw
ingress and 959 of 404,096 across verifier shards. No queue approached
saturation in this run.

The receiver also emits one-way samples, but those are explicitly labeled
`one_way_unsynchronized` and are not used as latency evidence unless host clocks
are independently verified as synchronized.

## Interpretation

This run proves functional completion accounting, durable completion exchange,
sampled RTT measurement, stage counters, queue high-water reporting, and a
nominal 100,000 packet/sec loopback load with no recorded loss. It does not pass
the strict sustained-throughput target because measured receiver durable
throughput was 97,693 transactions/sec, below 100,000.

CPU and RSS collection is implemented for Linux. Those fields are zero in this
Windows result and must be populated by the Ubuntu two-node run.

## Required Acceptance Evidence

The performance claim remains blocked until the runbook matrix is executed on
the two Ubuntu nodes and the resulting CSV/JSON files are retained:

- 1,000, 5,000, 10,000, 25,000, and unlimited offered rates;
- no storage, buffered storage, and durable storage;
- individual and batch Ed25519 verification;
- one and multiple authenticated client identities/connections;
- at least 60 minutes at 100,000 verified packets/sec;
- at least 5 minutes at the 200,000 packet/sec burst target;
- Linux CPU, RSS, NIC, queue, drop, latency, and storage-growth evidence.

The current tile runtime writes integrity-protected pilot shred records. It does
not yet convert the runtime output into the separate production blockstore's
ledger model and atomic write batches. Production blockstore integration is an
architectural follow-up and is not claimed by this benchmark.

## Verification Gates

The implementation passed:

- `cargo fmt --all --check`
- `cargo build`
- `cargo test`
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --features dalek_batch`
- `cargo test --features dalek_batch`
- `cargo clippy --all-targets --features dalek_batch -- -D warnings`

