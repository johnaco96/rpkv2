# Production Scale Targets

This document defines measurable production-scale targets for the current
current prototype. These are acceptance targets for future validation;
they are not claims that the current prototype already meets them.

## Baseline Test Profile

Unless a test says otherwise, measure on one validator node with:

- Linux x86_64, 8 dedicated vCPU, 32 GiB RAM, NVMe-backed storage.
- `--features ed25519`.
- Signed packets using `Header::signing_preimage(payload)`.
- Payload size: 256 bytes.
- Dedupe/replay protection enabled.
- Structured metrics endpoint enabled.
- Storage recovery policy explicitly configured.

Scale targets must be reported with the exact machine type, kernel, commit,
Cargo profile, feature flags, and config file used.

## Target Table

| Area | Production-scale target | Measurement |
| --- | ---: | --- |
| Packets/sec per node | Sustain 100,000 accepted signed packets/sec for 60 minutes; burst to 200,000 packets/sec for 5 minutes | `fast_tx`/`fast_rx` CSV: `received_packets / run_duration_secs`; runtime metric: rate of `rpkv2_packets_accepted_total` |
| Verified tx/sec | Sustain 100,000 verified tx/sec for 60 minutes | `fast_rx` CSV: `verified_packets / run_duration_secs`; runtime metric: rate of accepted packets with `rpkv2_bad_signatures_total` flat |
| End-to-end packet latency | p50 <= 2 ms, p90 <= 5 ms, p99 <= 20 ms, p999 <= 100 ms during sustained target load | `fast_rx` CSV: `p50_us`, `p90_us`, `p99_us`, `p999_us`; runtime metric: `rpkv2_packet_latency_us_*` |
| Verification latency | p99 <= 10 ms per verification batch | runtime metric: `rpkv2_verification_latency_us_max` sampled during run; future histogram percentiles should replace max-only validation |
| Packet loss under load | <= 0.01% estimated packet loss during sustained target load; 0 unexplained loss in a 10-minute steady-state segment | `bench_summary` JSON: `estimated_loss_percent`; receiver CSV: `loss_pct` |
| Bad signature rate | 0 accepted invalid signatures; invalid signatures counted and rejected | `rpkv2_bad_signatures_total`; negative test traffic must not increase accepted packet rate |
| Replay/drop correctness | 0 accepted duplicates within active replay window | replay tests plus `rpkv2_replay_drops_total`; benchmark duplicate injection report when available |
| Max queue depth | Every production queue remains below 75% of configured capacity for 99% of samples; never exceeds 90% for more than 10 seconds | `rpkv2_queue_depth{tile="..."}` sampled at 1-second interval and compared with configured queue sizes |
| Queue full drops | 0 queue-full drops during target sustained load | `rpkv2_queue_full_total{stage="..."}` and `rpkv2_queue_dropped_total{stage="..."}` remain flat |
| CPU usage | <= 80% sustained process CPU across allocated cores; <= 95% for bursts shorter than 60 seconds | OS/process telemetry: `pidstat`, `perf`, container metrics, or cloud agent CPU utilization |
| Memory usage | <= 16 GiB RSS sustained; no monotonic RSS growth > 5% after warmup during 24-hour soak | OS/process telemetry: RSS from `ps`, `pidstat -r`, container metrics, or cloud agent |
| Active connections | Maintain 1,000 active QUIC connections with health ready and no worker panic | runtime metric: `rpkv2_active_connections`; `/ready` returns HTTP 200 |
| Peer count | Maintain 1,000 configured peers; reject unknown peers; startup validation <= 30 seconds | config load timing; peer registry count in startup logs; `rpkv2_unknown_peer_drops_total` for rejected unknowns |
| Restart recovery time | Clean restart ready <= 30 seconds for normal storage; crash recovery/quarantine decision <= 120 seconds for 100 GiB storage | time from process start to `/ready` HTTP 200; storage recovery logs; `/health` JSON |
| Sustained soak duration | 24 hours at 100,000 signed packets/sec with no process restart, no critical worker panic, and no readiness loss | `/health`, `/ready`, tile health metrics, process uptime, accepted packet rate, queue metrics |
| Health/readiness | `/health` always reports `ready`, `degraded`, `unhealthy`, or `shutting_down`; `/ready` fails during startup, storage failure, worker failure, and shutdown | `/health` and `/ready` HTTP responses and JSON bodies |
| Storage errors | 0 storage write errors during target load; corrupted startup state detected deterministically | `rpkv2_storage_errors_total`; storage recovery tests/logs |

## Measurement Requirements

Every production-scale result must include:

- Commit SHA and branch.
- Exact binary and command line.
- Config file with secrets redacted.
- Hardware and OS description.
- Start/end timestamps.
- Sender CSV, receiver CSV, and `bench_summary` JSON when using the two-node UDP benchmark.
- Metrics scrape archive for runtime validator/demo tests.
- Logs covering startup, steady state, and shutdown.

Any claim without matching measurement artifacts is considered unverified.

## Benchmark Commands

Two-node UDP packet benchmark:

```text
WORKERS=1 VERIFY=on DEDUPE=on OUT_CSV=receiver.csv bash scripts/run_receiver.sh
RECEIVER_IP=<receiver_ip> PPS=100000 PAYLOAD=256 DURATION=3600 SIGNING=on OUT_CSV=sender.csv bash scripts/run_sender.sh
cargo run --bin bench_summary -- --tx sender.csv --rx receiver.csv --payload 256 --out summary.json
```

Runtime metrics scrape:

```text
curl http://127.0.0.1:9100/metrics
curl http://127.0.0.1:9100/health
curl http://127.0.0.1:9100/ready
```

Initial sustained soak:

```text
powershell -ExecutionPolicy Bypass -File scripts/run_soak.ps1
```

The soak output is `benchmarks/results/soak/soak-summary.json` by default. See
`docs/soak-test.md` for the summary schema and pass criteria.

Overload and recovery suite:

```text
powershell -ExecutionPolicy Bypass -File scripts/run_overload_suite.ps1
```

The overload output is `benchmarks/results/overload/overload-summary.json` by
default. See `docs/overload-recovery-tests.md` for scenarios and pass criteria.

## Pass/Fail Rules

A run passes only if all target rows relevant to the run type meet their target.
For example, a two-node UDP benchmark can validate packet rate, verified
throughput, loss, latency, and CPU/memory, but it does not validate QUIC
connection count or configured peer count.

If a target cannot be measured with current tooling, the result must be marked
`not measured`; it must not be inferred from unrelated metrics.

## Open Measurement Gaps

The current metrics expose max/sum/count for latency-like values, but not full
runtime percentile histograms. Production validation should add histogram
buckets or external percentile aggregation before relying on runtime metrics
for p99/p999 latency claims.

The current two-node `fast_rx` benchmark accepts `--workers` for runbook
compatibility but aggregates in one receiver loop. Multi-worker aggregate CSV
support is required before using this benchmark to prove multi-core packet
ingest scaling.
