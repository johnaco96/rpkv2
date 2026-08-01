# Local Functional Benchmark Evidence

## Scope

The checked-in CSV and JSON files under
`benchmarks/results/quic-runtime/` record a short Windows loopback smoke run.
They demonstrate that the benchmark executable can establish mutually
authenticated RPK QUIC/TLS 1.3, submit signed datagrams to the bounded pipeline,
receive ingress acknowledgements, and observe stored shred records.

This run is **not** a throughput result, capacity claim, production benchmark,
or comparison with another system. Five hundred packets on one computer are
not enough to establish sustained performance, and loopback results do not
represent physical-network behavior.

## Reproduction

From the recorded source commit, run:

```text
cargo run --release --bin quic_pipeline_bench -- local \
  --packets 500 \
  --payload-bytes 256 \
  --timeout-secs 10 \
  --out-dir benchmarks/results/quic-runtime
```

The command replaces `summary.csv` and `summary.json`. Each result records the
source commit, Rust version, build profile, enabled features, operating system,
basic hardware information, packet counts, and the exact measurement scope.

## Interpretation

Only fields actually populated by the local mode should be interpreted. The
`ingress_ack_round_trip` latency is a loopback ingress round trip, not
end-to-end durable completion latency. `stored_records` counts
integrity-protected shred records observed after downstream processing; it is
not a transaction count because a shred may represent batched work. Fields
reported as `not_measured`, `not_collected`, or zero without a matching
local-mode measurement must not be presented as performance evidence.

The authoritative results are the checked-in machine-readable files, not
numbers copied into this document. A change in results after rerunning the
command is expected because scheduling, hardware, operating-system activity,
and build changes affect measurements.

## Evidence Still Required for Performance Claims

Any sustained-throughput or latency claim remains blocked until a documented
multi-node run retains its raw CSV/JSON artifacts and records at least:

- exact reachable source commit and release build metadata;
- host CPU, memory, operating system, kernel, and network interface details;
- offered, accepted, verified, completed, and durably acknowledged rates;
- latency semantics and clock-synchronization method;
- queue high-water marks, drop reasons, CPU, RSS, NIC drops, and storage growth;
- warm-up policy, run duration, repetitions, and variability;
- storage and synchronization configuration.

The two-node procedure is documented in the
[QUIC/RPK VirtualBox benchmark runbook](quic-2node-virtualbox-runbook.md). Until
that evidence is collected and reviewed, the project makes no sustained
performance claim.
