# Two-Node QUIC/RPK VirtualBox Benchmark

This runbook is for the local VirtualBox test environment:

- receiver VM: `RPKv4`, host-only IP `192.168.56.101`;
- sender VM: `RPKv4-clone`, host-only IP `192.168.56.102`.

The numbers from this environment are useful functional benchmark evidence, but
they are not production validator performance claims.

## 1. Update Both VMs

```text
cd ~/rpkv2
git fetch --all
git checkout main
git pull --ff-only
cargo build --release --bin quic_pipeline_bench --features dalek_batch
```

## 2. Generate Transport Keys

On the receiver VM:

```text
cd ~/rpkv2
mkdir -p bench-keys
cargo run --release --bin quic_pipeline_bench -- generate-key \
  --key-out bench-keys/receiver.key \
  --spki-out bench-keys/receiver.spki
```

On the sender VM:

```text
cd ~/rpkv2
mkdir -p bench-keys
cargo run --release --bin quic_pipeline_bench -- generate-key \
  --key-out bench-keys/sender.key \
  --spki-out bench-keys/sender.spki
```

Copy `sender.spki` to the receiver and `receiver.spki` to the sender. Example
from the receiver VM:

```text
scp test@192.168.56.102:~/rpkv2/bench-keys/sender.spki bench-keys/sender.spki
```

Example from the sender VM:

```text
scp test@192.168.56.101:~/rpkv2/bench-keys/receiver.spki bench-keys/receiver.spki
```

## 3. Run Receiver

Before the high-load matrix, inspect Linux UDP limits on both nodes:

```text
sysctl net.core.rmem_max net.core.wmem_max
```

If either limit is below the benchmark's 16 MiB QUIC buffers, temporarily raise
it for the disposable benchmark VM and record the values with the result:

```text
sudo sysctl -w net.core.rmem_max=33554432
sudo sysctl -w net.core.wmem_max=33554432
```

These are host settings, not application defaults. Do not apply them blindly to
shared production hosts.

On `RPKv4`:

```text
cd ~/rpkv2
cargo run --release --features dalek_batch --bin quic_pipeline_bench -- receiver \
  --bind 192.168.56.101:4433 \
  --server-key bench-keys/receiver.key \
  --client-spki bench-keys/sender.spki \
  --expected-packets 10000 \
  --startup-timeout-secs 120 \
  --idle-timeout-secs 10 \
  --connections 1 \
  --verifier-workers 2 \
  --verifier-batch 256 \
  --signer-workers 2 \
  --queue-capacity 16384 \
  --replay-capacity 1000000 \
  --storage-enabled true \
  --storage-flush-records 256 \
  --storage-flush-ms 10 \
  --storage-sync-data false \
  --out-dir benchmarks/results/quic-2node/receiver \
  --storage-dir benchmarks/results/quic-2node/receiver/storage
```

Leave this running before starting the sender.

`--startup-timeout-secs` allows the sender to pre-sign a large packet corpus
after connecting. It is separate from `--idle-timeout-secs`, which detects
missing traffic after sending begins.

## 4. Run Sender

On `RPKv4-clone`:

```text
cd ~/rpkv2
cargo run --release --features dalek_batch --bin quic_pipeline_bench -- sender \
  --connect 192.168.56.101:4433 \
  --client-key bench-keys/sender.key \
  --server-spki bench-keys/receiver.spki \
  --packets 10000 \
  --payload-bytes 256 \
  --rate-pps 1000 \
  --burst-size 64 \
  --send-policy wait \
  --sample-every 100 \
  --connections 1 \
  --out-dir benchmarks/results/quic-2node/sender
```

## 5. Artifacts

Receiver output:

- `benchmarks/results/quic-2node/receiver/receiver-summary.csv`
- `benchmarks/results/quic-2node/receiver/receiver-summary.json`
- `benchmarks/results/quic-2node/receiver/storage/`

Sender output:

- `benchmarks/results/quic-2node/sender/sender-summary.csv`
- `benchmarks/results/quic-2node/sender/sender-summary.json`

Receiver latency is one-way latency based on the sender timestamp inside each
packet. Treat it as approximate unless both VM clocks are synchronized.
The sender JSON reports sampled ingress RTT, which does not require synchronized
clocks. `--rate-pps 0` disables pacing and offers packets as quickly as the
sender can enqueue the pre-signed bulk corpus. Controlled-rate runs use
`--send-policy wait`, which preserves older queued datagrams and reports
send-buffer pressure. Use `--send-policy evict-oldest` only for an explicit
overload test where Quinn queue eviction is part of the measured policy.

## 6. First Ramp

Start conservative:

```text
--packets 10000 --rate-pps 1000
```

Then try:

```text
--packets 50000 --rate-pps 5000
--packets 100000 --rate-pps 10000
--packets 200000 --rate-pps 25000
--packets 200000 --rate-pps 0
```

Stop increasing when drops, sender errors, storage errors, or VM CPU saturation
appear.

## 7. Required Matrix

Run each offered rate at `1000`, `5000`, `10000`, `25000`, and `0`. For every
rate, preserve both sender and receiver CSV/JSON under a unique output folder.

Compare these configurations:

| Case | Build/features | Receiver options | Sender options |
| --- | --- | --- | --- |
| Individual verification | default `ed25519` | `--verifier-workers 1` | `--connections 1` |
| Batch verification | `--features dalek_batch` | `--verifier-workers 1 --verifier-batch 256` | `--connections 1` |
| Parallel batch verification/signing | `--features dalek_batch` | `--verifier-workers 2 --verifier-batch 256 --signer-workers 2` | `--connections 2` |
| No-storage ceiling | `--features dalek_batch` | add `--storage-enabled false` | same connection count |
| Buffered storage | `--features dalek_batch` | `--storage-enabled true --storage-flush-records 256 --storage-flush-ms 10 --storage-sync-data false` | same connection count |
| Durable storage | `--features dalek_batch` | `--storage-enabled true --storage-flush-records 256 --storage-flush-ms 10 --storage-sync-data true` | same connection count |

`storage_sync_data=false` measures buffered pilot storage and is not a durable
production setting. The durable result must use `storage_sync_data=true`.

Use identical packet counts, payload size, connection count, QUIC buffer, and
queue-capacity settings when comparing two cases. Keep `--queue-capacity` fixed
across packet counts so memory use and saturation remain comparable. Keep
`--replay-capacity` above the number of unique nonces sent in one benchmark
slot. A run is
incomplete if sender and receiver artifacts disagree about the commit or
feature set.

## 8. Result Interpretation

- `accepted_packets` is successful ingress enqueue, not completed execution.
- `deduplicated_packets`, `verified_packets`, and `banked_transactions` are
  separate pipeline-stage counts.
- `durable_transactions` is transaction completion acknowledged by storage.
- `completed_transactions` includes the no-storage ceiling; in that mode
  `durable_transactions` must remain zero.
- `stored_records` counts shreds and must not be compared directly to packet
  count.
- `stage_rates` use first-packet-to-durable-completion time.
- `receive_duration_secs` measures only the network receive interval.
- `drop_reasons` and `queue_high_water` identify the first saturated stage.
- `network_deltas` records Linux UDP receive errors, receive-buffer errors, and
  interface drops observed during the run.
- `cpu_percent` is Linux process CPU consumed during the measured send or
  first-packet-to-durable-completion interval; packet corpus preparation and
  receiver startup wait are excluded.
- Sender `drops` includes QUIC datagrams accepted by the sender API but not
  observed by the receiver completion protocol.

VirtualBox results are development evidence. The 100k/200k production-scale
claim requires separate Linux hosts with dedicated CPU, NVMe, and a real NIC.

## 9. Multiple Authenticated Peers

For a real multi-peer case, generate a different client transport key and SPKI
for every simulated peer. Repeat `--client-spki` on the receiver and
`--client-key` on the sender in matching order:

```text
# receiver
--client-spki bench-keys/sender-0.spki \
--client-spki bench-keys/sender-1.spki \
--connections 2

# sender
--client-key bench-keys/sender-0.key \
--client-key bench-keys/sender-1.key \
--connections 2
```

The server constructs a distinct validator identity for every configured SPKI,
and every client key creates a separate QUIC endpoint. Supplying one key with
multiple connections remains useful for connection scaling, but it is not a
multi-peer identity test.

These options prove distinct TLS transport identities. Benchmark packets still
use the synthetic packet-signing key built into this tool, so this is not a
validator-set packet-key conformance test.

## 10. Recorded Local Evidence

See [performance-evidence.md](performance-evidence.md) for the
exact-commit Windows loopback engineering result and its explicit limitations.
