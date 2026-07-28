# Two-Node Signed UDP Benchmark Runbook

This runbook covers the signed UDP fast-path benchmark using `fast_rx` on a
receiver node and `fast_tx` on a sender node.

The benchmark is for synthetic performance experiments only. Do not treat the
results as production validator performance.

## 1. Security Preflight

Before provisioning or cloning:

- Review `docs/public-benchmark-security.md`.
- Use disposable cloud nodes.
- Restrict firewalls before first SSH login.
- Do not copy wallet keys, validator keys, `.env` files, or cloud credentials
  to benchmark nodes.

## 2. Provision Nodes

Create two Ubuntu 22.04 or 24.04 VMs:

- Receiver node: public IP, at least 2 vCPU.
- Sender node: public IP, at least 2 vCPU.

Use the same region or zone for the first run.

## 3. Firewall Rules

Receiver node inbound:

- TCP `22` from your admin IP.
- UDP `9000` from the sender public IP.

Sender node inbound:

- TCP `22` from your admin IP.

## 4. Repository Setup

On both nodes:

```bash
git clone git@github.com:johnaco96/rpkv2.git
cd rpkv2
```

Use temporary repository access and revoke it after testing.

On the receiver node:

```bash
bash scripts/setup_receiver.sh
```

On the sender node:

```bash
bash scripts/setup_sender.sh
```

The fixed configs are:

- `configs/benchmark/receiver.env`
- `configs/benchmark/sender.env`

Use `CONFIG=/path/to/custom.env` only when recording a deliberate variant.

## 5. Start Receiver

On the receiver node:

```bash
cd ~/rpkv2
bash scripts/run_receiver.sh
```

Equivalent positional form:

```bash
bash scripts/run_receiver.sh 1 on on receiver.csv
```

The receiver exits after receiving packets and then observing the configured
idle timeout.

## 6. Start Sender

On the sender node, replace `<RECEIVER_PUBLIC_IP>`:

```bash
cd ~/rpkv2
RECEIVER_IP=<RECEIVER_PUBLIC_IP> bash scripts/run_sender.sh
```

Equivalent positional form:

```bash
bash scripts/run_sender.sh <RECEIVER_PUBLIC_IP> 50000 256 60 on sender.csv
```

The scripts write:

- `benchmarks/results/two-node/sender.csv`
- `benchmarks/results/two-node/sender.meta.json`
- `benchmarks/results/two-node/receiver.csv`
- `benchmarks/results/two-node/receiver.meta.json`

## 7. Build Summary JSON

After copying the sender files onto the receiver node, or after collecting both
outputs onto one workstation:

```bash
cargo run --bin bench_summary -- \
  --tx benchmarks/results/two-node/sender.csv \
  --rx benchmarks/results/two-node/receiver.csv \
  --sender-meta benchmarks/results/two-node/sender.meta.json \
  --receiver-meta benchmarks/results/two-node/receiver.meta.json \
  --payload 256 \
  --out benchmarks/results/two-node/summary.json
```

The summary JSON embeds sender and receiver metadata so future comparisons can
check hardware, OS, Rust version, git commit, features, interface, duration,
packet size, offered load, accepted load, drops, and latency.

## 8. Ramp Plan

Start low and increase only while packet loss, CPU, and latency remain
acceptable:

1. `50k` PPS
2. `100k` PPS
3. `200k` PPS
4. `400k` PPS

Stop increasing when loss rises, CPU saturates, latency spikes, or bandwidth
limits are reached.

## 9. Collect Results

On each node:

```bash
bash scripts/collect_results.sh
```

Optional named archive:

```bash
bash scripts/collect_results.sh node-results.tar.gz
```

The archive includes CSV, JSON, and log files while excluding `.git/` and
`target/`.

## 10. Troubleshooting

- Receiver gets no packets: re-check UDP `9000` firewall rule and sender target
  IP.
- Build errors: rerun `bash scripts/setup_node.sh` and verify `rustc --version`
  and `cargo --version`.
- Signature failures: keep `SIGNING=on` on sender and `VERIFY=on` on receiver.
- High loss: reduce PPS, keep nodes in the same region, and confirm instance
  bandwidth limits.

Do not commit generated CSV, JSON, log, or archive files.
