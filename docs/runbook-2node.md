# Two-node signed UDP benchmark runbook

This runbook covers a **two-node signed UDP validator-ingress benchmark** using `fast_rx` (receiver) and `fast_tx` (sender) on two public cloud Ubuntu nodes.

> This setup is for benchmark experimentation only. Do **not** treat results as production validator performance.

## 1) Provision nodes

Create two Ubuntu VMs (22.04 or 24.04):

- **Receiver node**: public IP, at least 2 vCPU.
- **Sender node**: public IP, at least 2 vCPU.

Recommended baseline:

- Same cloud region/zone for initial tests.
- Disable burst-only instance classes for stable PPS.
- Attach enough disk for build artifacts and logs.

## 2) Security group / firewall rules

Open only required inbound ports:

- Receiver node:
  - UDP `9000` from sender node public IP (benchmark traffic)
  - TCP `22` from your admin IP (SSH)
- Sender node:
  - TCP `22` from your admin IP (SSH)

You do not need public inbound UDP on sender for this flow.

## 3) Node setup

The repository is private. Before cloning on each node, ensure the node has GitHub access via either:

- an SSH key registered to a GitHub account with repo access, or
- authenticated GitHub CLI (`gh auth login`) for a user with repo access.

On both nodes:

```bash
git clone git@github.com:johnaco96/rpkv2.git
cd rpkv2
git checkout benchmark-2node-signed
bash scripts/setup_node.sh
```

## 4) First-run benchmark config (recommended)

Start with this signed baseline on both nodes:

- `PPS=50000`
- `PAYLOAD=256`
- `DURATION=60`
- `SIGNING=on`
- `VERIFY=on`
- `DEDUPE=on`

## 5) Start receiver

On receiver node:

```bash
cd ~/rpkv2
WORKERS=4 VERIFY=on DEDUPE=on OUT_CSV=receiver.csv bash scripts/run_receiver.sh
```

Equivalent positional args form:

```bash
bash scripts/run_receiver.sh 4 on on receiver.csv
```

This binds to `0.0.0.0:9000` and enables `ed25519` feature when verify is on.

## 6) Start sender

On sender node, replace `<RECEIVER_PUBLIC_IP>`:

```bash
cd ~/rpkv2
RECEIVER_IP=<RECEIVER_PUBLIC_IP> PPS=50000 PAYLOAD=256 DURATION=60 SIGNING=on OUT_CSV=sender.csv bash scripts/run_sender.sh
```

Equivalent positional args form:

```bash
bash scripts/run_sender.sh <RECEIVER_PUBLIC_IP> 50000 256 60 on sender.csv
```

This enables `ed25519` feature when signing is on.

## 7) Ramp plan

Increase load in steps and collect results at each stage:

1. `50k` PPS
2. `100k` PPS
3. `200k` PPS
4. `400k` PPS

Stop increasing PPS when any of the following occurs:

- packet loss rises,
- CPU saturates,
- latency spikes badly, or
- bandwidth limits are hit.

## 8) Collect results

On each node:

```bash
cd ~/rpkv2
bash scripts/collect_results.sh
```

Optional named archive:

```bash
bash scripts/collect_results.sh node1-results.tar.gz
```

The archive includes `*.csv` and `*.log` files recursively (excluding `.git/` and `target/`).

## 9) Troubleshooting

- **Receiver not getting traffic**:
  - Re-check receiver UDP 9000 firewall rule.
  - Verify sender is targeting the receiver public IP.
- **Build errors**:
  - Re-run `bash scripts/setup_node.sh`.
  - Ensure `rustc` and `cargo` were printed at end of setup.
- **Low throughput**:
  - Confirm both nodes are in the same region.
  - Increase vCPU and tune `WORKERS`.
- **Feature mismatch**:
  - Keep `VERIFY=on` and `SIGNING=on` for signed path benchmarks.

## 10) Artifact hygiene

Do **not** commit generated CSV/log outputs or compressed archives to git.
