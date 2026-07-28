#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${CONFIG:-$ROOT/configs/benchmark/receiver.env}"
# shellcheck disable=SC1090
source "$CONFIG"

bash "$ROOT/scripts/setup_node.sh"
cargo build --release --features "${FEATURES:-ed25519}" --bin fast_rx --bin bench_summary

echo "receiver setup complete"
echo "config: $CONFIG"
