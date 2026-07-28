#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/benchmark_common.sh
source "$ROOT/scripts/benchmark_common.sh"
CONFIG="${CONFIG:-$ROOT/configs/benchmark/receiver.env}"
load_config "$CONFIG"

WORKERS="${WORKERS:-1}"
VERIFY="${VERIFY:-on}"
DEDUPE="${DEDUPE:-on}"
OUT_CSV="${OUT_CSV:-receiver.csv}"
IDLE_TIMEOUT_SECS="${IDLE_TIMEOUT_SECS:-2}"
if [[ $# -ge 1 ]]; then WORKERS="$1"; fi
if [[ $# -ge 2 ]]; then VERIFY="$2"; fi
if [[ $# -ge 3 ]]; then DEDUPE="$3"; fi
if [[ $# -ge 4 ]]; then OUT_CSV="$4"; fi
if [[ $# -ge 5 ]]; then IDLE_TIMEOUT_SECS="$5"; fi
BIND_ADDR="${BIND_ADDR:-0.0.0.0:9000}"
FEATURES="${FEATURES:-ed25519}"
OUT_DIR="${OUT_DIR:-benchmarks/results/two-node}"
OUT_META="${OUT_META:-receiver.meta.json}"
mkdir -p "$OUT_DIR"
OUT_CSV_PATH="$OUT_DIR/$OUT_CSV"
OUT_META_PATH="$OUT_DIR/$OUT_META"

CMD=(
  cargo run --release --features "$FEATURES" --bin fast_rx --
  --bind "$BIND_ADDR"
  --workers "$WORKERS"
  --verify "$VERIFY"
  --dedupe "$DEDUPE"
  --idle-timeout-secs "$IDLE_TIMEOUT_SECS"
  --out-csv "$OUT_CSV_PATH"
)

echo "Running receiver: ${CMD[*]}"
"${CMD[@]}"
write_metadata_json \
  receiver \
  "$OUT_META_PATH" \
  "$CONFIG" \
  "$IDLE_TIMEOUT_SECS idle-after-traffic" \
  "see_receiver_csv" \
  "see_sender_csv" \
  "see_receiver_csv" \
  "see_receiver_csv" \
  "see_receiver_csv" \
  "$FEATURES"
echo "Wrote receiver metadata: $OUT_META_PATH"
