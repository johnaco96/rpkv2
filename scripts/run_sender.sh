#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/benchmark_common.sh
source "$ROOT/scripts/benchmark_common.sh"
CONFIG="${CONFIG:-$ROOT/configs/benchmark/sender.env}"
load_config "$CONFIG"

if [[ $# -lt 1 && -z "${RECEIVER_IP:-}" ]]; then
  echo "Usage: RECEIVER_IP=<public_ip> $0 [pps] [payload] [duration] [signing] [out_csv]" >&2
  echo "   or: $0 <public_ip> [pps] [payload] [duration] [signing] [out_csv]" >&2
  exit 1
fi

if [[ $# -ge 1 ]]; then
  RECEIVER="$1"
  args=("${@:2}")
else
  RECEIVER="$RECEIVER_IP"
  args=("$@")
fi

PPS="${PPS:-100000}"
PAYLOAD="${PAYLOAD:-256}"
DURATION="${DURATION:-30}"
SIGNING="${SIGNING:-on}"
OUT_CSV="${OUT_CSV:-sender.csv}"
if (( ${#args[@]} > 0 )); then PPS="${args[0]}"; fi
if (( ${#args[@]} > 1 )); then PAYLOAD="${args[1]}"; fi
if (( ${#args[@]} > 2 )); then DURATION="${args[2]}"; fi
if (( ${#args[@]} > 3 )); then SIGNING="${args[3]}"; fi
if (( ${#args[@]} > 4 )); then OUT_CSV="${args[4]}"; fi
RECEIVER_PORT="${RECEIVER_PORT:-9000}"
FEATURES="${FEATURES:-ed25519}"
OUT_DIR="${OUT_DIR:-benchmarks/results/two-node}"
OUT_META="${OUT_META:-sender.meta.json}"
mkdir -p "$OUT_DIR"
OUT_CSV_PATH="$OUT_DIR/$OUT_CSV"
OUT_META_PATH="$OUT_DIR/$OUT_META"

CMD=(
  cargo run --release --features "$FEATURES" --bin fast_tx --
  --target "${RECEIVER}:${RECEIVER_PORT}"
  --pps "$PPS"
  --payload "$PAYLOAD"
  --duration-secs "$DURATION"
  --signing "$SIGNING"
  --out-csv "$OUT_CSV_PATH"
)

echo "Running sender: ${CMD[*]}"
"${CMD[@]}"
write_metadata_json \
  sender \
  "$OUT_META_PATH" \
  "$CONFIG" \
  "$DURATION" \
  "$PAYLOAD" \
  "$PPS" \
  "see_sender_csv" \
  "see_receiver_csv" \
  "see_receiver_csv" \
  "$FEATURES"
echo "Wrote sender metadata: $OUT_META_PATH"
