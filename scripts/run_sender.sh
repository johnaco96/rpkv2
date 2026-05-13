#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 && -z "${RECEIVER_IP:-}" ]]; then
  echo "Usage: RECEIVER_IP=<public_ip> $0 [pps] [payload] [duration] [signing] [out_csv]" >&2
  echo "   or: $0 <public_ip> [pps] [payload] [duration] [signing] [out_csv]" >&2
  exit 1
fi

if [[ -n "${RECEIVER_IP:-}" ]]; then
  RECEIVER="$RECEIVER_IP"
  shift_count=0
else
  RECEIVER="$1"
  shift_count=1
fi

args=("$@")
if (( shift_count == 1 )); then
  args=("${args[@]:1}")
fi

arg_or_default() {
  local index="$1"
  local default="$2"
  if (( index < ${#args[@]} )); then
    echo "${args[$index]}"
  else
    echo "$default"
  fi
}

PPS="${PPS:-$(arg_or_default 0 100000)}"
PAYLOAD="${PAYLOAD:-$(arg_or_default 1 256)}"
DURATION="${DURATION:-$(arg_or_default 2 30)}"
SIGNING="${SIGNING:-$(arg_or_default 3 on)}"
OUT_CSV="${OUT_CSV:-$(arg_or_default 4 sender.csv)}"

FEATURE_ARGS=()
if [[ "$SIGNING" == "on" ]]; then
  FEATURE_ARGS=(--features ed25519)
fi

CMD=(
  cargo run --release "${FEATURE_ARGS[@]}" --bin fast_tx --
  --target "${RECEIVER}:9000"
  --pps "$PPS"
  --payload "$PAYLOAD"
  --duration "$DURATION"
  --signing "$SIGNING"
  --out-csv "$OUT_CSV"
)

echo "Running sender: ${CMD[*]}"
"${CMD[@]}"
