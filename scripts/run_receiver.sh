#!/usr/bin/env bash
set -euo pipefail

WORKERS="${WORKERS:-${1:-4}}"
VERIFY="${VERIFY:-${2:-on}}"
DEDUPE="${DEDUPE:-${3:-on}}"
OUT_CSV="${OUT_CSV:-${4:-receiver.csv}}"

FEATURE_ARGS=()
if [[ "$VERIFY" == "on" ]]; then
  FEATURE_ARGS=(--features ed25519)
fi

CMD=(
  cargo run --release "${FEATURE_ARGS[@]}" --bin fast_rx --
  --bind 0.0.0.0:9000
  --workers "$WORKERS"
  --verify "$VERIFY"
  --dedupe "$DEDUPE"
  --out-csv "$OUT_CSV"
)

echo "Running receiver: ${CMD[*]}"
"${CMD[@]}"
