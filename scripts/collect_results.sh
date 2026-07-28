#!/usr/bin/env bash
set -euo pipefail

OUT_ARCHIVE="${1:-benchmark-results-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}"

mapfile -t FILES < <(find . -type f \( -name '*.csv' -o -name '*.json' -o -name '*.log' \) \
  -not -path './.git/*' \
  -not -path './target/*')

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "No CSV, JSON, or log files found to archive." >&2
  exit 1
fi

tar -czf "$OUT_ARCHIVE" "${FILES[@]}"
echo "Created archive: $OUT_ARCHIVE"
