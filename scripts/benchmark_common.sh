#!/usr/bin/env bash
set -euo pipefail

repo_root() {
  git rev-parse --show-toplevel 2>/dev/null || pwd
}

load_config() {
  local config_path="$1"
  if [[ ! -f "$config_path" ]]; then
    echo "Config file not found: $config_path" >&2
    exit 1
  fi
  # shellcheck disable=SC1090
  set -a
  source "$config_path"
  set +a
}

json_escape() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/}"
  printf '%s' "$value"
}

first_interface() {
  if command -v ip >/dev/null 2>&1; then
    ip route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}'
  elif command -v route >/dev/null 2>&1; then
    route print 0.0.0.0 2>/dev/null | awk 'NF >= 5 && $1 == "0.0.0.0" {print $4; exit}'
  fi
}

hardware_summary() {
  if command -v lscpu >/dev/null 2>&1; then
    lscpu | tr '\n' ';'
  else
    printf 'cpu_count=%s' "$(nproc 2>/dev/null || echo unknown)"
  fi
}

memory_summary() {
  if command -v free >/dev/null 2>&1; then
    free -h | tr '\n' ';'
  else
    printf 'unknown'
  fi
}

os_summary() {
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    printf '%s %s' "${NAME:-unknown}" "${VERSION_ID:-unknown}"
  else
    uname -a
  fi
}

write_metadata_json() {
  local role="$1"
  local output="$2"
  local config_path="$3"
  local duration="$4"
  local packet_size="$5"
  local offered_load="$6"
  local accepted_load="$7"
  local drops="$8"
  local latency="$9"
  local features="${10}"
  local network_interface="${NETWORK_INTERFACE:-$(first_interface)}"
  local commit
  local branch
  local rust_version
  local cargo_version

  commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
  branch="$(git rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)"
  rust_version="$(rustc --version 2>/dev/null || echo unknown)"
  cargo_version="$(cargo --version 2>/dev/null || echo unknown)"

  cat > "$output" <<JSON
{
  "schema": "rpkv2.two_node_benchmark_metadata.v1",
  "role": "$(json_escape "$role")",
  "captured_at_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "git_commit": "$(json_escape "$commit")",
  "git_branch": "$(json_escape "$branch")",
  "features": "$(json_escape "$features")",
  "config_path": "$(json_escape "$config_path")",
  "os": "$(json_escape "$(os_summary)")",
  "kernel": "$(json_escape "$(uname -a)")",
  "hardware": "$(json_escape "$(hardware_summary)")",
  "memory": "$(json_escape "$(memory_summary)")",
  "rust_version": "$(json_escape "$rust_version")",
  "cargo_version": "$(json_escape "$cargo_version")",
  "network_interface": "$(json_escape "${network_interface:-unknown}")",
  "test_duration_secs": "$(json_escape "$duration")",
  "packet_size_bytes": "$(json_escape "$packet_size")",
  "offered_load_pps": "$(json_escape "$offered_load")",
  "accepted_load_pps": "$(json_escape "$accepted_load")",
  "drops": "$(json_escape "$drops")",
  "latency": "$(json_escape "$latency")"
}
JSON
}
