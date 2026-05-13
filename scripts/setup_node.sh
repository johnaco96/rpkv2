#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

UBUNTU_VERSION="$(. /etc/os-release && echo "${VERSION_ID:-unknown}")"
case "$UBUNTU_VERSION" in
  "22.04"|"24.04")
    ;;
  *)
    echo "Warning: this script is tuned for Ubuntu 22.04/24.04 (detected: $UBUNTU_VERSION)." >&2
    ;;
esac

$SUDO apt-get update
$SUDO apt-get install -y curl git build-essential pkg-config clang ca-certificates

if ! command -v rustup >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi

export PATH="$HOME/.cargo/bin:$PATH"
rustup toolchain install stable --profile minimal
rustup default stable

echo "rustc version: $(rustc --version)"
echo "cargo version: $(cargo --version)"
