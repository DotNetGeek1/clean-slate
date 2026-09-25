#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq qemu-system-x86 ovmf curl ca-certificates build-essential
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.89.0
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-uefi
export RUSTFLAGS="-D warnings"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/target}"
export OVMF_CODE="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
export REPORT_PATH="${REPORT_PATH:-/tmp/docker-exhaustive.txt}"
cd /work
bash scripts/run-tests.sh --exhaustive
tail -5 "$REPORT_PATH"
