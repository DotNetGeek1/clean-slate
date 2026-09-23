#!/bin/bash
# Build frozen BusyBox and refresh committed metadata (not the binary if >1.5 MiB).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
TAG="m9-busybox-frozen:local"
IMAGE_DIGEST="alpine@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507"

docker build -f Dockerfile -t "$TAG" .
CID="$(docker create "$TAG")"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT
docker cp "$CID:/export/." "$ROOT/"
docker cp "$CID:/busybox" "$ROOT/busybox"
docker cp "$CID:/export/.config" "$ROOT/.config"
docker rm -f "$CID" >/dev/null

{
  echo "dockerfile=$ROOT/Dockerfile"
  echo "build_image=$IMAGE_DIGEST"
  echo "busybox_tarball=busybox-1.37.0.tar.bz2"
  echo "busybox_tarball_sha256=3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4"
  echo "busybox_version=1.37.0"
  echo "musl=1.2.5-r11 (Alpine 3.21 build-base)"
  echo "CC=gcc CONFIG_STATIC=y CONFIG_PIE=n"
} > "$ROOT/toolchain.txt"

cp "$ROOT/busybox.sha256" "$ROOT/sha256" 2>/dev/null || sha256sum "$ROOT/busybox" | awk '{print $1}' > "$ROOT/busybox.sha256"
echo "frozen SHA-256: $(cat "$ROOT/busybox.sha256") size=$(cat "$ROOT/size_bytes.txt")"
