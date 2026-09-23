#!/bin/bash
# Build musl-minimal BusyBox via Dockerfile; copies artifacts to this directory.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
IMAGE="${BUILD_IMAGE:-alpine:3.21}"
TAG="m9-busybox-musl-minimal:local"

docker build -f Dockerfile -t "$TAG" --build-arg BUSYBOX_VERSION=1.37.0 .
CID="$(docker create "$TAG")"
trap 'docker rm -f "$CID" >/dev/null 2>&1 || true' EXIT
docker cp "$CID:/export/." "$ROOT/"
docker cp "$CID:/export/.config" "$ROOT/.config" 2>/dev/null || docker cp "$CID:/export/.config" "$ROOT/.config"
docker rm -f "$CID" >/dev/null

{
  echo "dockerfile=$ROOT/Dockerfile"
  echo "build_image=$IMAGE"
  docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || true
  echo "busybox_version=1.37.0"
  echo "CC=musl-gcc CONFIG_STATIC=y"
} > "$ROOT/toolchain.txt"

echo "musl-minimal SHA-256: $(cat "$ROOT/sha256")"
