#!/bin/sh
# Host wrapper: extract Alpine busybox-static via Docker (Windows/Linux).
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
IMAGE="${BUILD_IMAGE:-alpine:3.21}"
docker pull "$IMAGE" >/dev/null
DIGEST="$(docker inspect --format='{{index .RepoDigests 0}}' "$IMAGE" 2>/dev/null || echo unknown)"
docker run --rm -v "$ROOT:/out" -w /out "$IMAGE" sh /out/build-inner.sh
{
  echo "image_digest=$DIGEST"
} >> "$ROOT/toolchain.txt"
echo "Done: $ROOT"
