#!/bin/sh
# M9 Phase A — Alpine busybox-static candidate (run on Linux or: docker run ... sh build-inner.sh)
set -eu
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
OUT="$ROOT"
IMAGE="${BUILD_IMAGE:-alpine:3.21}"

apk add --no-cache busybox-static binutils file coreutils >/dev/null 2>&1 || true

cp /bin/busybox "$OUT/busybox"
/bin/busybox | head -1 > "$OUT/version.txt"
/bin/busybox --list > "$OUT/applets.txt"
readelf -h -l -S "$OUT/busybox" > "$OUT/readelf.txt"
sha256sum "$OUT/busybox" | awk '{print $1}' > "$OUT/sha256"
wc -c "$OUT/busybox" | awk '{print $1}' > "$OUT/size_bytes.txt"
file "$OUT/busybox" > "$OUT/file.txt"

{
  echo "image=$IMAGE"
  echo "package=busybox-static"
  head -1 "$OUT/version.txt"
  echo "libc=musl (Alpine bundled)"
  apk info busybox-static 2>/dev/null || true
  apk info musl 2>/dev/null | head -5 || true
} > "$OUT/toolchain.txt"

cat > "$OUT/README.config.txt" <<'EOF'
Alpine ships busybox-static as a prebuilt package; no .config is installed on target.
Pin: apk package version from toolchain.txt and reproduce with the same Alpine release + busybox-static package.
EOF

echo "SHA-256: $(cat "$OUT/sha256")"
