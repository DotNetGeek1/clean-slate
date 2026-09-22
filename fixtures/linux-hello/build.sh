#!/usr/bin/env bash
# Deterministic rebuild of hello-linux-x86_64 for M8 acceptance (#96).
#
# Pinned toolchain identity is recorded in README.md. Rebuild inside WSL/Linux
# with GNU binutils (as/ld) matching that identity for bit-identical output.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

OUT="hello-linux-x86_64"
OBJ="hello.o"

rm -f "$OBJ" "$OUT" "${OUT}.tmp"

# Fixed flags: static freestanding non-PIE, no build-id, no timestamps in notes.
as --64 -o "$OBJ" hello.S
ld \
  -m elf_x86_64 \
  -static \
  -nostdlib \
  -no-pie \
  --build-id=none \
  --hash-style=sysv \
  -z norelro \
  -T hello.ld \
  -o "${OUT}.tmp" \
  "$OBJ"

# Drop any residual comment/note sections that survived /DISCARD/.
objcopy \
  --remove-section=.comment \
  --remove-section=.note \
  --remove-section=.note.gnu.property \
  --remove-section=.note.GNU-stack \
  "${OUT}.tmp" "$OUT"

rm -f "$OBJ" "${OUT}.tmp"

sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
readelf -h -l -S "$OUT" > readelf.txt

echo "Built $OUT"
echo "SHA-256: $(cat "${OUT}.sha256")"
