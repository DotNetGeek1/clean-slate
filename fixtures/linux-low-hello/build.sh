#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"
OUT="hello-linux-low-x86_64"
OBJ="hello.o"
rm -f "$OBJ" "$OUT" "${OUT}.tmp"
as --64 -o "$OBJ" hello.S
ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T hello.ld -o "${OUT}.tmp" "$OBJ"
objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack "${OUT}.tmp" "$OUT"
rm -f "$OBJ" "${OUT}.tmp"
sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"
readelf -h -l -S "$OUT" > readelf.txt
echo "Built $OUT"
