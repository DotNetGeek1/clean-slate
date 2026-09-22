#!/usr/bin/env bash
# Reproducible malformed ELF byte fixtures for #92 host tests (M8.6 / #96).
# Usage: ./generate.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

le16() { printf '%02x%02x' $(($1 & 255)) $((($1 >> 8) & 255)); }
le32() {
  printf '%02x%02x%02x%02x' \
    $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255))
}
le64() {
  printf '%02x%02x%02x%02x%02x%02x%02x%02x' \
    $(($1 & 255)) $((($1 >> 8) & 255)) $((($1 >> 16) & 255)) $((($1 >> 24) & 255)) \
    $((($1 >> 32) & 255)) $((($1 >> 40) & 255)) $((($1 >> 48) & 255)) $((($1 >> 56) & 255))
}
hx() { echo -n "$1" | xxd -r -p; }

# ELF64 LE header fields + N program headers encoded as hex pairs.
# Args after fixed header knobs are raw 56-byte phdr hex blobs.
write_elf() {
  local out=$1
  local ei_class=$2
  local ei_data=$3
  local e_type=$4
  local e_machine=$5
  local e_phentsize=$6
  local e_phnum=$7
  shift 7
  local hdr
  hdr="7f454c46"
  hdr+="$(printf '%02x' "$ei_class")"
  hdr+="$(printf '%02x' "$ei_data")"
  hdr+="01000000000000000000"
  hdr+="$(le16 "$e_type")"
  hdr+="$(le16 "$e_machine")"
  hdr+="$(le32 1)"
  hdr+="$(le64 0x400078)"   # e_entry
  hdr+="$(le64 64)"         # e_phoff
  hdr+="$(le64 0)"          # e_shoff
  hdr+="$(le32 0)"          # e_flags
  hdr+="$(le16 64)"         # e_ehsize
  hdr+="$(le16 "$e_phentsize")"
  hdr+="$(le16 "$e_phnum")"
  hdr+="$(le16 0)$(le16 0)$(le16 0)"
  local body="$hdr"
  local ph
  for ph in "$@"; do
    body+="$ph"
  done
  hx "$body" > "$out"
}

phdr_load() {
  # type=1 PT_LOAD, flags, offset, vaddr, filesz, memsz, align
  local flags=$1 offset=$2 vaddr=$3 filesz=$4 memsz=$5 align=$6
  echo -n "$(le32 1)$(le32 "$flags")$(le64 "$offset")$(le64 "$vaddr")$(le64 "$vaddr")"
  echo -n "$(le64 "$filesz")$(le64 "$memsz")$(le64 "$align")"
}

phdr_interp() {
  local offset=$1 filesz=$2
  echo -n "$(le32 3)$(le32 4)$(le64 "$offset")$(le64 0)$(le64 0)"
  echo -n "$(le64 "$filesz")$(le64 "$filesz")$(le64 1)"
}

pad_to() {
  local file=$1 size=$2
  local cur
  cur=$(wc -c < "$file" | tr -d ' ')
  if [ "$cur" -lt "$size" ]; then
    dd if=/dev/zero bs=1 count=$((size - cur)) >> "$file" 2>/dev/null
  fi
}

LOAD_OK="$(phdr_load 5 0 0x400000 120 120 4096)"

# bad-magic
write_elf bad-magic.elf 2 1 2 62 56 1 "$LOAD_OK"
printf '\x00' | dd of=bad-magic.elf bs=1 seek=0 count=1 conv=notrunc 2>/dev/null
pad_to bad-magic.elf 200

# elfclass32
write_elf elfclass32.elf 1 1 2 62 56 1 "$LOAD_OK"
pad_to elfclass32.elf 200

# big-endian (EI_DATA = ELFDATA2MSB)
write_elf big-endian.elf 2 2 2 62 56 1 "$LOAD_OK"
pad_to big-endian.elf 200

# em-aarch64 (183)
write_elf em-aarch64.elf 2 1 2 183 56 1 "$LOAD_OK"
pad_to em-aarch64.elf 200

# et-dyn (3)
write_elf et-dyn.elf 2 1 3 62 56 1 "$LOAD_OK"
pad_to et-dyn.elf 200

# truncated-phdr-table: e_phnum=2 but file stops after first phdr (120 bytes)
write_elf truncated-phdr-table.elf 2 1 2 62 56 2 "$LOAD_OK" "$LOAD_OK"
truncate -s 120 truncated-phdr-table.elf

# filesz-gt-memsz
LOAD_BAD_FSZ="$(phdr_load 5 0 0x400000 200 100 4096)"
write_elf filesz-gt-memsz.elf 2 1 2 62 56 1 "$LOAD_BAD_FSZ"
pad_to filesz-gt-memsz.elf 200

# overlapping-pt-load
LOAD_A="$(phdr_load 5 0 0x400000 0x1000 0x1000 4096)"
LOAD_B="$(phdr_load 5 0 0x400800 0x1000 0x1000 4096)"
write_elf overlapping-pt-load.elf 2 1 2 62 56 2 "$LOAD_A" "$LOAD_B"
pad_to overlapping-pt-load.elf 200

# has-pt-interp
INTERP="$(phdr_interp 176 7)"
LOAD_C="$(phdr_load 5 0 0x400000 200 200 4096)"
write_elf has-pt-interp.elf 2 1 2 62 56 2 "$INTERP" "$LOAD_C"
pad_to has-pt-interp.elf 176
printf '/lib64\0' >> has-pt-interp.elf
pad_to has-pt-interp.elf 200

# vaddr-kernel-range
LOAD_K="$(phdr_load 5 0 0xffff800000000000 0x1000 0x1000 4096)"
write_elf vaddr-kernel-range.elf 2 1 2 62 56 1 "$LOAD_K"
pad_to vaddr-kernel-range.elf 200

# vaddr-page-zero
LOAD_Z="$(phdr_load 5 0 0 0x1000 0x1000 4096)"
write_elf vaddr-page-zero.elf 2 1 2 62 56 1 "$LOAD_Z"
pad_to vaddr-page-zero.elf 200

# phentsize-wrong (48 instead of 56)
write_elf phentsize-wrong.elf 2 1 2 62 48 1 "$LOAD_OK"
pad_to phentsize-wrong.elf 200

# offset-beyond-eof: p_offset=0x1000, filesz=0x100, file only 200 bytes
LOAD_EOF="$(phdr_load 5 0x1000 0x400000 0x100 0x100 4096)"
write_elf offset-beyond-eof.elf 2 1 2 62 56 1 "$LOAD_EOF"
pad_to offset-beyond-eof.elf 200

echo "Generated:"
ls -1 *.elf
