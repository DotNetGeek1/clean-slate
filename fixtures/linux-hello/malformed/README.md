# Malformed ELF fixtures for #92

Hand-built negative cases used by Linux ELF loader host tests. They are **not**
meant to execute. Regenerate with `./generate.sh` (bash + `xxd` + `dd`) for
byte-identical output. Good-shaped loads use the same image base as the
committed fixture (`0x0000400000400000`); `vaddr-page-zero` and
`vaddr-kernel-range` remain deliberately outside that window.

| File | What is wrong |
|------|----------------|
| `bad-magic.elf` | First magic byte cleared (`0x7f` → `0x00`) |
| `elfclass32.elf` | `EI_CLASS = ELFCLASS32` |
| `big-endian.elf` | `EI_DATA = ELFDATA2MSB` |
| `em-aarch64.elf` | `e_machine = EM_AARCH64` (183) |
| `et-dyn.elf` | `e_type = ET_DYN` |
| `truncated-phdr-table.elf` | `e_phnum = 2` but file truncated before second phdr |
| `filesz-gt-memsz.elf` | `PT_LOAD` with `p_filesz > p_memsz` |
| `overlapping-pt-load.elf` | Two `PT_LOAD` segments with overlapping VA ranges |
| `has-pt-interp.elf` | Contains `PT_INTERP` plus a `PT_LOAD` |
| `vaddr-kernel-range.elf` | `p_vaddr` in high canonical / kernel window |
| `vaddr-page-zero.elf` | `p_vaddr = 0` (page zero) |
| `phentsize-wrong.elf` | `e_phentsize = 48` instead of 56 |
| `offset-beyond-eof.elf` | `p_offset + p_filesz` past end of file |

Rebuild:

```bash
cd fixtures/linux-hello/malformed
chmod +x generate.sh
./generate.sh
```
