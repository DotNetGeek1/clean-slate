# Linux hello fixture (M8.6 / #96)

Deterministic unmodified Linux x86-64 `ET_EXEC` ELF used for M8 acceptance.
**Fixture bytes are frozen after the follow-up push that relocates the image
into the Clean-Slate user VA window** — do not relink or patch them to paper
over loader bugs (#92/#97 inject the artifact unchanged).

## Why this link address

Clean-Slate identity-maps physical memory at virtual 0 and gives each process
exactly one private PML4 slot:

```text
0x0000_4000_0000_0000 .. 0x0000_4080_0000_0000
```

A classic Linux `ET_EXEC` at `0x400000` would alias the shared identity map and
cannot be mapped in M8. This fixture is therefore linked at

```text
0x0000_4000_0040_0000   (= window base + classic 4 MiB offset)
```

That is still a normal Linux user address (far below `TASK_SIZE`), so the same
source + ordinary linker script runs **unchanged** on real Linux. This is a
link-address choice, not a Clean-Slate-specific binary patch. Supporting
low/`0x400000` user mappings is M9+ kernel work (higher-half kernel).

The first `PT_LOAD` starts at file offset 0 / `p_vaddr = 0x0000400000400000`
and covers the ELF header + program headers (`FILEHDR`/`PHDRS` in `hello.ld`)
so `#92` can set `AT_PHDR` to a real mapped user address.

## Behaviour (exact order)

1. `syscall` nr **999** with zeroed args. Expect `rax == -38` (`-ENOSYS`). If not,
   `exit(1)` via syscall 60.
2. `write(1, "Hello from Linux.\n", 18)` via syscall **1**.
3. `exit(0)` via syscall **60**.

Nothing else: no `brk`, `arch_prctl`, TLS setup, `rt_sigaction`, `exit_group`,
or `set_tid_address`. The program does not read the initial stack. String
addressing is RIP-relative (`lea rsi, [rip + msg]`).

## Files

| Path | Role |
|------|------|
| `hello.S` | Freestanding `_start` (GNU as) |
| `hello.ld` | Single RX `PT_LOAD` at `0x0000400000400000` (headers included) |
| `build.sh` | Deterministic rebuild |
| `hello-linux-x86_64` | Committed acceptance binary (**frozen**) |
| `hello-linux-x86_64.sha256` | SHA-256 of the binary (hex, one line) |
| `metadata.toml` | Pinned ELF / `PT_LOAD` / user-window fields |
| `readelf.txt` | `readelf -h -l -S` transcript |
| `malformed/` | Negative ELF fixtures for #92 (+ `generate.sh`) |

## Pinned toolchain identity

Built inside WSL2 on this host:

| Item | Value |
|------|-------|
| Distro | Docker Desktop WSL (Alpine-based `PRETTY_NAME="Docker Desktop"`; musl target) |
| Packages installed for this build | `binutils` 2.45.1-r0, `bash` 5.3.3-r1, `coreutils` 9.8-r1 (`apk add --no-cache binutils bash coreutils`) |
| Assembler | GNU assembler (GNU Binutils) **2.45.1** (`x86_64-alpine-linux-musl`) |
| Linker | GNU ld (GNU Binutils) **2.45.1** |
| Kernel | Linux 5.15.167.4-microsoft-standard-WSL2 |

Rebuilds that need bit-identical output must use the same binutils major/minor
(2.45.1) and the same `build.sh` flags.

## Rebuild

From a Linux/WSL shell (convert the Windows path with `wslpath` if needed):

```bash
cd fixtures/linux-hello
chmod +x build.sh
./build.sh
```

Flags used: `as --64`; `ld -static -nostdlib -no-pie --build-id=none
--hash-style=sysv -z norelro -T hello.ld`; then `objcopy` strips residual
`.comment` / `.note*` sections.

### Reproducibility proof (this tree)

```text
$ ./build.sh
SHA-256: 619a000cfa6990b3d73f97e365cf333aa140b09cfba096fac082647731004e4a
$ rm -f hello-linux-x86_64 hello-linux-x86_64.sha256 readelf.txt && ./build.sh
SHA-256: 619a000cfa6990b3d73f97e365cf333aa140b09cfba096fac082647731004e4a
# identical both times
```

## Linux execution proof (WSL)

```text
$ ./hello-linux-x86_64 > /tmp/m8-hello.out
$ echo $?
0
$ wc -c /tmp/m8-hello.out
18 /tmp/m8-hello.out
$ od -c /tmp/m8-hello.out
0000000   H   e   l   l   o       f   r   o   m       L   i   n   u   x
0000020   .  \n
0000022
$ xxd /tmp/m8-hello.out
00000000: 4865 6c6c 6f20 6672 6f6d 204c 696e 7578  Hello from Linux
00000010: 2e0a                                     ..
```

Stdout is exactly the 18 bytes `Hello from Linux.\n`; exit status is 0.

## Verification (host)

```bash
cargo xtask verify-m8-fixture
cargo test -p xtask m8_fixture
```

`verify-m8-fixture` checks SHA-256 against `hello-linux-x86_64.sha256`, asserts
every field in `metadata.toml` against a local ELF64 parser, and additionally
requires every `PT_LOAD` VA range to lie in
`[0x0000400000000000, 0x0000408000000000)` and the program-header table to lie
inside a `PT_LOAD` file range.

## Why only write / exit + the 999 probe

M8 Linux personality (#94) implements `write` and `exit`. The deliberate
unsupported syscall 999 proves `-ENOSYS` encoding and that the process
continues before the greeting. See [docs/M8_FIXTURE.md](../../docs/M8_FIXTURE.md).

## Malformed fixtures

See [malformed/README.md](malformed/README.md). Regenerate with
`malformed/generate.sh`.
