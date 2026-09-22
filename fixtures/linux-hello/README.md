# Linux hello fixture (M8.6 / #96)

Deterministic unmodified Linux x86-64 `ET_EXEC` ELF used for M8 acceptance.
**After this branch is pushed, the committed binary bytes are frozen** — do not
relink or patch them to paper over loader bugs (#92/#97 inject the artifact
unchanged).

## Behaviour (exact order)

1. `syscall` nr **999** with zeroed args. Expect `rax == -38` (`-ENOSYS`). If not,
   `exit(1)` via syscall 60.
2. `write(1, "Hello from Linux.\n", 18)` via syscall **1**.
3. `exit(0)` via syscall **60**.

Nothing else: no `brk`, `arch_prctl`, TLS setup, `rt_sigaction`, `exit_group`,
or `set_tid_address`. The program does not read the initial stack.

## Files

| Path | Role |
|------|------|
| `hello.S` | Freestanding `_start` (GNU as) |
| `hello.ld` | Single RX `PT_LOAD` at conventional `0x400000` base |
| `build.sh` | Deterministic rebuild |
| `hello-linux-x86_64` | Committed acceptance binary (**frozen**) |
| `hello-linux-x86_64.sha256` | SHA-256 of the binary (hex, one line) |
| `metadata.toml` | Pinned ELF / `PT_LOAD` fields |
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
SHA-256: 21e044df3b25c26d07c7d6cc536564c7c9e539ca9b98f105022aac7607d6a7ba
$ rm -f hello-linux-x86_64 hello-linux-x86_64.sha256 readelf.txt && ./build.sh
SHA-256: 21e044df3b25c26d07c7d6cc536564c7c9e539ca9b98f105022aac7607d6a7ba
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

`verify-m8-fixture` checks SHA-256 against `hello-linux-x86_64.sha256` and
asserts every field in `metadata.toml` against a local ELF64 parser (no kernel
crate dependency).

## Why only write / exit + the 999 probe

M8 Linux personality (#94) implements `write` and `exit`. The deliberate
unsupported syscall 999 proves `-ENOSYS` encoding and that the process
continues before the greeting. See [docs/M8_FIXTURE.md](../../docs/M8_FIXTURE.md).

## Malformed fixtures

See [malformed/README.md](malformed/README.md). Regenerate with
`malformed/generate.sh`.
