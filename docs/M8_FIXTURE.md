# M8 Linux hello fixture — provenance and verification

Authoritative tree: [`fixtures/linux-hello/`](../fixtures/linux-hello/).

This document freezes how Clean-Slate obtains, rebuilds, and verifies the
**unmodified** Linux ELF used for Milestone 8 acceptance (#96 / M8.6).

## Provenance

- Source: `hello.S` (GNU as, freestanding `_start`) + `hello.ld` (single RX
  `PT_LOAD`, conventional `0x400000` base).
- Build recipe: `build.sh` with fixed `as`/`ld` flags (`-static -nostdlib
  -no-pie`, `--build-id=none`, discard/strip note and comment sections).
- Toolchain identity and Linux execution transcript: see
  [`fixtures/linux-hello/README.md`](../fixtures/linux-hello/README.md).
- Committed artifact: `hello-linux-x86_64` plus `hello-linux-x86_64.sha256` and
  `metadata.toml`. **Bytes are frozen after the #96 branch is pushed**; later
  lanes must not rewrite the binary to work around loader issues.

## Behaviour contract

Exact order:

1. Unsupported syscall **999** → expect `-ENOSYS` (`-38`); else `exit(1)`.
2. `write(1, "Hello from Linux.\n", 18)`.
3. `exit(0)`.

No other Linux syscalls. The fixture therefore requires only the M8 syscall
surface from #94 (`write` / `exit`) plus the unsupported-syscall / `-ENOSYS`
path from #93.

## Rebuild

```bash
cd fixtures/linux-hello
./build.sh
```

Run twice (clean between) and confirm identical SHA-256. Update
`metadata.toml` / `readelf.txt` only when intentionally cutting a new frozen
binary (orchestrator-approved).

## Verification

```bash
cargo xtask verify-m8-fixture
```

Checks:

- SHA-256 of `hello-linux-x86_64` matches `hello-linux-x86_64.sha256`
- Local ELF64 header/phdr parse (checked arithmetic; no dependency on the
  `clean-slate-elf` crate) matches every pin in `metadata.toml`
  (`ET_EXEC`, `EM_X86_64`, ELFCLASS64/LE, entry, phentsize/phnum, each
  `PT_LOAD` field, no `PT_INTERP`, no `PT_DYNAMIC`)

CI runs this via `.github/workflows/pr.yml` whenever `fixtures/**` or xtask
changes.

## Malformed companions

`fixtures/linux-hello/malformed/` supplies reproducible negative ELFs for #92
host tests. See that directory's README and `generate.sh`.

## Injection note

QEMU / kernel injection (#92/#97) must `include_bytes!` / copy this artifact
**unchanged**. Relinking against Clean-Slate libraries is out of scope and
forbidden for M8 acceptance.
