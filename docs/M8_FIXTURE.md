# M8 Linux hello fixture — provenance and verification

Authoritative tree: [`fixtures/linux-hello/`](../fixtures/linux-hello/).

This document freezes how Clean-Slate obtains, rebuilds, and verifies the
**unmodified** Linux ELF used for Milestone 8 acceptance (#96 / M8.6).

## Why this link address

Clean-Slate identity-maps physical memory at virtual 0 and grants each process
a single private PML4 slot
`0x0000_4000_0000_0000 .. 0x0000_4080_0000_0000`. A conventional `ET_EXEC` at
`0x400000` cannot be mapped in M8 (it would collide with the shared identity
map). The fixture is therefore linked at
`0x0000_4000_0040_0000` (window base + classic 4 MiB offset).

That address is still a valid Linux userspace VA (`< TASK_SIZE`), so the same
assembly source and ordinary linker script produce a binary that runs unchanged
on real Linux. This is a **link-address choice**, not a Clean-Slate-specific
relink/patch of the artifact. Low/`0x400000` user mappings remain M9+ kernel
debt (higher-half kernel). The first `PT_LOAD` includes the ELF/phdr headers
(`FILEHDR`/`PHDRS`) so `AT_PHDR` can name a mapped user address.

## Provenance

- Source: `hello.S` (GNU as, freestanding `_start`, RIP-relative string load) +
  `hello.ld` (single RX `PT_LOAD` at `0x0000400000400000`, headers included).
- Build recipe: `build.sh` with fixed `as`/`ld` flags (`-static -nostdlib
  -no-pie`, `--build-id=none`, discard/strip note and comment sections).
- Toolchain identity and Linux execution transcript: see
  [`fixtures/linux-hello/README.md`](../fixtures/linux-hello/README.md).
- Committed artifact: `hello-linux-x86_64` plus `hello-linux-x86_64.sha256` and
  `metadata.toml`. **Bytes freeze after the M8.6 follow-up push**; later lanes
  must not rewrite the binary to work around loader issues.

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
  (`ET_EXEC`, `EM_X86_64`, ELFCLASS64/LE, entry, phoff/phentsize/phnum, each
  `PT_LOAD` field, no `PT_INTERP`, no `PT_DYNAMIC`)
- Every `PT_LOAD` VA range lies in `[0x0000400000000000, 0x0000408000000000)`
- The program-header table file range lies inside some `PT_LOAD` file range

CI runs this via `.github/workflows/pr.yml` whenever `fixtures/**` or xtask
changes.

## Malformed companions

`fixtures/linux-hello/malformed/` supplies reproducible negative ELFs for #92
host tests (generator derives good-shaped loads from the window base; page-zero
and kernel-range cases remain conceptually out-of-window). See that directory's
README and `generate.sh`.

## Injection note

QEMU / kernel injection (#92/#97) must `include_bytes!` / copy this artifact
**unchanged**. Relinking against Clean-Slate libraries is out of scope and
forbidden for M8 acceptance.
