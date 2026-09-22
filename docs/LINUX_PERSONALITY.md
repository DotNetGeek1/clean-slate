# Linux x86-64 personality — execution contract (M8.1)

Linux is a **compatibility personality**, not the native Clean-Slate ABI. This document freezes the M8.1 contract consumed by the ELF loader (#92), syscall dispatch (#93), and `write`/`exit` + fd table lanes (#94/#95). Implementation types live in the `clean-slate-linux-abi` crate and in `kernel/src/process/personality.rs`.

## Personality model and trust boundary

Each userspace process carries trusted metadata:

```text
ExecutionPersonality::Native          (default)
ExecutionPersonality::LinuxX86_64
```

Rules:

1. Personality is assigned only by trusted process creation/loading code.
2. Userspace **cannot** select or switch personality via a syscall argument.
3. Syscall entry resolves the current process from the trusted scheduler/registry path (`current_process_id` / `current_syscall_caller_pid`), reads `execution_personality`, **then** interprets `RAX`.
4. Native and Linux syscall-number spaces may overlap (notably native `READ_U64 = 1` vs Linux `write = 1`) without ambiguity because routing is by personality, not by number alone.

`dispatch_target_for(personality)` is the pure hook #93 will call before decoding registers.

## Register and result convention

On `SYSCALL` (Linux x86-64):

| Register | Role |
|----------|------|
| `RAX` | syscall number in; `i64`-shaped result out |
| `RDI` `RSI` `RDX` `R10` `R8` `R9` | arguments 0..5 |
| `RCX` | clobbered (user RIP) — **not** an argument |
| `R11` | clobbered (user RFLAGS) — **not** an argument |

Decoded request shape: `LinuxSyscallRequest { nr, args: [u64; 6] }`.

M8 required numbers: `SYS_WRITE = 1`, `SYS_EXIT = 60`. Any other number returns `-ENOSYS`; the process continues.

## Errno encoding (Linux vs native)

**Linux:** success is a non-negative value in `RAX`. Failure is two's-complement `-errno` as `u64`. Decode rule: signed values in `[-4095, -1]` are errors (`clean_slate_linux_abi::encode_rax` / `decode_rax`).

**Native Clean-Slate:** sentinel encoding such as `SYSCALL_ENOSYS = u64::MAX - 37`. That bit pattern happens to equal `(-38) as u64`, so a Linux decoder would report `ENOSYS` — coincidence of shape only. The type system keeps the spaces apart (`LinuxSyscallResult` vs raw native `u64` sentinels). Personality routing must select which space applies **before** interpreting `RAX`.

## Unsupported-syscall behaviour

- Return `-ENOSYS` via Linux encoding.
- Process continues (no kill for unknown numbers in M8).
- Diagnostics are bounded by `UnsupportedSyscallBudget` (default limit 8). Further hits increment `suppressed` only. #93 wires the budget into kernel state.

## User pointer validation

Linux handlers that touch user memory must use the existing kernel primitives:

- `validate_user_pointer_range`
- `validate_user_writable_pointer_range`

in `kernel/src/mm/user_mapping.rs`. Linux fd numbers are **not** capabilities and never become resource authority.

## Initial process stack layout

At `_start`, `RSP` is 16-byte aligned and points at `argc`:

```text
low addresses (RSP)
  argc: u64
  argv[0] .. argv[argc-1]     (user VAs of strings)
  NULL
  envp[0] ..                  (user VAs of strings)
  NULL
  auxv pairs (a_type, a_val)  … ending with (AT_NULL, 0)
  [0..15 bytes padding]
  NUL-terminated string bytes (argv then envp)
high addresses (stack_top)
```

Auxv constants used by M8: `AT_NULL=0`, `AT_PHDR=3`, `AT_PHENT=4`, `AT_PHNUM=5`, `AT_PAGESZ=6`, `AT_ENTRY=9`.  
Defined but **not emitted** in M8: `AT_RANDOM=25`, `AT_SECURE=23`, `AT_PLATFORM=15`.

Builder API: `build_initial_stack(buf, stack_top_vaddr, argv, envp, auxv) -> InitialStackImage { rsp, bytes_used }`. #92 copies the image into mapped stack page(s).

### Worked example (M8 canonical)

Assumptions:

- `stack_top_vaddr = 0x0000_0000_7000_0000`
- `argv = ["hello"]`, `envp = []`
- auxv: `(AT_PHDR, 0x400040)`, `(AT_PHENT, 56)`, `(AT_PHNUM, 3)`, `(AT_PAGESZ, 4096)`, `(AT_ENTRY, 0x401000)` — builder appends `(AT_NULL, 0)`

String region (6 bytes) occupies `[stack_top-6, stack_top)`:

| VA | bytes |
|----|-------|
| `0x6FFF_FFFA` .. `0x6FFF_FFFF` | `68 65 6c 6c 6f 00` (`hello\0`) |

Vector region (with 16-byte-aligned `RSP`):

| Offset from RSP | Content |
|-----------------|---------|
| `+0` | `argc = 1` |
| `+8` | `argv[0] = 0x6FFF_FFFA` |
| `+16` | `NULL` (argv end) |
| `+24` | `NULL` (envp end) |
| `+32` | `AT_PHDR`, `0x400040` |
| `+48` | `AT_PHENT`, `56` |
| `+64` | `AT_PHNUM`, `3` |
| `+80` | `AT_PAGESZ`, `4096` |
| `+96` | `AT_ENTRY`, `0x401000` |
| `+112` | `AT_NULL`, `0` |

`RSP % 16 == 0`. Empty argv/envp is valid (`argc=0`, immediate argv/envp `NULL`s). Host tests in `clean-slate-linux-abi` lock the exact bytes and alignment.

## M8 fixture contract

Authoritative fixture binary:

- Linux x86-64, static `ET_EXEC`, no PIE, no `PT_INTERP`, no libc/dynamic loader
- Freestanding `_start`
- Success path: `write(1, …)` then `exit(0)`
- Separate probe: unsupported syscall → `-ENOSYS`

## Ownership split

| Layer | Owns |
|-------|------|
| Kernel / process | Personality tag, address space, safe user copies, process registry |
| Linux personality | Register decode, errno translation, Linux fd semantics, stack/auxv contract |
| Native services / capabilities | Actual output and resource authority behind translated calls |

Linux fd numbers must never be confused with capability handles.

## M9 extension points (explicit non-goals for M8)

- Broader syscall coverage (BusyBox-class), filesystem/path projection, sockets
- Auxv: `AT_RANDOM`, `AT_SECURE`, `AT_PLATFORM`
- TLS / thread-local setup at entry
- Dynamic linking, PIE, signals, `brk`/`mmap` breadth

See also: [COMPATIBILITY.md](COMPATIBILITY.md), [ROADMAP.md](ROADMAP.md) (M8/M9), [ARCHITECTURE.md](ARCHITECTURE.md).

## #93 dispatch

Syscall entry (`clean_slate_syscall_dispatch`) resolves the caller with
`current_syscall_caller_pid()` (scheduler thread + CR3 cross-check), reads
`execution_personality` from the process registry, then calls
`dispatch_target_for` **before** interpreting `RAX`:

| Target | Path |
|--------|------|
| `Native` | Existing native match, factored as `dispatch_native` (unchanged semantics) |
| `LinuxX86_64` | `syscall::linux::dispatch` |

If the caller cannot be resolved, behaviour stays native (same as pre-#93).

Linux module layout (`kernel/src/syscall/linux/`):

- `decode` — `SyscallContext` → `LinuxSyscallRegisters` → `LinuxSyscallRequest`
- `table` — `LinuxSyscallHandler` / `LinuxSyscallContext { pid, instance_generation, frame }`;
  `SYS_WRITE` / `SYS_EXIT` placeholders return `Err(ENOSYS)` until #94
- `user_copy` — bounded copy-in on `validate_user_pointer_range` → `Err(EFAULT)`
- unsupported numbers use `UnsupportedSyscallBudget` and log
  `[LNX ] unsupported syscall=<nr> errno=ENOSYS` while under budget

First Linux dispatch for a process instance logs
`[LNX ] personality=x86_64 pid=<pid>` (once per `(pid, instance_generation)`).

If a Linux-tagged process has no live instance generation, dispatch fails closed
with `-ESRCH` and a bounded `[LNX ] missing generation …` diagnostic (no silent
generation-0 sentinel).

`copy_user_bytes` returns `Ok(0)` for zero length, clamps long copies to 64 bytes
(caller decides short-write semantics), and `Err(EFAULT)` on validation failure.

QEMU proof: `cargo xtask test-m8-linux-dispatch` (`m8-linux-dispatch-self-test`),
marker `[M8.3] PASS`.
