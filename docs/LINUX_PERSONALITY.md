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
- Success path: unsupported-syscall probe (nr 999 → `-ENOSYS`), then `write(1, …)` then `exit(0)`
- Provenance, rebuild, and `cargo xtask verify-m8-fixture`: see [M8_FIXTURE.md](M8_FIXTURE.md)

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

## M8.2 — ELF loader and process image (#92)

`kernel/src/process/linux_image.rs` turns the frozen fixture bytes into a
registered, isolated Clean-Slate process at runtime (nothing is flattened by
`kernel/build.rs`). Production code, always compiled; only the embedded bytes
(`LINUX_M8_FIXTURE`, feature `m8-linux-image`) and the QEMU self-test
(`m8-linux-image-self-test`, `cargo xtask test-m8-linux-image`) are feature-gated.

Pipeline (transactional, mirrors `service::spawn`):

1. `validate_linux_image(bytes) -> Result<LinuxImagePlan, LinuxImageError>` (pure,
   host-tested). `LINUX_M8_LOAD_POLICY` is `ET_EXEC`-only, W^X, page-zero reject,
   window `[0x0000_4000_0000_0000, 0x0000_4080_0000_0000)`. On top of
   `clean-slate-elf` it rejects `PT_INTERP` / `PT_DYNAMIC`, distinguishes page-zero,
   identity-map (`< window base`), kernel/non-canonical (`>= 1<<47`) and
   out-of-window addresses, requires `p_align` to be 0/1 or a power of two
   `>= 4096`, requires the program headers to be covered by a PT_LOAD (for
   `AT_PHDR`), rejects segments intersecting the stack reservation, and checks the
   mapping budget (`MAX_ADDRESS_SPACE_USER_MAPPINGS`) and the exact page-table
   frame demand (`MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES`) before anything is mapped.
   Every failure is a distinct `LinuxImageError` variant with a `description()`.
2. `build_linux_process_image` creates the address space, maps PT_LOAD pages via
   `image_loader::map_load_plan_segments` (segment-derived R/W/X, BSS zero-filled
   per page by `page_file_span`), maps the stack, writes the initial stack bytes
   through the process root (never via a user pointer), verifies the guard page
   is unmapped and the resource counts match the plan. Any failure destroys the
   address space (every frame and page-table frame reclaimed).
3. `launch_linux_process(allocator, kernel_stack_top, scheduler_slot, bytes)`
   registers the `Process` with `execution_personality: ExecutionPersonality::LinuxX86_64`
   (trusted kernel metadata, fixed at construction — the one launch-time
   assignment) and configures the scheduler thread, returning
   `LaunchedLinuxProcess { pid, tid, instance_generation, entry, launch_rsp, … }`.

Stack placement (fixed, documented): two NX+W+U pages
`[0x0000_407F_FFFF_D000, 0x0000_407F_FFFF_F000)` at the top of the slot, guard
page `0x0000_407F_FFFF_C000` unmapped, slot's last page unmapped. Two pages
because the fixture uses no stack and the default mapping budget is four pages
(one PT_LOAD page + two stack pages leaves one page of headroom); M9 may grow it.

Initial stack (per the contract above): `argc = 1`, `argv[0] = "hello-linux-x86_64"`,
`envp = []`, auxv `AT_PHDR` (derived: `phdr_vaddr` = first PT_LOAD covering
`e_phoff`, `0x0000_4000_0040_0040` for the fixture), `AT_PHENT = 56`,
`AT_PHNUM = e_phnum`, `AT_PAGESZ = 4096`, `AT_ENTRY = e_entry`, `AT_NULL`.
`AT_RANDOM` is not emitted (M9). Launch RSP is 16-byte aligned and points at
`argc`; for the fixture it is `0x0000_407F_FFFF_EF60`.

Proof (`[M8.2] PASS`): the first syscall of the Linux pid (nr 999) is observed
at the syscall entry with `user_rip` inside the RX PT_LOAD page and
`user_rsp == launch RSP`; the process is then torn down through
`teardown_current_process` and allocator free frames / registry occupancy return
to the pre-launch baseline while a native sibling keeps making progress. The
Linux syscall surface (#93/#94), fd projection (#95) and the acceptance run (#98)
are not exercised here; #97 wires `launch_linux_process` into the boot path and
grants console / stdio after it returns.

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

## #95 fd projection

Linux stdio is a **projection** onto existing Clean-Slate IPC console authority, not a new resource class.

### Model

- Each Linux-personality process may own a bounded fd table (`LINUX_FD_TABLE_CAPACITY = 4`, fds `0..3`) stored in a kernel registry keyed by `(pid, InstanceGeneration)`.
- Registry capacity equals `PROCESS_REGISTRY_CAPACITY` (not a separate soft limit).
- The table is **not** a field on `Process` (avoids spawn / literal churn).
- fd integers are compatibility-local only. Authority is always an `IpcEndpointTable` send-capability handle granted to that pid by trusted bootstrap (`grant_console_capability_for_pid` / `grant_send_capability`).
- M8 install: fd 1 = stdout, fd 2 = stderr (both `ConsoleEndpoint` projections onto the **same** console capability); fd 0 and fd 3 stay `Closed`. Stderr is not distinguishable from stdout on serial in M8 (acceptable for the fixture).
- Console sink lifecycle: `grant_console_capability_for_pid` lazily creates **one** kernel-owned `ConsoleSink` and reuses it for every grant. Holder teardown retires that holder's send capability only; the shared endpoint is not destroyed, so replacement launches do not exhaust `IPC_ENDPOINT_CAPACITY`.

### API (for #94 / #97)

- `install_stdio_for_process(pid, generation, stdout_handle, stderr_handle)` — does **not** pre-validate that the handles are held by `pid` (`send_message` does); rejects `KERNEL_PROCESS_ID`. M8 should pass the same handle twice.
- `projection_for(pid, generation, fd) -> Result<LinuxFdProjection, LinuxErrno>`
- `write_fd(pid, generation, fd, bytes) -> Result<usize, LinuxErrno>` (core: `LinuxFdRegistry::write_fd(&mut self, &mut IpcEndpointTable, …, personality)`)
- `release_for_process(pid, generation)` (also hooked from production teardown in `process/domain.rs`)
- `console_sink_render_style(personality) -> ConsoleSinkRenderStyle` (`Verbatim` for Linux, `NativeFramed` for native)

`write_fd` always calls `IpcEndpointTable::send_message(pid, handle, bytes)`. Naming fd 1 without a real grant yields `EACCES` / no output.

### `IpcSendError` → `LinuxErrno`

| IPC error | Linux errno |
|-----------|-------------|
| `InvalidCapability`, `StaleCapability` | `EBADF` |
| `Unauthorized` | `EACCES` |
| `InvalidMessageLength` | `EINVAL` |

Closed / out-of-range / missing / stale `(pid, generation)` also return `EBADF`. Empty writes return `Ok(0)` without IPC. Writes longer than `IPC_MAX_MESSAGE_BYTES` (64) return a **short write** of 64 bytes; #94 decides whether to loop.

### ConsoleSink rendering

Reuse `IpcEndpointKind::ConsoleSink` only — no raw console syscall and no new endpoint kind.

- **Linux-personality** senders on the fd path: payload is written to serial **verbatim** so acceptance can extract exactly `Hello from Linux.\n`.
- **Native** `SYSCALL_NR_IPC_SEND` framing (`[IPC ] console pid=N: …`) is unchanged in the native syscall handler.

### Teardown / replacement

Production `teardown_current_process` / `teardown_process_by_id` call `release_for_process` before IPC capability teardown. A replacement process with the same pid and a new generation gets a fresh table; lookups with a stale generation fail closed (`EBADF`). Holder capability slots are reclaimed so sequential relaunches do not grow endpoint/capability occupancy.

## M8.4 — write and exit (#94)

`kernel/src/syscall/linux/write.rs` and `exit.rs` replace the #93 placeholders in `table.rs`. Only `SYS_WRITE = 1` and `SYS_EXIT = 60` are wired; every other number (including `brk`, `arch_prctl`, `set_tid_address`, `exit_group`, `futex`, `mmap`) still takes the #93 unsupported path (`-ENOSYS`, bounded diagnostic, process continues). The handler type `LinuxSyscallHandler` and `LinuxSyscallContext { pid, instance_generation, frame }` are unchanged.

### `write(fd, buf, count)` — `rdi`, `rsi`, `rdx`

Order of checks (matches Linux `fdget_pos` → copy):

1. **fd first.** `linux_fd::projection_for(pid, generation, fd)` for the trusted caller. Out-of-range fd, `Closed` slot (fd 0 / fd 3 in M8), missing table or stale `(pid, generation)` → `EBADF`. Only fd 1 and fd 2 can be open in M8. `EBADF` therefore takes precedence over `EFAULT` **and** over the zero-length shortcut (`write(0, bad_ptr, 0)` is `EBADF`).
2. **`count == 0` → `Ok(0)`** without touching user memory or the endpoint, even for a non-canonical pointer.
3. **Bounded chunk loop.** The request is delivered in chunks of `LINUX_WRITE_CHUNK_BYTES = 64` (= `LINUX_USER_COPY_MAX_BYTES` = `IPC_MAX_MESSAGE_BYTES`, asserted at compile time). Each chunk is copied in with `copy_user_bytes` (live page-table walk, user bit required; failure → `EFAULT`) and then sent with `linux_fd::write_fd` → `IpcEndpointTable::send_message(pid, handle, chunk)`, so holder / generation / endpoint checks apply to every chunk and there is no kernel serial shortcut. Linux-personality senders render **verbatim** (#95).
4. **Single-call bound.** `LINUX_WRITE_MAX_BYTES = PAGE_SIZE (4096)` → at most `LINUX_WRITE_MAX_CHUNKS = 64` iterations, implemented as a fixed-range `for` so the loop is bounded even if a primitive misbehaves. A request longer than 4096 bytes is a **short write of exactly 4096** (never `EINVAL`, never an unbounded spin). Justification: a page is the granularity of user-range validation, Linux permits any short write, and a conforming caller (libc `write` loops) still completes arbitrarily long output while per-syscall IPC/serial work stays bounded.
5. **Partial-write rule.** `EFAULT`/`EBADF`/`EACCES`/`EINVAL` on the **first** chunk is returned as the errno; a failure (or short delivery) on a **later** chunk returns the bytes already delivered. The returned count always equals bytes accepted by the sink and never exceeds `count`. A primitive that copies fewer bytes than asked or a sink that claims more than it was handed is a kernel invariant violation and fails closed (`EINVAL` / partial count) rather than over-reporting.
6. The result is encoded once by `dispatch_with` (`encode_rax`); handlers never encode.

The loop is the pure function `write_chunked(count, fetch, deliver)`; host tests inject slice-backed `fetch` and a local `LinuxFdRegistry` + `IpcEndpointTable` `deliver`, and the non-canonical-pointer `EFAULT` case runs the real `copy_user_bytes`. The 18-byte fixture write is a single chunk.

`IpcSendError → LinuxErrno` mapping is #95's (`InvalidCapability`/`StaleCapability → EBADF`, `Unauthorized → EACCES`, `InvalidMessageLength → EINVAL`).

### `exit(status)` — `rdi`

- Recorded exit status is `status & 0xff` (`LINUX_EXIT_STATUS_MASK`; what a parent would see via `WEXITSTATUS`). Higher bits are discarded by contract; `exit(-1)` records 255.
- Logs one bounded line `[LNX ] exit pid=<pid> status=<n>`.
- Terminates through the **production** path: `process::domain::teardown_current_process(allocator, kernel_root_frame(), status, false)` with the allocator from `service_lifecycle_syscall_allocator_mut()` — the same call and arguments the userspace fault handler uses. That path retires the thread, reclaims the address space, IPC endpoints/capabilities, capability-space and network holdings, and calls `linux_fd::release_for_process` (#95 hook). Nothing is reimplemented; if the torn-down pid differs from the caller the kernel fails closed.
- **Never returns to userspace.** The SYSCALL stub restores the `SyscallContext` frame the dispatcher returns and executes `sysretq`, so an interrupt-style frame cannot be handed back through it. The handler therefore switches itself, exactly like the fault path and kernel task exit: `teardown_current_process` already selected the next runnable thread and activated its CR3 / TSS / syscall stacks (`prepare_current_scheduler_thread_dispatch`); the handler then does `restore_task_context(next_frame)` (`iretq`), or `start_first_task` when the scheduler returned `FRESH_TASK_SENTINEL` for a never-started kernel thread, or `fatal_kernel_error` when no runnable thread remains (mirrors the fault path's fail-closed behaviour). Every branch diverges, so the `LinuxSyscallResult` return type is satisfied by `!` coercion and `encode_rax` is never reached for `exit`. IF is masked for the whole path (IA32_FMASK) and the code runs on the exiting thread's static per-slot kernel stack, the same situation as a fault on that thread.

### QEMU proof (`cargo xtask test-m8-linux-dispatch`)

The M8.3 self-test is extended rather than duplicated. Trusted self-test code tags the process `LinuxX86_64`, calls `IpcEndpointTable::grant_console_capability_for_pid(pid)` once and `linux_fd::install_stdio_for_process(pid, generation, handle, handle)` **before** the process runs (this is the exact launch sequence #97 must perform), then hand-assembled code does: `syscall 999` → `rax == -38` else `exit(1)`; `write(1, "Hello from Linux.\n", 18)` → `rax == 18` else `exit(2)`; `write(7, …)` → `rax == -9` else `exit(3)`; `exit(0)`. Kernel-side checks: the fd projection accepted exactly the 18 expected bytes in one delivery and nothing for fd 7; render style is `Verbatim`; the exit status is 0; the process left the registry; no scheduler/IPC resource remains attributed to it; `projection_for` fails closed after exit; held capabilities return to baseline (the shared kernel-owned ConsoleSink persists by design); a Native sibling made progress. Serial must show `Hello from Linux.` at the start of a line (no `[IPC ] console` framing), `[LNX ] exit pid=… status=0`, then `[M8.3] PASS`. Any deviation is a `[FAIL]` fatal error; xtask times out fail-closed.

## M8.7 — integrated launch path (#97)

Production entry point: `service::linux_launch::launch_linux_hello(allocator,
kernel_stack_top, scheduler_slot, elf_bytes)`. Order (under
`without_interrupts` so the new Ready thread cannot run half-wired):

1. `process::linux_image::launch_linux_process` — validate/map/register with
   `ExecutionPersonality::LinuxX86_64` fixed at construction (#92).
2. `IpcEndpointTable::grant_console_capability_for_pid(pid)` once (#95).
3. `linux_fd::install_stdio_for_process(pid, generation, handle, handle)`.
4. Log `[LNX ] ELF loaded pid=<pid> entry=<hex>`.

Any failure after a process was inserted tears it down through
`teardown_process_by_id`, logs `[LNX ] load failed: <description>`, and returns
`Err` — never kernel-fatal. Feature `m8-linux-hello` bumps `TASK_COUNT` to 3
(both demo kernel tasks plus Linux hello in scheduler slot 2) and starts the
fixture through `ServiceLifecycleController` as
`BuiltinServiceImage::LinuxHello` / `LINUX_HELLO_SERVICE_ID`. The controller
owns generation and restart; boot arms a one-shot Start (`remaining_restarts =
0`). Load failure at boot logs `[LNX ] load failed: …` and continues into
`start_scheduler()` — it must never become `[FAIL]`.

Observer proof (`cargo xtask test-m8-linux-hello`, marker `[M8.7] PASS`): the
self-test never grants console/stdio and never drives relaunch. It Starts a
two-launch session (`remaining_restarts = 1`), watches the first exit +
controller Start (stale fd fail-closed, fresh stdout projection, exit
`status=0`, delivered hello bytes / Verbatim render), then the second exit,
then feeds a malformed corpus image to `launch_linux_hello` and asserts `Err`
+ no process + no frame leak while a native sibling keeps making progress
(+N after the malformed proof). The same xtask also boots the production
feature build and requires the hello signature plus `[M2  ] PASS`. Serial
signature (CRLF-safe, in order):

```text
[LNX ] ELF loaded pid=<pid> entry=0x0000400000400078
[LNX ] personality=x86_64 pid=<pid>
[LNX ] unsupported syscall=999 errno=ENOSYS
Hello from Linux.
[LNX ] exit pid=<pid> status=0
… (second launch under the self-test) …
[M8.7] PASS
```

No `[IPC ] console` line may contain the hello text.

### Generation spaces (M8.7)

Two generation counters appear in serial and must not be confused:

- **Controller / service generation** — `[SVC ] launch service=32768 pid=… gen=N`
  is `ServiceLifecycleController`'s authoritative generation for
  `LINUX_HELLO_SERVICE_ID` (bumped on each Start).
- **Process / registry generation** — observer lines such as
  `[M8.7] first exit observed pid=… gen=N` and fd-table keys use the process
  registry `instance_generation` assigned at insert. Stale fd lookups and
  `#98` greps for fd/identity proofs must use this process generation, not the
  `[SVC ] … gen=` field.

## M8 acceptance (#98)

Authoritative gate: `cargo xtask test-m8` (aliases `m8`, `m8.9`). Emits host-side
`[M8  ] PASS` only after every phase succeeds. Does not restate #96/#97 contracts;
see [M8_FIXTURE.md](M8_FIXTURE.md) and [M8.7 — integrated launch path (#97)](#m87--integrated-launch-path-97).

### What it proves

Ordered phases (`[M8  ] step N/5 <name>`):

1. `verify-m8-fixture` — SHA-256 + pinned ELF metadata for the committed hello binary.
2. `clean-slate-elf` host tests — segment-aware load-plan foundation (#129).
3. `clean-slate-linux-abi` host tests — errno/syscall/stack contract (#91).
4. `linux-image loader (host)` — `#92` `process::linux_image` + malformed corpus
   (`cargo test -p clean-slate-kernel --features m8-linux-image process::linux_image`).
5. `test-m8-linux-hello` — composed once (self-test then production QEMU); not
   re-booted inside the aggregate.

### Marker order (production build first for launch/output/exit)

**Production** (`--features m8-linux-hello`) — launch/personality/ENOSYS/hello/exit
must come from this boot (production `#97` path, not self-test shortcuts):

```text
[LNX ] ELF loaded pid=<n> entry=0x0000400000400078
[LNX ] personality=x86_64 pid=<n>
[LNX ] unsupported syscall=999 errno=ENOSYS
Hello from Linux.
[LNX ] exit pid=<n> status=0
[TASK] task 1 progress=
[TASK] task 2 progress=
[M2  ] PASS
```

No `[IPC ] console` line may contain `Hello from Linux.`.

**Self-test** (`--features m8-linux-hello-self-test`) — supplies evidence the
production boot cannot (known #97 limitation: no native userspace sibling):

```text
… first hello/exit …
[LNX ] ELF loaded pid=<n2> entry=0x0000400000400078
[M8.7] first exit observed pid=<n> gen=<process-gen> status=0
[M8.7] relaunch observed pid=<n2> gen=<process-gen2>
… second hello/exit …
[M8.7] second exit observed
[M8.7] malformed ELF rejected fail-closed
[M8.7] native progress=<n> …
[M8.7] PASS
```

Use **process** generation (`[M8.7] … gen=`) for identity/fd proofs, not
`[SVC ] … gen=`. The second `[LNX ] ELF loaded` appears **before** the
`[M8.7] first exit observed` / `relaunch observed` pair (controller Start
runs inside the exit path).

### Debugging failures phase by phase

| Failing step | Likely cause | Next action |
| --- | --- | --- |
| `verify-m8-fixture` | Bytes or metadata drift | Rebuild per [M8_FIXTURE.md](M8_FIXTURE.md); do not hand-edit the ELF |
| `clean-slate-elf (host)` | Load-plan / W^X / window regression | `cargo test -p clean-slate-elf` |
| `clean-slate-linux-abi (host)` | errno/stack/syscall contract | `cargo test -p clean-slate-linux-abi` |
| `linux-image loader (host)` | Policy or malformed corpus | `cargo test -p clean-slate-kernel --features m8-linux-image process::linux_image` |
| `test-m8-linux-hello` | Production or observer serial | Re-run `cargo xtask test-m8-linux-hello`; compare to the marker tables above |

Scripts treat `test-m8` as Aggregate and `test-m8-linux-hello` /
`test-m8-linux-image` / `test-m8-linux-dispatch` / `verify-m8-fixture` as
Constituents so `--exhaustive` recognizes `m8` without inventing a second
aggregate boot path inside `test-m8` itself.
