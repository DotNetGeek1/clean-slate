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

M8 required `SYS_WRITE = 1` and `SYS_EXIT = 60`. In this tree the registered Linux syscalls are the set in [Supported Linux ABI](COMPATIBILITY.md#supported-linux-abi). A number with no handler returns `-ENOSYS` and the process continues.

## Load policies and VA windows (M9 / #142)

- **M8 frozen hello:** `LoadPlanPolicy::m8_legacy_slot_x86_64()` / `LINUX_M8_LOAD_POLICY` — single PML4 slot 128, stack at the top of that slot (`launch_linux_process`).
- **Conventional low ET_EXEC:** `LoadPlanPolicy::linux_conventional_x86_64()` — e.g. static images linked at `0x400000`; `launch_linux_process_with_policy` + `validate_linux_low_va_image` (M9 acceptance). Console capability + stdio install match the M8.7 production sequence before the scheduler runs the image.

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
- `execve` syscall surface (#102), fork, dynamic linking, PIE, signals, `brk`/`mmap` breadth
- TLS / thread-local setup at entry (beyond static musl auxv contract)

See also: [COMPATIBILITY.md](COMPATIBILITY.md), [ROADMAP.md](ROADMAP.md) (M8/M9), [ARCHITECTURE.md](ARCHITECTURE.md).

## M9 #102 — process / exec / wait / pipe

Lane #102 implements the frozen BusyBox process subset on trusted `(pid, generation)`:
`fork`, `execve` (production pointer copy → `LinuxExecSpec` → `commit_exec`), `wait4`,
`exit_group`, `getppid`, and `pipe`. Parent/child links live in
`kernel/src/process/linux_proc/table.rs`; pipes are bounded (`LINUX_PIPE_MAX` ×
`LINUX_PIPE_CAPACITY` = 1024 bytes each) with `#147` `PipeRef` backends and `#145`
blocking (`WaitKey` namespace `0x50 << 56`: pipe reader
`0x50<<56 | 0x01<<48 | index<<32 | gen`, writer `0x02<<48`, parent wait
`0x50<<56 | pid`). Empty/full pipes and `wait4` block via `block_linux_syscall`
(idempotent restart; no spin, no `EAGAIN`). Pipe `write` with no readers returns
`EPIPE` (no `SIGPIPE` delivery in M9). A parent's `exit_group` reaps its zombie
children and orphans its running ones: an orphan keeps its proc-table slot and is
re-parented to pid 0, so its own exit later reaps it at once (#215; it used to lose the
slot and halt the kernel on that exit). An exit that finds no slot logs
`[LNX ] exit pid=… without proc-table slot` and tears the process down anyway. `read(0)` front-end lives in
`syscall/linux/fd.rs` (`ensure_open_fd`, 1024-byte scratch, kind dispatch); pipe
bytes use `linux_proc/pipe::read_fd`. `fork` copies each parent user page into a new frame
(`mm/fork_clone.rs`), up to `LINUX_FORK_MAX_PAGES`, which is the 16,384-page (64 MiB)
address-space ceiling, so a process within its memory budget can fork (#297). There is no
copy-on-write. A fork the free frames or the large mapping tables cannot hold fails with
`ENOMEM` before any page is copied. The child PTE keeps the parent's present, user, writable,
and no-execute bits (`user_copy_flags`). Capability inheritance is
`inherit_capabilities_for_fork`: it walks the parent with `list_holder` and
installs a child record with the same rights. It does not call `delegate` and
does not require `Rights::DELEGATE` (`kernel/src/capability/mod.rs`), but it
withholds a record carrying any `Rights::root_only_for` bit of its class
(`fork_inheritable`), as delegation would refuse it, and audits each withheld
record as `NotDelegable` (#203). Each copy is charged to the child, which is its own holder
with its own 16-slot quota (#220); a copy the child has no room for fails the fork with `EAGAIN`
and every copy already installed is revoked and released. `fork` also
returns `EAGAIN` when `LINUX_MAX_PROC_ENTRIES` (14) is full, when the parent already has 12
unreaped children, or when the scheduler or process registry (16 each) is full. Fault exits publish
a signalled wait status (`SIGSEGV` for page fault and general protection,
`SIGILL` for invalid opcode) through `linux_proc/fault.rs` before teardown.
With `m9-rootfs`, `exec_resolve::resolve_executable` calls
`linux_fs::resolve_executable`. Without `m9-rootfs`, `/bin/busybox` and
`/bin/sh` resolve to the M8 hello ELF (`LINUX_M8_FIXTURE`); the proc, exec-args,
and runtime probe paths resolve only on their self-test features. `fork.rs`
does not contain `linux_mem_clone_for_fork_stub` or
`linux_signal_clone_for_fork_stub`.

### Acceptance

- Fixture: `fixtures/linux-proc-probe/linux-proc-probe-x86_64` (raw syscalls: pipe +
  fork/wait, exec marker, `ECHILD`/`EBADF`/`EPIPE`, a grandchild that outlives its
  parent's `exit_group` and then exits (`[M9.I] orphan exit OK`, #215), fork-bomb `EAGAIN`).
- QEMU: `cargo xtask test-m9-linux-proc` (`m9-linux-proc-self-test`) — eight probe
  cycles with `[M9.I] PASS`, logging `pipe_pool_live`, `proc_table_live`, and open
  description pool occupancy each cycle.

## M9 #104 — rootfs fixture

Deterministic BusyBox rootfs bytes for M9 acceptance live in a bounded
`CSROOTFS` v1 image (`clean-slate-rootfs`, manifest `fixtures/busybox/frozen/rootfs.toml`).
Host verification: `cargo xtask verify-m9-fixture`. Provenance and layout:
[fixtures/busybox/frozen/ROOTFS.md](../fixtures/busybox/frozen/ROOTFS.md).

With `m9-rootfs`, `kernel/build.rs` embeds `$OUT_DIR/m9-rootfs.img` after verifying
the frozen BusyBox SHA-256. `process::linux_rootfs::image()` parses the blob with
the no_std reader (`lookup`, `children`, exact path bytes — no normalization).

**Link semantics (#101):** `EntryKind::Link` stores the target path in `data`.
Exec and path resolution for symlinks must preserve the **original** pathname
(`argv[0]` / `AT_EXECFN`) so BusyBox selects the applet; do not rewrite to the
link target before invoking the binary.

Read-only image entries cover `/bin`, `/etc`, and applet links. Only `/tmp` carries
the writable-root marker; durable writes traverse M5/M6 (#101), not the embed.

## M9 #101 — filesystem/path projection

Kernel-side bounded namespace broker over two backends: the read-only #104
`CSROOTFS` image and M6.3 persistent objects for writable `/tmp` files. Path
normalization (`LINUX_PATH_MAX = 256`), single-level rootfs symlinks, and
read-only enforcement (EROFS on rootfs writes and `mkdir` outside `/tmp`) live in
`process::linux_fs`. Syscall surface: `open`, `stat`, `lstat`, `getcwd`,
`mkdir`, `getdents64`; generic `read`/`lseek` front-ends dispatch on #147 open
descriptions (File vs Console vs Pipe/Socket placeholders).

| Limit | Value |
|-------|-------|
| Namespace nodes | 64 (`LINUX_FS_MAX_NODES`) |
| `/tmp` entries | 8 (dirs + files) |
| `/tmp` file bytes | 512 (`OBJECT_MAX_PAYLOAD_BYTES`) |
| Tmp object ids | `0x4c_0000` .. +4 files |

Boot (`m9-rootfs`): `init_namespace(linux_rootfs::image())` after integrity log.
Linux launch grants tmp object capabilities (`grant_linux_tmp_object_capabilities`);
failure is fail-closed. Tmp I/O uses `ObjectRequestQueue::submit` +
`block_linux_syscall(0x46 << 56 | request_id)`; `service_complete` wakes the
blocked syscall. Restart idempotency: poll completed slot before resubmit.

**Lifecycle (12 events):** rootfs integrity log → namespace init → tmp capability
grant → open path resolve → descriptor alloc → rootfs read or object RMW write →
object queue submit → block → service_complete wake → restart poll → read copy →
close (offset discard) → process teardown (namespace retained).

**Debt:** compatibility policy is kernel-resident for M9; mandate prefers a
userspace fs service — this lane is a broker, not a VFS.

QEMU acceptance: `cargo xtask test-m9-linux-fs` (`fixtures/linux-fs-probe/`).

## #304 — persistent `/home` (stage 1)

`/home` is one flat, writable directory that survives reboots, sized for what a Linux Doom
port writes: up to six save games of at most 180 KiB, its config file, and optional
screenshots and demos. It is not a filesystem; the object store stays a boot/config and
`/tmp` store, and a real filesystem is a later milestone item.

Each file is one storage-service object (`0x4D_0001` + slot), and a 512-byte name table
(object `0x4D_0000`, magic `CSHOME01`, 15 entries of length + name) lists them. The kernel
code is `process::linux_fs::home_table` (layout, pure) and `home_backend` (requests).

| Limit | Value |
|-------|-------|
| Files | 15 (`HOME_MAX_FILES`) |
| Name bytes | 27 (`HOME_NAME_MAX`); longer is `ENAMETOOLONG` |
| Bytes per file | 1 MiB (`HOME_MAX_FILE_BYTES`) |
| Live bytes in the store | a third of the storage service's 8 MiB heap; past it, `ENOSPC` |
| Bytes per `read` | 512 (one `READ_AT`; callers loop, as on any short read) |

**Protocol.** The object capability gains `READ_AT`, `WRITE_AT` and `TRUNCATE`, which
carry an `offset` (request bytes 40..48; the payload moves to 48). `WRITE_AT` and
`TRUNCATE` are staged, not committed; the next whole-object `WRITE` or `DELETE`, or a
`COMMIT`, commits them with it. The `/home` broker authorises every request against the
caller's right on the table object. Native holders reach the same ops through
`OBJECT_SUBOP_SUBMIT_AT` (#312; see [ARCHITECTURE.md](ARCHITECTURE.md#m63-persistent-object-capability-surface)).
The storage service answers `NO_SPACE` (status 5) past its live-bytes budget or a full
object table.

**Durability.** Writing the table, with every file's current length, commits the table
and all staged file bytes together. It is written on create, rename and unlink, and by
`close` of a written fd, `fsync` and `fdatasync`. A crash loses writes since the last
commit, never the agreement between the table's lengths and the bytes.

**Syscalls.** `open` (`O_CREAT`, `O_TRUNC`; `O_APPEND` and `O_EXCL` stay `EINVAL`), `read`, `write` (any
length; file writes are no longer clamped to 4096 bytes), `lseek`, `close`, `stat`,
`lstat`, and the new `fstat`, `fsync`, `fdatasync`, `ftruncate`, `rename` and `unlink`.
`mkdir` under `/home` is `EPERM` (it is flat), `mkdir /home` is `EEXIST`, a rename into or
out of `/home` is `EXDEV`, and exec of a `/home` file is `EACCES`. The Linux grant
(`TmpObjects`) now also carries `READ`/`WRITE` on the table object, so the shell's
authority line reads `tmp-objects=5`.

**Known gaps.** A file unlinked while open is gone at once (its open fds fail). A process
that exits without closing a written file leaves the change staged until the next commit.
No subdirectories, locking, permissions or timestamps.

QEMU acceptance: `cargo xtask test-m9-linux-fs` boots twice on one disk. The first boot runs
`fixtures/linux-home-probe/` on an empty `/home`: one 184320-byte `write` of a save, read
back, a config written, `fsync`ed and `ftruncate`d, and a write-then-rename-then-unlink. The
second boot finds `[HOME] loaded files=2 bytes=184324`, checks both files byte for byte,
and removes them.

## M9 #146 — Linux exec / process image substrate

`kernel/src/process/linux_exec.rs` generalizes the M8 loader into a bounded,
transactional exec substrate used by production launch (`launch_linux_process_from_spec`)
and by M8 hello via `m8_hello_exec_spec`. The `execve` **syscall** (#102) is out of
scope; this lane only prepares and commits static ET_EXEC images inside the kernel.

### `LinuxExecSpec`

| Field | Role |
|-------|------|
| `image` | Static ET_EXEC bytes (path-agnostic) |
| `argv` / `envp` | Pointer arrays on the initial stack (bytes, not UTF-8) |
| `exec_filename` | `AT_EXECFN` auxv string (bytes) |
| `stack_pages` | User stack size in pages (one guard page below; W^X) |
| `policy` | `LoadPlanPolicy` (same window / W^X rules as M8) |

Deliberate limits (host-tested): `LINUX_EXEC_MAX_ARGS`, `LINUX_EXEC_MAX_ENVS`,
`LINUX_EXEC_MAX_ARG_BYTES`, `LINUX_EXEC_MAX_STACK_PAGES`.

### Prepare / commit semantics

- **`prepare_linux_image`**: pure w.r.t. any live process — builds a fresh
  `ProcessAddressSpace`, maps segments, constructs argv/envp/auxv on the stack,
  returns `PreparedLinuxImage { entry, launch_rsp, page_table_frames, … }`. Any
  failure destroys the partial address space; the caller's live image is untouched.
- **`launch_linux_process_from_spec`**: fresh process registration (M8 hello, M9 low
  hello, self-tests).
- **`commit_exec(frame, …)`**: transactional exec on the **calling thread** from
  Linux syscall context on that thread's syscall kernel stack. Under
  `without_interrupts`: verify `instance_generation` and `live_threads == 1`,
  `replace_address_space` in the registry (same pid, same generation, same slot),
  then `activate_address_space_root` for the prepared image (kernel text, static
  task stacks, and the physmap remain valid in the shared high half, so continuing
  on the current kernel stack after CR3 switch is safe), then
  `linux_fd::close_on_exec(pid, generation)` (#147 fd core) and
  `destroy_process_address_space(old)`. Rewrite the in-place `SyscallContext` for
  `sysretq`: `user_rip` = entry, `user_rsp` = launch stack, `user_rflags` with IF
  and reserved bit 1 set, other GPRs zeroed, `rax = 0`. The scheduler's
  `saved_stack_pointer` / `launch_entry` are **not** touched. Failures before the
  registry commit leave
  the live process untouched and return errno to the syscall; after commit there
  is no half-image failure path.

### musl 1.2.5 auxv (static ET_EXEC)

Emitted set matches [M9_ABI_INVENTORY.md](M9_ABI_INVENTORY.md): `AT_PHDR`, `AT_PHENT`,
`AT_PHNUM`, `AT_PAGESZ`, `AT_BASE = 0`, `AT_FLAGS`, `AT_ENTRY`, uid/gid pairs,
`AT_SECURE = 0`, `AT_RANDOM` (16 bytes — **RDRAND** when available, documented
fallback; fixed test bytes only under `m9-linux-exec-self-test`), `AT_EXECFN`, `AT_NULL`.

Stack builder: `linux-abi/src/stack.rs` (`build_initial_stack_with_tail`).

### Acceptance

- Host: variable argv/envp layout, limit enforcement, auxv values, malformed-image
  rollback, M8 canonical stack byte-identical.
- QEMU: `cargo xtask test-m9-linux-exec` (`m9-linux-exec-self-test`) — fixture
  `fixtures/linux-exec-args/linux-exec-args-x86_64` at `0x400000` prints phase-1
  argv/envp/auxv, invokes `SYS_EXECVE` (self-test stub: fixed phase-2 spec, ignores
  user pointers; `#102` replaces with real pointer parsing into the same
  `LinuxExecSpec` / `commit_exec`), restarts at `_start` with phase-2 argv (same
  pid/generation), then a second `execve` with a truncated ELF returns `ENOEXEC` while
  the post-exec image keeps running; teardown restores allocator baseline;
  `[M9.F] PASS`.

## M9 #105 — Linux socket ABI onto M7

Syscall front-ends live in `kernel/src/syscall/linux/socket.rs` (`socket`, `bind`,
`connect`, `sendto` only; no `recvfrom`). The data plane is `#147` `read`/`write`/`writev`:
`SYS_READ` in `table.rs::lookup_core_handler` dispatches `SocketRef` to
`process::linux_socket::read_socket`. `write` and `writev` on a socket fd both gather
at most one page of the request and send it as one `write_socket` call
(`syscall::linux::write::write_socket_gathered`); socket fds have no console, file or
pipe write projection. Before #255 `writev` lacked this branch and returned `EBADF`, so
BusyBox `wget`'s request (musl stdio flushes with `writev`) never left the guest. UDP/TCP I/O is brokered through M7
`NetworkRequest` frames with at most one in-flight `request_id` per socket row;
blocking uses `block_linux_syscall` wait keys `0x53 << 56 | index << 32 | generation`.

Launch: `grant_linux_network_capabilities` from `launch_linux_process_from_spec`
when feature `m9-linux-socket` is enabled (fail closed on grant failure). The socket layer
itself is compiled under cfg `clean_slate_linux_socket`, which covers that feature and the
default image ([Network client](#network-client-218-s7a)). Teardown:
last `SocketRef` release submits `NetworkRequest::Close`; process exit releases all
sockets via `linux_fd` release hooks.

QEMU: `cargo xtask test-m9-linux-socket` (`m9-linux-socket-self-test`) — host M7
peer with `FixtureOptions.m9_profile` (DNS A → `10.77.0.50`, HTTP on
`10.77.0.50:4001`), static probe `fixtures/linux-socket-probe/linux-socket-probe-x86_64`,
8-cycle socket pool baseline, stale-session `ESTALE` proof; `[M9.L] PASS`. The fixture
answers the probe's `GET /` only after receiving the whole request, and the lane requires
exactly one answered request and no refused connection (#255).

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

If the caller cannot be resolved (scheduler/registry/CR3 cross-check or
personality lookup failure), dispatch **fails closed**: log a bounded
`[SYSC] unresolved caller reason=… fail-closed` diagnostic, then contain the
current userspace process through the production `teardown_current_process`
path (same containment model as the userspace fault handler). No native or
Linux handler runs; personality is never inferred from `RAX` or other user
registers. Kernel-invariant failures (no current thread, non-userspace caller)
use `fatal_kernel_error` instead.

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

## #147 fd / open-description core (M9)

Linux fd integers remain compatibility-local. Authority lives in a **global bounded open-description pool** (`OPEN_DESCRIPTION_CAPACITY = 48`) referenced by per-process fd tables (`LINUX_FD_TABLE_CAPACITY = 16`, lowest-free allocation).

Each fd entry stores `FdEntry { open: OpenDescriptionId, flags: FdFlags }` where `OpenDescriptionId { index, generation }` never aliases a replaced object. Open descriptions carry shared `OpenStatus` / `offset`, `DescriptorKind` (console, file/dir/pipe/socket placeholders), and a refcount; `close` drops one ref, final ref runs a kind-specific release hook.

Syscalls wired for this lane: `close(3)`, `writev(20)`, `dup2(33)`, `fcntl(72)` (`F_GETFD`/`F_SETFD`/`F_GETFL`/`F_SETFL`/`F_DUPFD_CLOEXEC`). `write(1)` uses the same console backend via open descriptions. Errno mapping: `EBADF` stale/closed, `EMFILE` per-process table full, `ENFILE` pool full, `EINVAL` bad `fcntl` (including an `F_DUPFD_CLOEXEC` minimum at or beyond the fd table)/`writev` iovcnt. `FD_CLOEXEC` is set by `open(O_CLOEXEC)`, `socket(SOCK_CLOEXEC)`, `F_DUPFD_CLOEXEC` and `F_SETFD`; `dup2` and `pipe` clear it; a committed `execve` closes every fd that has it.

QEMU: `cargo xtask test-m9-fd-core` (`m9-fd-core-self-test`), markers `[M9.G] pool_before_boot=` plus the M8.3 dispatch proof on the new substrate.

## #95 fd projection

Linux stdio is a **projection** onto existing Clean-Slate IPC console authority, not a new resource class.

### Model

- Each Linux-personality process owns a bounded fd table (`LINUX_FD_TABLE_CAPACITY = 16`) in the #147 registry keyed by `(pid, InstanceGeneration)`.
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

- **Linux-personality** senders on the fd path: payload bytes reach COM1 through
  [`console_write_bytes`](../../kernel/src/process/linux_fd.rs) (raw serial write).
  UTF-8 interpretation and `<non-utf8>` substitution are **not** used (#144).
- **Native** `SYSCALL_NR_IPC_SEND` framing (`[IPC ] console pid=N: …`) is unchanged in the native syscall handler.

## #144 byte-transparent stdio

Linux `write` still delivers IPC in 64-byte chunks, but **serial projection is
byte-transparent**: each accepted chunk is written with
`diagnostics::serial::serial_write_bytes` via
`linux_fd::console_write_bytes` — the only supported path from Linux stdio
payload bytes to the host serial device (#147 shared fd core must call this).

```rust
// kernel/src/process/linux_fd.rs — stdio backend contract for #147
pub(crate) fn console_write_bytes(bytes: &[u8]);
```

Properties locked by host tests and `cargo xtask test-m8-linux-dispatch` (M9
phase): arbitrary bytes (NUL, invalid UTF-8, control), multibyte UTF-8 split
across chunk boundaries, and 4096-byte single-call short writes are preserved
without CRLF translation. Kernel self-test emits `[M9.D] bytes=<n> fnv=<hex>`
over the sentinel-framed block (`<<M9BYTES>>` … `<<END>>`); xtask checks the
line against `linux_stdio_m9_payload::M9_STDIO_BLOCK_FNV`.

### Teardown / replacement

Production `teardown_current_process` / `teardown_process_by_id` call `release_for_process` before IPC capability teardown. A replacement process with the same pid and a new generation gets a fresh table; lookups with a stale generation fail closed (`EBADF`). Holder capability slots are reclaimed so sequential relaunches do not grow endpoint/capability occupancy.

## Serial console input (#218 S4)

COM1 receive feeds a canonical-mode line discipline (`kernel/src/device/serial_console/`) that fd 0 of the serial-console shell reads (see [Serial-console stdin](#serial-console-stdin-218-s5)). The receiver is compiled only with the `clean_slate_serial_console` cfg (the default image and `serial-input-self-test`) and is off until `serial_console::enable()` runs; every other build leaves IER at 0 and never echoes. The default image turns it on at boot, before init runs (`[KERN] serial console input on vector=N`).

- **Printable ASCII** (`0x20`–`0x7E`) is echoed and appended to the edit line.
- **CR or LF** commits the line with a trailing `\n` and echoes `\r\n`. A CR LF pair is two lines, the second empty.
- **BS or DEL** erases one byte and echoes `\b \b`; on an empty line it does nothing and echoes nothing.
- **Ctrl-U** erases the whole edit line, echoing `\b \b` once per byte.
- **Ctrl-D** on an empty line records one end-of-file, which is delivered after the committed bytes typed before it. Only one end-of-file can be pending, so a second one before the first is taken is dropped and counted. On a non-empty line, Ctrl-D commits the line without a newline, and a read stops at its end. Ctrl-D is not echoed.
- **Every other byte** (other control bytes, bytes `0x80`–`0xFF`, escape sequences byte by byte) is dropped without echo and counted.
- **Limits.** The edit line holds 256 typed bytes, so a full line commits as 257 bytes with its `\n`. Further printable bytes are dropped, not echoed, and counted; editing keys still work on a full line. The committed buffer holds 1024 bytes. A finished line that does not fit is echoed but held back whole, never split or truncated. While it is held back, every received byte is refused and counted, so a typed-ahead line can never be torn. The held line is committed when a read frees enough space.
- **Reads.** `read` copies at most one line and stops after `\n`, at the end of a Ctrl-D line, or before a pending end-of-file. A small buffer gets a line in pieces. `would_block` is true when there is nothing to read and no end-of-file is next, and `take_eof` consumes the end-of-file once it is next. Committing a line or recording an end-of-file wakes waiters on `CONSOLE_INPUT_KEY` from the IRQ (with no waiters this is a no-op), then calls the optional input notifier.
- **UART errors.** A byte with a framing, parity or break error is discarded and counted. A receive overrun (bytes the 16-byte FIFO lost) is counted, since the bytes are already gone. One interrupt drains at most 16 bytes and re-arms IER if the UART still has an interrupt pending, so a stuck or flooding line cannot hold the CPU in the handler. Echo is written from the interrupt, at most three bytes per byte read, except that Ctrl-U on a full line echoes 768.
- **Sharing COM1 with kernel output.** There is no lock. Every kernel write (`serial_write_fmt`, `serial_write_bytes`, the fatal and panic paths) emits its whole record with interrupts masked, and the receive interrupt runs with interrupts masked, so echo lands between records, never inside one, and nothing can deadlock on the port. Reading the line status on the transmit path clears the receive error bits; the transmit path hands them to the receive interrupt so the flagged byte is still discarded.
- **Not supported:** raw or non-canonical mode, termios or `ioctl`, `VINTR`/`VQUIT`/`VSUSP` (Ctrl-C, Ctrl-\ and Ctrl-Z are ordinary dropped control bytes, not signals), job control, UTF-8 or other multibyte input, and output processing beyond the echo listed above.

## Serial-console stdin (#218 S5)

In the default image the system manifest's shell row (`SYSTEM_SHELL_SPEC`, service 0x5400, image `LinuxShell`) is BusyBox as `/bin/sh -i` with `PATH=/bin`. Init starts that row once storage is ready. `kernel/src/service/system_shell.rs` builds the process and applies the row's grants before the new thread can run; it does not decide when the shell starts.

**Authority.** The row's grants are `Console`, `ConsoleInput`, `TmpObjects` and `NetworkClient`, and the Linux launcher applies them while it builds the process, before it can run:

- `Console`: the console capability, installed as fd 1 and fd 2. The shell's prompt, its output and its commands' output go there.
- `ConsoleInput`: fd 0, a read-only console-input description. This is the grant that makes the shell interactive; it requires `Console` in the same row, and the manifest refuses it anywhere else.
- `TmpObjects`: read and write capabilities on the four `/tmp` backing objects (`0x4C0000`–`0x4C0003`), so `/tmp` is writable. Storage serves them.
- `NetworkClient`: the network client entitlement, and through it a client capability for the live network instance (see [Network client](#network-client-218-s7a)).

Being a Linux process adds the Linux personality (`linux=1`). It gets no other network authority, no block device, no object-service role, no lifecycle control and no IPC endpoints. The launch-time authority audit counts all of this; the shell's line must read `console=1 net-client=1 net-client-entitlement=1 tmp-objects=5 linux=1 console-input=1` with every other count 0 while a network instance is live, and `net-client=0` while none is. `for_grants` derives that expectation from the row's image and grants, and from whether a network instance is live, as for every other row. The process line ends `net-client=1` when the row grants `NetworkClient`, whether or not a client capability was issued.

**fd 0.** Only a launch whose row carries `ConsoleInput` installs it. Every other process, and every other build, keeps fd 0 closed as before. Writing to fd 0 is `EBADF`. `read(0)`:

- copies committed bytes and stops after a `\n` (or at the end of a line committed with Ctrl-D), so one read returns at most one line;
- with nothing committed, returns 0 once for a pending end-of-file (Ctrl-D on an empty line), and the next read blocks again;
- with nothing committed and no end-of-file, returns `EAGAIN` on an `O_NONBLOCK` description, and otherwise blocks on `CONSOLE_INPUT_KEY` and restarts the syscall when the receive interrupt commits a line or records an end-of-file.

Syscalls run with interrupts masked: `IA32_FMASK` is written with `SYSCALL_ENTRY_RFLAGS_MASK`, which includes IF (`kernel/src/syscall/mod.rs`), the host test in `syscall/validation.rs` pins that, and the syscall path contains no `sti`. The receive interrupt therefore cannot commit a line between a reader's empty check and its waiter registration, so no wake is lost.

`poll` reports fd 0 readable while a read would not block, and never writable. A `poll` that waits on fd 0 records a producer interest; after every commit or end-of-file the receive interrupt calls the input notifier, which wakes every poller with an interest in console input. If the interest table is full, a poll that includes console input returns `ENOMEM` instead of sleeping through input it could never be woken for.

**Through the console service (#310).** For a process whose console goes through the console service (it holds `CONSOLE_CONNECT` on the console port, as the shell's tree does), `read(0)` asks its console stream instead: the kernel sends a `READ` of up to 62 bytes and blocks on the connection, and the service answers the oldest waiting `READ` with a committed line, an end of input, or nothing. A read returns the answer's bytes (what does not fit stays for the next read), 0 for an end of input, and `EAGAIN` on an `O_NONBLOCK` description while the `READ` waits. `poll` sends that `READ` ahead of time, and any event on a kernel-held console connection wakes every poller with an interest in console input. The rules above hold unchanged; while the service cannot be reached, fd 0 reads the line discipline directly.

**Waiting cannot exhaust a kernel table.** A blocked `read(0)` takes one waiter slot, and the waiter table has one slot per scheduler thread (`MAX_WAITERS` is defined as `TASK_COUNT` in `sched/wait.rs`) and a blocked thread waits on one key at a time, so no number of blocked readers can fill it. The poll interest table is shared and fixed (16 entries, at most 8 fds per `poll`); a full table is `ENOMEM` for the caller, never a kernel error.

**Children.** `fork` copies the fd table, so commands the shell runs inherit fd 0 (and fd 1, fd 2 and the `/tmp` capabilities); `exec` keeps it. A pipeline's `dup2` replaces fd 0 with the pipe in the reading command. The authority audit runs once, when the service instance is launched, so children are not audited; they hold no more than the shell did.

**Readiness and restart.** The kernel reports the shell ready (`[SVC ] ready service=21504 … kernel-observed first-console-input-wait`) the first time the live instance blocks reading fd 0, which is after it printed its prompt. Linux `exit` and `exit_group` publish the exit of a live service instance to the lifecycle controller before teardown, as a CPL3 fault already did; a refused publication is fatal. Init restarts the shell after every exit, and gives up when three restarts in a row end before a ready report (`RestartSpec::OnExitUntilUnready`). Details and the values in use are in [DEVELOPMENT.md](DEVELOPMENT.md#the-serial-console-shell).

**Limits.**

- Ctrl-C, Ctrl-Z and Ctrl-\ are dropped control bytes, and signals are stored but never delivered, so nothing can interrupt a command.
- All processes holding fd 0 read one input stream; each committed line goes to whichever reader takes it first (through the console service, the one that has waited longest).
- `ioctl` returns `ENOTTY` for every request on every open fd, so no program sees a terminal and ash runs without line editing or history.
- There is no job control. This BusyBox has no `jobs`, `fg` or `bg`, and a background command fails because ash opens `/dev/null` for its stdin and there is no `/dev`.
- The prompt is `# `. A fresh shell prints it just before its banner, so the first prompt of each instance is not on the last line.
- Output is not translated: the guest writes `\n`, and the host terminal or QEMU's stdio backend moves to the start of the line.
- Escape sequences from arrow and function keys are not recognised: the ESC byte is dropped and the printable rest enters the line.

## Network client (#218 S7a)

The default image compiles the Linux socket layer (#105) with cfg `clean_slate_linux_socket`, which `kernel/build.rs` emits for the default image and for `m9-linux-socket`. A row with `NetworkClient` in a build without that cfg fails to launch with `system shell: NetworkClient needs the Linux socket layer, which this build does not compile`; the grant is never skipped. The manifest accepts `NetworkClient` on Linux rows only.

**Entitlement.** At launch the kernel records a network client entitlement for the process: a capability record on `ResourceRef::network(0x5200, u64::MAX)`, which names the network service and no instance (instance generations are `u32`, and an M7 grant made before the first network start sits on generation 0), with rights connect, send and receive (`kernel/src/capability/network.rs`). It authorises nothing itself: no live resource matches it, `authorize_network_op` refuses it regardless, and the socket broker never picks it. `fork` copies it into the child as a derived record, and process teardown revokes it with the rest of the holder's records. The authority audit counts it as `net-client-entitlement`, apart from `network`.

**Client capability.** Socket operations need a client capability bound to the live instance, `ResourceRef::network(0x5200, generation)`, as in M7. The kernel derives one from the entitlement:

- at launch, if a network instance is live (`[CAP ] net client entitlement holder=<pid> service=20992 instance-generation=<g>`, or `instance-generation=none`);
- for every process holding an entitlement each time a network instance registers with the lifecycle controller (`[CAP ] net client reissued holder=<pid> generation=<g>`).

Issuing revokes and releases the holder's earlier instance-bound client records first, so a holder has at most one, and an instance going away (exit, fault, restart or terminate) revokes and releases them all (`[CAP ] net client revoked count=<n> reason=instance-gone`). The table therefore holds at most two records per entitled process whatever the number of restarts; the capability table has 128 slots, at most 16 per holder (#220). With no instance live the shell still launches and runs, and `socket(2)` fails with `EACCES` (`[NET ] denied`), so `nslookup` and `wget` report an ordinary error.

**Children across a restart.** A child forked before the network restarts holds the inherited entitlement and a derived copy of the parent's client capability. The instance going away revokes that copy with the parent's. On the new instance's registration the child, as an entitlement holder, gets its own client capability for the new generation, independent of the parent's. A child forked afterwards inherits the parent's current one.

**Sockets of a lost instance.** When the instance goes away every open Linux socket is marked lost before the client capabilities are revoked. Its in-flight bridge request is dropped, so the new instance never serves it, and its readers, writers and `poll` waiters are woken. Each restarted syscall then fails: streams with `ECONNRESET`, datagrams with `EIO`. A lost socket polls readable, writable and in error (and hung up for TCP), so `poll` returns rather than sleeping. Lost sockets are never rebound to the new instance: every later operation fails the same way until the fd is closed, and closing one sends nothing to the service. A socket whose open had not completed is closed outright. The log line is `[NET ] linux sockets lost count=<n> reason=instance-gone`.

Host tests in `capability/network.rs` and `process/linux_socket/mod.rs` cover re-issue, 1000 restarts without accumulation, a launch with and without a live instance, a child forked before a restart, and the wake of a blocked reader and a poll waiter.

**Proven in QEMU (#218 S7b).** `cargo xtask test-system` ([DEVELOPMENT.md](DEVELOPMENT.md)) boots the `system-test-hooks` build, the default image plus a kernel hook that faults a service with a real user-mode page fault when its control byte arrives on COM1: Ctrl-\ the network service, and Ctrl-], Ctrl-^ and Ctrl-_ the compositor, desktop shell and app (used by `test-system`'s desktop boot and by `test-system-desktop`). For the network service, under a live shell it shows:
- the lost-socket path, which until then had host tests only: a BusyBox `wget` blocked in a TCP read of a peer that never answers is woken and fails with `ECONNRESET` (`wget: error getting response: Connection reset by peer`) after `[NET ] linux sockets lost`, and the shell survives and prompts again;
- the revoke on the instance going away (`[CAP ] net client revoked`);
- init's restart policy restarting the network service once (`[SUP ] restart service=20992 attempt=1`), the new instance registering as generation 2 with a launch audit that matches its manifest row, and the re-issue to the shell (`[CAP ] net client reissued holder=<shell pid> generation=2`);
- `nslookup` and `wget` working again from the same shell through generation 2.

Each `wget` is a full exchange: the fixture answers only a request it has received, and the lane requires one answered request per `wget` step and no connection refused for lack of one. The blocked reader's request reaches the fixture's hold port too, which reports it and never answers. A child forked before the restart is covered by host tests only.

TLS is not exercised from the shell: this BusyBox has no TLS and cannot be rebuilt here, and TLS stays covered by the M7 lanes only.

## M8.4 — write and exit (#94)

`kernel/src/syscall/linux/write.rs` and `exit.rs` are the `write` and `exit` handlers. At M8.4 they were the only wired Linux syscalls. In this tree, `lookup_handler` in `kernel/src/syscall/linux/table.rs` also registers the calls listed under [Supported Linux ABI](COMPATIBILITY.md#supported-linux-abi). `brk`, `arch_prctl`, `set_tid_address`, `exit_group`, and `mmap` have handlers when the features named there are enabled. `futex` still has no handler. A number with no handler still returns `-ENOSYS` with a bounded `[LNX ] unsupported syscall=<nr> errno=ENOSYS` line, and the process continues. The handler type `LinuxSyscallHandler` and `LinuxSyscallContext { pid, instance_generation, frame }` are unchanged. The rest of this section is the `write` and `exit` contract.

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
- **Never returns to userspace.** The SYSCALL stub restores the `SyscallContext` frame the dispatcher returns and executes `sysretq`, so an interrupt-style frame cannot be handed back through it. The handler therefore switches itself, exactly like the fault path and kernel task exit: `teardown_current_process` already selected the next runnable thread and activated its CR3 / TSS / syscall stacks (`prepare_current_scheduler_thread_dispatch`); the handler then does `restore_task_context(next_frame)` (`iretq`), or `start_first_task` when the scheduler returned `FRESH_TASK_SENTINEL` for a never-started kernel thread, or, when no runnable thread remains, the idle thread (`sched::idle::idle_after_last_thread` logs `[KERN] no runnable thread remained after …; idling`, as the fault path does; #215). Every branch diverges, so the `LinuxSyscallResult` return type is satisfied by `!` coercion and `encode_rax` is never reached for `exit`. IF is masked for the whole path (IA32_FMASK) and the code runs on the exiting thread's static per-slot kernel stack, the same situation as a fault on that thread.

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

Ordered phases (`[M8  ] step N/7 <name>`):

1. `verify-m8-fixture` — SHA-256 + pinned ELF metadata for the committed hello binary.
2. `clean-slate-elf` host tests — segment-aware load-plan foundation (#129).
3. `clean-slate-linux-abi` host tests — errno/syscall/stack contract (#91).
4. `linux-image loader (host)` — `#92` `process::linux_image` + malformed corpus
   (`cargo test -p clean-slate-kernel --features m8-linux-image process::linux_image`).
5. `test-m8-linux-image` — M8.2 ELF loader self-test boot.
6. `test-m8-linux-dispatch` — M8.3 personality dispatch self-test boot.
7. `test-m8-linux-hello` — composed once (self-test then production QEMU); not
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

## M9 #103 — runtime / memory / time / poll / signals-state

**Owner lane:** `syscall/linux/runtime.rs` (+ `poll.rs`), `process/linux_mem.rs`,
`process/linux_signal.rs`, `time/`, `linux-abi/runtime.rs`.

**Syscalls:** `arch_prctl`, `brk`, `getpid`, `ioctl`, `mmap`, `munmap`,
`nanosleep`, `poll`, `rt_sigaction`, `rt_sigprocmask`, `set_tid_address`, `uname`.

**Time:** APIC timer rate is calibrated once at boot against PIT channel 2 with
interrupts masked (`[TIME] apic tick calibrated: ticks/s=N ref=pit`). Linux
`nanosleep` / `poll` timeouts are exact `Deadline::MonotonicNs` values
(`monotonic_deadline_from_timespec` / `monotonic_deadline_from_millis`:
TSC `now + request`, no tick rounding). The periodic tick adds under one
period before the expiring check; see `M9.md`, "Timed wait latency".

**Memory:** per-process brk/mmap bookkeeping in `linux_mem` (bounded tables;
anonymous `MAP_PRIVATE|MAP_ANONYMOUS` only; W^X rejects `PROT_EXEC|PROT_WRITE`).

**Signals:** disposition + blocked mask storage only (no delivery in M9).

**Blocking:** `nanosleep` / `poll` use `block_linux_syscall` with wait-key
namespace `0x52` (see `M9_BLOCK_WAKE.md`).

**QEMU:** `cargo xtask test-m9-linux-runtime` — eight probe launch/exit cycles,
baseline occupancy logged, `[M9.J] PASS`.
