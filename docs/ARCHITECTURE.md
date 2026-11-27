# Architecture

## Architectural stance

Clean-Slate should use a pragmatic microkernel/hybrid architecture: keep the privileged kernel deliberately small while allowing performance-sensitive paths to use shared memory, batched IPC, zero-copy buffers, and narrowly scoped fast paths.

The project is not pursuing microkernel purity for its own sake. Isolation and recoverability matter more than ideology, and avoidable IPC overhead should be engineered away where possible.

## Kernel responsibilities

The kernel should own only the mechanisms that genuinely require privileged execution:

- CPU scheduling;
- virtual memory and page-table management;
- physical memory allocation primitives;
- process/address-space creation;
- capability validation and transfer;
- IPC primitives;
- interrupt routing;
- timers;
- syscall entry/exit;
- IOMMU control;
- minimal CPU and platform management.

Everything that can reasonably live outside the kernel should be considered for userspace.

The kernel crate's module layout, visibility rules and dependency direction are documented in [DEVELOPMENT.md — Kernel source layout](DEVELOPMENT.md#kernel-source-layout).

## Userspace services

Expected services include:

- device manager;
- filesystem/object service;
- network stack/service;
- graphics compositor and GPU service;
- audio service;
- input service;
- application supervisor;
- package/application manager;
- compatibility runtimes;
- repair/observability engine.

These services should communicate through explicit contracts and capability-bearing IPC rather than shared global state.

M10 amendment: the graphics compositor is the input consumer. It drains the kernel raw input queue directly (`Input{INPUT_CONSUME}`); there is no separate input service in M10, and the M10 display backend is kernel-resident rather than a GPU service process. See [GRAPHICS.md](GRAPHICS.md).

## Application domains

Every executable component runs inside a revocable security domain.

A domain owns or is granted:

- a private virtual address space;
- CPU scheduling identity;
- memory accounting;
- explicit capabilities;
- IPC endpoints;
- application-private mutable state;
- access to shared system services only through capabilities.

An application starts with minimal authority. It does not automatically inherit the user's filesystem, network, devices, clipboard, camera, microphone, or other processes.

Riskier applications can be promoted to stronger isolation tiers, including a hardware-backed microVM.

## Capability model

Clean-Slate should use object capabilities rather than relying primarily on ambient user identity.

Conceptually:

```text
Image Editor
  |
  +-- FileCapability(photo.jpg, read/write)
  +-- RenderCapability
  +-- ClipboardCapability(temporary)
```

No file capability means no file access. No network capability means no network access.

Capabilities should be delegable, attenuable, revocable where practical, and auditable.

## Resource ownership

Resources belong to domains and services rather than vaguely to a user session.

When a domain dies, resources associated with it should become reclaimable immediately:

- private memory;
- handles;
- IPC endpoints;
- timers;
- background jobs;
- temporary storage;
- device contexts.

This is intended to eliminate zombie helpers, forgotten startup services, and poorly attributable resource consumption.

## Drivers

Native drivers should preferably execute outside the kernel inside restricted driver domains.

A driver receives only the hardware capabilities it requires, such as:

- MMIO ranges;
- IRQ endpoint;
- DMA buffers;
- PCI configuration access;
- power-management operations.

The IOMMU must restrict device DMA to authorized memory.

A driver crash should ordinarily become a driver-domain failure rather than a kernel failure.

## M5 storage layering

M5 introduces a Clean-Slate-native block contract between hardware-specific block transports and persistent-store logic.

- `clean-slate-block` is the narrow reusable layer. It owns device identity, geometry, bounded block read/write validation, transport-vs-request error separation, and the explicit `flush` durability barrier.
- `clean-slate-store` is the first transport-independent on-disk policy layer. It is a boot/config and `/tmp` store, not a filesystem: flat objects named by a 64-bit id and a name of at most 32 bytes, with no directories, offsets, partial writes or per-object metadata beyond length. A real filesystem is its own milestone item. Version 3 uses two redundant one-block superblocks at LBA 0 and 1, each containing magic/version/geometry/CRC-32C fields, the object limit, the next object epoch, and the extent and CRC-32C of an object table; each commit writes its payloads and then the table into the copy-on-write arena paired with the slot it commits to, so a newer generation never overwrites blocks still referenced by the currently committed superblock. A table entry carries the object's id, epoch, name, length, extent and a payload CRC-32C. The table CRC covers the generation and the table's LBA, and each payload CRC covers the object's id, epoch, start LBA and length, so an intact payload at another object's place is rejected. Versions 1 (an additive byte sum) and 2 (a seven-entry table inside the superblock) are refused as `UnsupportedVersion`, not migrated.
- The object limit is derived from the disk: one object per 16 blocks of a payload arena, at least 128 and at most 65,536 (`object_limit`), so the 64 MiB QEMU data disk allows 4095. A commit rewrites the table of live objects only, so its cost grows with the objects stored, not with the limit.
- Every object gets an epoch when it is created, from a counter the superblock persists, and keeps it across rewrites. An object created after a delete, under the same id or name, gets a larger epoch, so a reference bound to (id, epoch) can never reach the new object. An epoch becomes durable with the commit that created its object; it must not be handed out before that commit returns.
- Persistent-store code must depend only on this contract. It must not import VirtIO queue structures, PCI configuration details, MMIO register layouts, or raw DMA descriptors.
- The initial real backend may live in the kernel for bring-up, but that is an implementation detail. The long-term direction remains a restricted driver/service domain once MMIO/IRQ/DMA capabilities exist.
- M5 uses a bounded request/response block wire contract between the userspace storage service and a kernel-hosted bootstrap backend. The public wire format carries only protocol/version/op/request-id/device-id/LBA/count/length/status/geometry fields, never kernel pointers or physical addresses.
- Block completion is interrupt driven (#186). The kernel backend (`service::block_bridge` over `device::virtio::block`) keeps one request in flight. `SYSCALL_NR_BLOCK_REQUEST` submits it and blocks the calling thread on the block completion key (`0x48 << 56`) with a `Deadline::MonotonicNs` 5 s after submission (`BLOCK_COMPLETION_TIMEOUT_NS`). The virtio-blk queue interrupt only counts and wakes that key; it arrives by MSI-X, or by INTx on GSI 23 when the device has no MSI-X table, through the device-interrupt routing shared with virtio-net (see [NETWORK.md](NETWORK.md#blocking-waits-and-virtio-interrupts-167-170)). Every wait outcome, the deadline included, resumes with `BlockedResume::RetrySyscall`, so the re-executed syscall either harvests the used ring or, once the deadline has passed, abandons the request. Abandoning poisons the queue, because the device may still own the descriptors, so the driver resets the device at once (#199): it writes status 0 and waits (at most 1024 reads) for it to read back 0, after which the device no longer touches the ring, then negotiates the same features again, re-reads the geometry, clears and re-attaches the static ring, assigns the MSI-X queue vector again (a virtio reset clears it; the kernel-side vector or INTx route stays allocated, and an INTx reset reads the ISR to drop a stale assertion) and sets `DRIVER_OK`. The timed-out request completes as `ResetRequired` (`[BLK ] request id=N timed out; device reset`, after `[BLK ] device reset complete resets=N`), and later requests go ahead. A malformed completion (wrong descriptor id, short used length) fails its request and resets the device the same way. A reset that fails (status stuck, or the device came back with other features, queue size or geometry) stops the device and logs `[BLK ] device reset failed: …`; every later request then completes as `ResetRequired` until the next boot. The storage service treats a block error during a commit as a failed request (`OBJECT_STATUS_STORE_ERROR`) and keeps serving: the committed generation moves only when a commit's flushes all complete, and what the failed request staged stays staged, so its outcome is unknown rather than durable until the next commit that completes. A second caller waits behind a live owner's request on the same key and deadline, and the next caller drains a dead owner's completion. Nothing spins on the used ring. A kernel without a calibrated TSC cannot build the deadline, so it fails block requests closed with `DeviceFault` and logs `[BLK ] block completion deadlines require a calibrated TSC` (an error the kernel carries on from, so not a `[FAIL]`); self-test lanes that attach the data disk calibrate it.
- Bootstrap compromise: only the dedicated storage service instance receives raw-block authority at launch time. Ordinary userspace processes must not gain raw block access through generic syscalls or IPC.
- Future direction: replace the kernel-hosted bootstrap backend with a restricted driver domain that speaks the same bounded block wire contract so persistent-store code is unchanged.
- A successful `flush` is the only M5 durability guarantee. Callers may assume that writes completed before the flush survive the backend's reboot/crash model only after the flush succeeds; successful writes without a later successful flush are readable but not yet durable.
- The `clean-slate-store` commit point is the successful return from the `flush` issued after the next-generation superblock write. A first `flush` after the payload writes and before the superblock write keeps a write-back cache from persisting the superblock ahead of the payload it references. Because object data for a new generation is written only into the inactive copy-on-write arena and the superblock only into the inactive slot, recovery may expose either the previously committed generation or the new generation, but never metadata from one generation paired with object data from another.
- Deleting an object (`ObjectStore::delete_object`) is staged like a write and applied by the next commit, which writes a superblock with no entry for it. There are no tombstones: the commit's new arena simply has no extent for the deleted payload, and the previous generation, still holding the object, is kept until the commit after. A crash before the commit point therefore leaves the object as last committed; one after leaves it gone. A deleted id and name are free for reuse in the same commit.
- The store assumes a write of one logical block (512 bytes on today's disks) is atomic on power loss: afterwards the block holds either all its old bytes or all its new ones. Each superblock is one block, so every slot write either lands whole or not at all. Under that assumption no crash, including one during the first `format`, leaves a disk that is neither blank (both slots all zero, so it is formatted) nor mountable; `store/tests/fault_matrix.rs` checks this in its honest and sector-atomic modes, the latter also tearing multi-block payload writes at block boundaries. A device that tears inside a block can interrupt the first `format` with a slot holding only a byte prefix of the new superblock. The storage service refuses such a disk as `InterruptedFormat` ("interrupted first format, or corrupt") instead of formatting it, because the same bytes could be what damage left of a real store; deleting the image starts fresh.
- Host crash tests inject deterministic power loss or I/O failure only at counted block write/flush boundaries via `clean_slate_block::fault::FaultInjectingBlockDevice`, covering every boundary between the first object-data write and the commit flush. Recovery must validate superblock magic/version/checksum, geometry, generation, and object extents/lengths before selecting a committed state, and a corrupted newer superblock must fall back to the older valid one.
- Buffer ownership remains synchronous and call-scoped: backends may inspect caller slices only for the duration of `read_blocks`/`write_blocks` and must not retain raw userspace pointers after the call returns. The kernel backend keeps this across its blocking wait: the block syscall does not return until the request completes or fails, write data is copied into the DMA bounce buffer at submission, and read data is copied out of it only by the resumed syscall of the caller that submitted the request. An abandoned or drained completion never touches another caller's buffer.

## M8 ELF load-plan and Linux personality layering

M8 keeps Linux as a compatibility personality above the native kernel. Before the
Linux runtime loader lands (#92), M8.0 establishes one shared load-plan substrate
in `clean-slate-elf`:

- build-time native userspace embedding (`kernel/build.rs`) validates PT_LOAD
  metadata, emits only file-backed bytes, and generates segment tables / mapped-
  page demand;
- kernel `mm::image_loader` maps those segments transactionally with W^X and BSS
  zero-fill (a merged page that would be both writable and executable is a hard
  error; `userspace.ld` page-aligns `.data` away from RX sections so native images
  do not share pages across the W^X boundary);
- #92 should reuse `parse_load_plan` + `map_load_plan_segments` under a Linux
  `LoadPlanPolicy` (accepted `e_type`, auxv/phdr metadata already recorded on
  `LoadPlan`) rather than a second ELF parser.

### Userspace VA window (M9 / #142)

The kernel uses a supervisor direct map at `0xffff_8000_0000_0000` (512 GiB
window) for physical-memory access. The kernel-owned CR3 maps, in the low half,
only the kernel image (identity, W^X per section) and device register pages
mapped on first use (see [M1 virtual memory layout](#m1-virtual-memory-layout)); **process
roots clear all canonical user PML4 slots `[0, 256)`** so every process may map
conventional low Linux VAs (e.g. `0x400000` in slot 0) and legacy M8 window
images at `0x0000_4000_0000_0000` without inheriting the kernel identity map.

`LoadPlanPolicy::linux_conventional_x86_64()` accepts `[0x10000, 1<<47)`; the
frozen M8 fixture remains valid via `LoadPlanPolicy::m8_legacy_slot_x86_64()`.
Process roots attach kernel low carve-outs via shared leaf page tables (fixed
`KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES = 3` per process) rather than inheriting
kernel identity mappings; user availability inside carve-out 2 MiB windows is
blocked at map and pointer-validation time. See [M9_ADDRESS_SPACE.md](M9_ADDRESS_SPACE.md).

Execution personality metadata and Linux syscall/errno/stack contracts are owned
by #91 (`clean-slate-linux-abi`); syscall dispatch routing is #93.

M8.2 (#92) reserves the top of the slot for the Linux user stack: two NX+W
stack pages `[0x0000_407F_FFFF_D000, 0x0000_407F_FFFF_F000)`, an unmapped guard
page below at `0x0000_407F_FFFF_C000`, and the slot's last page
`0x0000_407F_FFFF_F000` left unmapped so the stack top is never the window end.
Any PT_LOAD intersecting `[0x0000_407F_FFFF_C000, 0x0000_4080_0000_0000)` is
rejected (`SegmentOverlapsStackReservation`). See
[LINUX_PERSONALITY.md](LINUX_PERSONALITY.md), "M8.2 — ELF loader and process image".

M9 #146 adds the bounded exec substrate (`LinuxExecSpec`, `prepare_linux_image`,
`commit_exec`) on top of the same loader; M8 hello and production Linux launch share
`launch_linux_process_from_spec`. See [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md),
"M9 #146 — Linux exec / process image substrate". M9 #102 process/fork/wait/pipe:
[LINUX_PERSONALITY.md](LINUX_PERSONALITY.md) "M9 #102 — process / exec / wait / pipe".

M9 #104 pins the BusyBox rootfs as a hash-verified `CSROOTFS` image embedded when
`m9-rootfs` is enabled (`process::linux_rootfs`, `cargo xtask verify-m9-fixture`).
See [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md) "M9 #104 — rootfs fixture" and
[fixtures/busybox/frozen/ROOTFS.md](../fixtures/busybox/frozen/ROOTFS.md).

M9 #101 projects paths onto that image plus M6.3 `/tmp` objects
(`process::linux_fs`, `cargo xtask test-m9-linux-fs`). See
[LINUX_PERSONALITY.md](LINUX_PERSONALITY.md) "M9 #101 — filesystem/path projection".

### Linux personality end-to-end path (#97)

With `m8-linux-hello`, boot Starts `LINUX_HELLO_SERVICE_ID` through
`ServiceLifecycleController` (`BuiltinServiceImage::LinuxHello`): runtime load
(#92) → `LinuxX86_64` process → console grant + stdio projection (#95) → Linux
syscall dispatch (#93) → `write`/`exit` (#94) → production teardown. Both demo
kernel tasks keep running alongside Linux (scheduler slot 2). Controller-owned
re-Start yields a new generation and a fresh fd table. M9 #147 generalizes the
fd table into open descriptions (see [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md)
"#147 fd / open-description core"). M9 #105 adds Linux `socket`/`bind`/`connect`/`sendto`
plus `#147` read/write data plane onto M7 (see [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md)
"M9 #105" and [NETWORK.md](NETWORK.md)). See
[LINUX_PERSONALITY.md](LINUX_PERSONALITY.md) "M8.7".

Demo-task boot completion (`[M2  ] PASS`) treats scheduler slots in
`Empty`/`Reaped`/`Exited` as finished so a reaped Linux slot does not fatal the
tail after the demos exit.

## M7 network layering

M7 introduces `clean-slate-network`, a transport-independent contract between raw NIC backends, the userspace network service, and the protocol stack. VirtIO details stay in the kernel driver lane; applications receive attenuated `ResourceClass::Network` capabilities rather than ambient connectivity. See [NETWORK.md](NETWORK.md) for the ownership map, rights vocabulary, and hermetic fixture contract.

Wave-1 storage boundaries should remain split so parallel lanes avoid shared-file conflicts:

```text
clean-slate-block           shared geometry/read-write/flush/error contract
kernel VirtIO block area    hardware transport implementation
userspace storage service   IPC/service boundary
persistent store crate      dual-superblock object-store policy using only clean-slate-block
host storage test kit       fake/fault backends and crash-model tests
xtask/scripts               QEMU persistence harness
```

## M10 graphics layering

M10 introduces `clean-slate-graphics` (`no_std`, zero-dependency) and `clean-slate-native-abi`: the frozen contract between the kernel display and input mechanism, the userspace compositor, and its clients. The kernel owns every device, queue, BAR and physical address, and exposes only four capability classes (`SharedBuffer`, `Graphics`, `Display`, `Input`). The compositor is an ordinary supervised service and the only holder of `Display` and `Input`. Apps and the shell are compositor clients that render into their own shared buffers and exchange 64-byte protocol frames over a service port; surfaces and windows are connection-scoped compositor objects, not kernel capabilities. See [GRAPHICS.md](GRAPHICS.md) for the authority split, module ownership, process and thread boundaries, lifecycles and the #110 acceptance mapping.

There is one launch policy, and it is init's. Init owns start order and restart. The kernel declares the manifest rows and applies each service's manifest grants at launch; it does not choose which row runs next. The kernel's earlier M10 desktop policy, which launched and relaunched the compositor, desktop shell and app itself, was deleted in #218 S6f.

The bounded service port (#200) is a class-agnostic engine in `clean-slate-port` (`port/`), instantiated once in the kernel (`kernel/src/service/port.rs`) with thin syscall wrappers (`port_syscall.rs`). Clients and servers use syscall 17 (`SYSCALL_NR_SERVICE_PORT`): 64-byte frames, kernel-stamped `TrustedEnvelope` metadata, and optional `SharedBuffer` capability transfer on `SEND` (child installed with `READ` only). Compositors multiplex port readiness (and display and input readiness once #111/#113 bind to them) through syscall 20 work sets (`kernel/src/sched/work_set.rs`, `WORK_SET_CAPACITY` = 8). Blocking uses atomic check-then-block (`block_current_thread_unless`) with absolute monotonic deadlines and `wake_all_registered` (no pending-wake pollution). Process teardown runs port and work-set hooks in the shared P4 order before `revoke_for_holder`; `ResourceSnapshot` records `port_connections`, `ports_served` and `work_sets`. Acceptance: `cargo xtask test-m10-port` (`[M10.port] PASS`). See [GRAPHICS.md](GRAPHICS.md) service-port and work-set ABI sections.

Native memory (#306) is syscall 23 (`SYSCALL_NR_MEMORY`, `native-abi/src/memory.rs`): MAP gives a native process anonymous, zeroed, read-write, never-executable pages at a kernel-chosen or hinted address in its native memory window (`0x6000_0000_0000`, 1 GiB, its own PML4 slot); UNMAP frees any part of them (a partial unmap splits a run); PROTECT switches pages between read-only and read-write; QUERY returns pages in use and the budget. The budget is a page count from the manifest row (`ServiceSpec::memory_pages`, at most 16,384), set by the kernel when it starts the row; a process with none has a budget of 0. `kernel/src/process/native_mem.rs` keeps one record per instance (sorted, coalesced runs, at most 64) and computes every change as a new record before touching the page tables, so a refused call (`EINVAL`, `ENOSPC` past the budget or out of runs, `EEXIST` for a fixed map over a mapped page, `ENOMEM` when the kernel is out of frames) changes nothing. Pages count against the address space's mapping table like every other user page, so the address-space teardown frees whatever is still mapped at exit, once, and drops the record. Acceptance: `cargo xtask test-m10-native-memory` (`[M10.mem] PASS`).

The native clock (#308) is syscall 24 (`SYSCALL_NR_CLOCK`, `native-abi/src/clock.rs`): MONOTONIC returns nanoseconds on the calibrated TSC clock every native deadline is measured on, and WALL returns Unix nanoseconds (UTC) or `STATUS_ENODATA` when the boot has no wall clock. Boot reads UEFI `GetTime` once, last before `ExitBootServices`, together with the TSC (`kernel/src/time/wall.rs`); once the TSC is calibrated the two give the boot epoch, the Unix time at monotonic 0, and WALL is that epoch plus MONOTONIC, so the clocks never drift apart within a boot. It fails closed: a firmware time that is missing, invalid, or earlier than the build floor (`WALL_CLOCK_DEFAULT_FLOOR_UNIX`, 2026-11-26, or the build's `SOURCE_DATE_EPOCH` when later) leaves no wall clock for the whole boot, and the boot log says why (`[TIME] no wall clock: …`). A firmware time with no time zone is read as UTC. `time::wall::wall_clock_ns` is the one kernel source of wall time for the audit log (#219), certificate checks (#221) and Linux `CLOCK_REALTIME` (#222). Programs read it through the runtime's `clock` module (`monotonic`, `wall` → `Option<WallTime>`, with `CivilTime` for the UTC date). Acceptance: `cargo xtask test-m10-clock` (`[M10.clock] lane PASS`).

The native runtime (#307, `clean-slate-runtime`, `runtime/`) is the client side of those contracts, and the one place native programs issue syscalls from. `sys` holds the `syscall` instruction behind a `Syscalls` trait (`Kernel` on target, `fake::FakeKernel` with the `fake` feature on the host). `Error` is the one mapping from a status: `ESTALE` and `EPIPE` are `Gone` (the peer or server has ended), `ETIMEDOUT` is `TimedOut`, `EAGAIN` is `WouldBlock`, and everything else is `Failed(status)`. On top of it: `port` (connections with deadlines and the `Disconnected` and `ServerGone` notices, work sets, the clock), `buffer` (allocate-and-map shared buffers), `compositor` (a tagged-request client that turns a compositor that ended into `Gone`), `console` (console writes, split into 64-byte messages, and `ConsoleStream`, a stream on the console service), `process` (exit, abort, the ready report) and `heap` (a `GlobalAlloc` with 16 to 2048-byte size classes over 16-page chunks from syscall 23, with larger blocks mapped directly). The playground and desktop shell sessions use `clean_slate_runtime::Error` as their `HostError` and run on `CompositorClient`; init, the audit service and the lifecycle transport use its syscalls and console.

The console service (#310, `clean-slate-console`, `console/`; manifest row 0x5600, grants `ConsoleService` and `Console`, no dependencies) owns the serial console for native programs. It serves the console port, a service port of class `ResourceClass::Console` (`CONSOLE_PORT_RESOURCE_ID` 0x5600; a client holds `CONSOLE_CONNECT`, the service `CONSOLE_SERVE`), and holds the only capability on the serial console device (`ResourceRef::serial_console_device()`, `READ` and `WRITE`), which it uses through syscall 25 (`SYSCALL_NR_CONSOLE_DEVICE`, `native-abi/src/console.rs`): `FIND_HANDLE` returns the caller's device handle (`EBADF` when it holds none), `WRITE` writes 1 to 256 bytes (`EINVAL` outside that, `EACCES` on a handle that is not the device or lacks the right), `BIND_INPUT` binds a work-set bit that the kernel signals whenever the line discipline commits a line or an end of input, and `READ_INPUT` takes up to 256 committed bytes (at most one line), returning the count, `CONSOLE_INPUT_END` for a consumed end of input, or `EAGAIN`; both need `READ`. Each port connection is one stream. `WRITE` requests carry up to 62 bytes, and the service writes each line as `pid=N: text` with `N` the pid from the kernel-stamped envelope, so a writer cannot end another writer's line or start one of its own; it drops `\r`, shows other control bytes but `\t` in caret notation, splits a line past 200 bytes with a trailing `\`, and writes a partial line when its writer asks to read or closes, and, still open, once it has drained its port, so a prompt is not held back. `READ` (with a nonblocking flag) answers with input, end of input, or no input. Typed input goes to the oldest waiting `READ` across all streams, and the service takes it from the kernel (`READ_INPUT`) only for a waiting `READ`, so with no reader it stays committed in the line discipline; the kernel keeps line editing and echo. The kernel puts `[CON ] ` (`CONSOLE_LINE_TAG`) at the start of every line the device writes, ending a line another writer left open first; each service write starts a line of its own, and only the kernel's echo of typed input goes on after a line the device left open (the prompt), itself tagged but unlabeled when it starts a line, and no gate marker can be satisfied by text on such a line (`xtask/src/marker_spec.rs`), so nothing a client writes can pass for a kernel or init line. A manifest row holds `ConsoleClient` only on a desktop image or the Linux shell, and only when it depends on the console service row (declared before it); the kernel grants it on launch, naming the live instance's port, as it does for compositor clients. The playground is the first native client.

The serial shell's console output goes through the service too (#310 part 2, `kernel/src/service/console_stream.rs`). The shell row holds `ConsoleClient`, and a forked child inherits the record, so `write` and `writev` on the console fds 1 and 2 of any process in the shell's tree go to a stream the kernel connects lazily as that process: the port engine stamps the pid on every request, so the service labels the text `pid=N: ` and no process can write as another or print an untagged line, and the forge check in `test-system-shell` holds that a printed `[M4  ] PASS` satisfies no marker. A write sends what the stream's queue takes; with nothing sent it waits for room and restarts. `exit` and `exit_group` wait until the service has received everything the process wrote, since the port drops a connection's undelivered requests when its client exits (as a terminal drains output before close). While the service cannot be reached (not yet started, restarting, or out of connections) the kernel writes the text itself, labeled and tagged the same way. `read` on fd 0 goes through the same stream (#310 part 3): the kernel sends a `READ` of up to 62 bytes for the process and blocks on the connection until the answer arrives, returning input (keeping what did not fit for the next read), 0 for end of input, or, on an `O_NONBLOCK` description, `EAGAIN` while the `READ` waits. `poll` on fd 0 sends that `READ` ahead of time and is woken by any event on a kernel-held connection. The service says `[CONS] serial input answered a read` once a boot, the first time typed input answers one. While the service cannot be reached, fd 0 reads the line discipline directly, as before. A restart of the console service does not end the shell: its streams end with `ServerGone`, the kernel writes and reads for it directly meanwhile, and when the new instance is granted its port the kernel replaces the `CONSOLE_CONNECT` record of every Linux process holding one on an earlier generation's port with one on the new port (`[CONS] client reissued holder=N port=22016:P`, `P` naming the new process's instance; `capability::console::reissue_kernel_console_clients`), so the next read or write connects a stream to the new instance. Native clients keep the record they were launched with. Terminal attach and detach come next (#311).

The launcher port (#237, `native-abi/src/launcher.rs`, `supervisor/src/launcher.rs`) is how a native program asks init to start a program. It is a service port of class `ResourceClass::Launcher` (`ResourceRef::launcher_port()`, id `LAUNCHER_PORT_ID` 1, no instance generation: init's death is fatal, so nobody else ever serves it). The kernel registers it when it launches init and writes init's `LAUNCH_SERVE` handle into the bootstrap page (`launcher_capability`); a row with `Grant::LauncherClient` (desktop-shell rows only) gets a root `LAUNCH_CONNECT`. A request names a manifest row by its `launch_name`; there is no exec of a path, and init starts the row with exactly the grants it declares, as at boot. `LIST` is answered with one entry per named row (state `idle`, `starting`, `running`, `restarting` or `down`, the instance generation and pid) and a `LIST_END`; `START` with `started`, `already-running`, `unknown-name`, `busy` (restarting, or a dependency not running yet) or `refused` (init gave up on it or a dependency). Each connected client also gets a `CHANGED` entry whenever a named row's state or instance changes; a client whose event queue is full, or that sends a malformed request, is disconnected. A row may be `Start::OnRequest`: init never starts it at boot, it restarts `Never`, no row may depend on it, and when its instance exits or faults it goes back to idle (`[INIT] service=N exited; starts again on request`) until it is asked for again; boot settles with such rows counted as `idle=N`. Init sleeps in `WORK_SET` `WAIT` alone: `LIFECYCLE_WAIT` op `BIND_WAKE` (`rdx` 1) makes each lifecycle message set one bit of its work set, the port's `BIND_WAKE` sets two more, and after a wake init drains lifecycle messages with non-blocking `LIFECYCLE_WAIT`s and then the port. The kernel's idle evidence (`[KERN] idle thread halted 16 times in a row while init pid=N waited with no deadline`) follows either wait. In this first part the desktop shell lists the rows once it is ready (`[SHELL] launcher listed=N`); the rail starts and switches between them in a later part.

```text
graphics / native-abi        shared contract crates (#110)
runtime                      native client side: syscalls, errors, port/compositor/console clients, heap (#307)
kernel mm shared buffers     SharedBuffer objects and mappings (#195)
kernel service port          connections, work sets, capability transfer (#200)
kernel display backends      GOP (#111) and VirtIO-GPU (#114) behind ScanoutBackend
kernel input                 i8042 driver and raw input queue (#113)
raster / ui                  CPU rendering and UI toolkit (#111, #116)
compositor (+ wm)            composition, focus, window policy (#112, #115)
desktop-shell / playground   clients (#116, #117)
```

The VirtIO 1.x modern PCI transport (#196, `device::virtio::modern`) is the kernel substrate for #114. It matches only modern-only functions (device ID `0x1040 + id`, revision ≥ 1), sizes every BAR, validates the vendor capabilities against their BARs, and fails closed on any region `mm::mmio` will not map as device memory (usable RAM, the local APIC window, an existing kernel mapping). Bring-up follows the virtio 1.2 status sequence, re-reads `FEATURES_OK`, and negotiates `VERSION_1` plus requested device-class bits only. Queues are split virtqueues with 64-bit ring addresses (`device::virtio::virtqueue`) over kernel-static DMA memory. Completion is interrupt driven: MSI-X table entry 0 serves every queue, or INTx acknowledged through the ISR byte on a GSI no other driver has routed. The transport has three states: `Ready`, `ResetRequired` (timeout, ring protocol violation, `DEVICE_NEEDS_RESET`, config generation unstable after four reads) and `Poisoned` (reset stuck, bring-up failed, generation exhausted, interrupt lost). `reset()` resets the device, then brings it up again under a new generation, so every earlier token is stale. Nothing in the transport waits (W4). Each device arms one entry in the bounded kernel timeout registry (`sched::timeout`, W3: 8 slots, `Exhausted` when full) at the earliest in-flight deadline. It cancels that entry when the last completion is harvested, and whenever the device leaves `Ready` for any reason other than the timeout itself. Entries expire from the same timer path as `Deadline::MonotonicNs` waiters, so an idle registry costs one comparison per tick. Expiry moves the device to `ResetRequired`. It never retries.

### Shared-buffer VA window (#195)

Client and compositor pixels live in kernel-allocated **shared buffers** mapped into a dedicated canonical window, separate from each process's private `map_process_page` mappings.

| Field | Value |
|---|---|
| PML4 index | 160 (`WINDOW_PML4_INDEX`; derived from `SHARED_WINDOW_BASE`) |
| Base VA | `0x0000_5000_0000_0000` (`SHARED_WINDOW_BASE`) |
| Slot stride | 16 MiB (`SHARED_WINDOW_SLOT_STRIDE`) |
| Slots per process | 20 (`MAX_SHARED_MAPPINGS_PER_PROCESS`) |
| Window span | base + 20 × stride (fits below the 47-bit user ceiling) |

Each process root that maps shared buffers installs a private PDPT/PD subtree under PML4 slot 160 (not inherited from the kernel half of the root). Rows own only their page-table frames, never buffer backing frames. Directory entries are always `PRESENT | WRITABLE | USER | NO_EXECUTE`; leaf `WRITABLE` is set only for `ReadWrite` mappings. `map_process_page` rejects any private mapping that overlaps the window; `destroy_process_address_space` refuses teardown while slot 160 is still populated (`address-space teardown found a live shared window`). That refusal is a structural invariant backstop, not a recovery path: a refused teardown is kernel-fatal. Step 5 below is what guarantees the slot is empty by then; before it was wired, a native exit with a live window reached `fatal_kernel_error`.

**Process teardown (P4; the step-5 slot comes from W5/#205).** After port/display/input steps and `revoke_for_holder` (step 4), capability reconciliation retargets orphaned reader rows to a shared zero page and queues frame reclaim. **Step 5 (`SharedMappings`, wired by #195):** `release_shared_mappings` calls `mm::shared_buffer::teardown_process`, which removes every window row for the exiting PID (live or orphaned), detaches attachments without freeing buffer frames owned elsewhere, and frees the window's page-table frames. **Step 6:** `destroy_process_address_space` for private pages only. The `test-m10-shared-buffer` lane proves exit, fault (read-only write, shared-window exec) and CAP_REVOKE of the root while mapped all end in step 5 rather than `fatal_kernel_error`.

**TLB model.** Documented at shared-buffer init: single CPU, `CR4.PCIDE=0`, interrupts masked around page-table edits. Non-active roots need no shootdown; edits to the active root reload CR3 before freed page-table frames are reused. Boot logs `[MM  ] shared-buffer tlb model single-cpu no-pcid`. SMP bring-up must replace this with an explicit shootdown protocol.

**NX enforcement.** Boot calls `enable_and_verify_nxe` immediately after `ExitBootServices` and logs `[CPU ] NXE enabled nx=1 firmware_nxe=<0|1>`. Without `EFER.NXE`, `NO_EXECUTE` PTEs would fault as reserved-bit violations instead of instruction-fetch faults; `cargo xtask test-m10-nxe` locks this down before shared-buffer mappings rely on NX leaves.

**Supervisor guards (#217).** Right after NXE, `enable_kernel_guards` sets `CR0.WP` (OVMF usually leaves it set; boot no longer relies on that) and, when CPUID leaf 7 reports them, `CR4.SMEP`, `CR4.SMAP` and `CR4.UMIP`, then reads both registers back. It logs `[CPU ] guards wp=on smep=<on|unsupported> smap=<on|unsupported> umip=<on|unsupported> firmware_wp=<0|1>`. With WP set, a supervisor write to a read-only page faults, so the page-table edits that need one go through `without_write_protect`. SMEP makes a CPL0 instruction fetch from a user page fault; UMIP makes `sgdt`/`sidt`/`sldt`/`smsw`/`str` at CPL3 raise `#GP`. SMAP makes a CPL0 load or store to a user page fault unless `RFLAGS.AC` is set. `kernel/src/mm/user_access.rs` is the only code that touches user memory: `copy_from_user`, `copy_to_user`, `read_user`/`write_user` for `UserPod` types and `copy_cstring_from_user` each validate the range with the page walk, then copy with one `rep movsb` between `stac` and `clac`. The boot records whether SMAP is on once, and the helper and the interrupt entry stub read that flag, so `stac`/`clac` never run on a CPU without SMAP. There is no fault fixup: on one CPU with syscalls running with IF clear, nothing can change the validated mappings before the copy, so a fault in the window is a kernel bug. Interrupt and exception entry runs `clac` (gate delivery keeps `AC`), `SYSCALL` clears `AC` through FMASK, and a context switch resumes through `iretq`/`sysretq` with the target's saved RFLAGS, so `AC` does not leak. A host test rejects raw pointer casts of syscall argument registers anywhere else in `kernel/src`. Every xtask QEMU lane runs a `-cpu` model with `+smep,+smap,+umip`. NMI (IST2) and `#MC` (IST3) have their own guarded IST stacks beside the double-fault one (IST1), because either can arrive between `SYSCALL` and the kernel stack switch. `cargo xtask test-m2` checks all of this in its kernel-guards step.

Syscall-16 ABI, limits, and capability rules: [GRAPHICS.md](GRAPHICS.md#shared-buffers-syscall-16-195).

## Driver description experiment

A long-term research direction is a declarative device description format describing registers, queues, interrupts, DMA structures, reset/power sequences, and protocol semantics.

The OS could compile or interpret this description into a sandboxed driver runtime, with optional optimized native components.

Machine-assisted maintenance could then discover bounded device quirks—such as timing workarounds—inside controlled test environments rather than generating arbitrary privileged kernel code.

## Transactional system state

System components should be immutable/versioned where possible.

An update should produce a new system state rather than mutating the live installation in place:

```text
system version A
       |
       +--> construct version B
                    |
                    +--> health checks
                           |
                    success -> promote B
                    failure -> retain A
```

Application installations should follow the same broad model: immutable package image plus private mutable state plus granted capabilities.

## Repair and supervision

Every important service should expose structured lifecycle and health operations, conceptually including:

```text
health()
restart()
dependencies()
metrics()
diagnostics()
rollback()
```

The supervisor maintains a dependency graph and event history. A failure can therefore be diagnosed progressively rather than treated as an opaque whole-system problem.

Examples of repair actions:

- restart a crashed service;
- revoke a misbehaving capability;
- throttle a runaway domain;
- rollback a component update;
- quarantine a device driver;
- test a candidate repair in a disposable cloned environment;
- promote a repair only after health checks pass.

## M1 virtual memory layout

M1 keeps paging and physical-memory policy inside the kernel. The current kernel-owned layout (`kernel/src/mm/layout.rs`, `kernel/src/mm/kernel_bootstrap.rs`):

- only `EfiConventionalMemory` pages from the post-`ExitBootServices` UEFI map are considered allocator-usable;
- the running kernel image and the current early stack are reserved explicitly before allocator setup;
- the kernel uses the firmware's identity map (`phys + 0`) only while it builds its own root: until `install_kernel_owned_root` switches CR3, page-table frames and allocator metadata are reached at their physical address, and through the direct map afterwards;
- **kernel W^X (#217).** The kernel root is built from nothing; no firmware page table is copied or linked. Its low half maps the kernel image at its identity address in 4 KiB leaves with the permission of the PE section holding each page (`kernel/src/mm/kernel_image.rs`). `lld-link` defines no per-section symbols, so boot reads the section table from the loaded image's headers (`LoadedImage` base): executable sections are RX (`.text`), writable ones RW+NX (`.data`, which holds `.bss`, every kernel stack including the IST stacks, and the stack guard pages until they are unmapped), everything else R+NX (`.rdata`, `.eh_frame`, `.reloc`, the PE headers). Boot fails on a section that is both writable and executable, a section alignment that is not a multiple of 4 KiB (the build uses 4 KiB) or a section outside the image. NX goes on leaves only, so the carve-out contract (no NX on the directory path, `paging::assert_carve_out_directory_path_has_no_nx`) holds and process roots copy the same leaf permissions through the shared carve-out tables. After the root, stack guards, holes and shared tables are in place, boot walks the kernel root and the probe process root and fails unless no leaf is writable and executable through every level, then logs `[MM  ] kernel w^x text=RX rodata=R+NX data=RW+NX image=[…) pages rx=… r=… rw=… inherited=0 wx_leaves=0` (`inherited` counts top-level entries still pointing at a firmware page table). `test-m2`'s kernel-guards step writes to `.text` and `.rdata` (#PF `0x3`) and jumps into `.data` and onto the boot stack (#PF `0x11`). The direct map keeps its supervisor RW+NX alias of the image's frames, so a write through `phys_to_virt` of a text frame is not stopped.
- what the kernel still needs from the firmware's physical address space after `ExitBootServices`, and how it is mapped: no UEFI runtime service is called and no boot-services memory is touched, so neither is mapped. ACPI tables are parsed before `ExitBootServices` (`interrupt::acpi`) and are not mapped afterwards (their frames stay reachable read-write through the direct map if ever needed). Device registers that drivers address physically (the I/O APIC, MSI-X table entries and virtio capability windows) are mapped by `mm::mmio::with_kernel_identity_mmio` on first use, page by page, at their identity address in the kernel root only, RW+NX and uncached (PCD|PWT); the helper refuses usable RAM, the local APIC window and any page already mapped with other permissions, and draws page tables from a 16-frame pool reserved at boot. The local APIC is the RW+NX uncached alias described below; the GOP framebuffer is RW+NX uncached at its direct-map address. Nothing else from firmware's identity map survives: the early UEFI stack, the firmware's page tables and the memory-map buffer stay reserved from the allocator but are unmapped;
- a direct physical map at `0xffff_8000_0000_0000` (PML4 slot 256, 512 GiB, write-back) is shared by every process root (slots >= 256 are copied from the kernel root);
- device apertures such as the GOP framebuffer are excluded from the write-back physmap bootstrap, and mapped 4 KiB uncached at their direct-map address (`phys_to_virt`) where a scanout write path is built. The kernel root has no identity alias of the aperture;
- three holes are kept in the kernel root (`kernel/src/mm/identity_holes.rs`, #253). Process roots inherit them because their low shared tables and every kernel-half PML4 entry are copied from the kernel root. The first is the null page `[0x0, 0x1000)`. Nothing uses physical page 0 after `ExitBootServices`: the allocator starts at `0x1000`, the physmap skips frame 0, the kernel calls no UEFI runtime service, has no real-mode trampoline, and finds ACPI through the UEFI configuration table. Since the W^X root maps no identity RAM at all, the null page and the APIC window are holes because nothing maps them; `arm_identity_holes` still unmaps and verifies them so a later mapping change cannot reopen them silently. The second is the local APIC's 2 MiB identity window, `[0xfee0_0000, 0xff00_0000)` under QEMU. The third is the same window's direct-map image, `[0xffff_8000_fee0_0000, 0xffff_8000_ff00_0000)`, so a corrupted frame number or page-table entry passed through `phys_to_virt` cannot reach the APIC either. The windows are removed because QEMU treats a store to APIC offset 0, or anywhere in the 1 MiB APIC space outside the register page, as an MSI whose data is the stored value. A stray kernel store there could therefore deliver an INIT and reset the CPU without a trace.
- the kernel reaches the APIC only through a 4 KiB uncached alias at `LOCAL_APIC_ALIAS_VA = 0xffff_c000_0000_0000`, the base of PML4 slot 384 (`KERNEL_DEVICE_ALIAS_SLOT_BASE`). That slot is outside the direct map, and it is mapped in the kernel root before any process root exists, so every root shares it. `phys_to_virt` reaches it only for a physical address of at least 2^46 (64 TiB). Boot reads MAXPHYADDR from CPUID `0x8000_0008` (36 bits if the leaf is absent) and fails unless every physical address the CPU can form is below that bound, so no frame of this machine converts to the alias. A value that is not a frame at all, at or above 2^MAXPHYADDR, could still wrap there; the holes do not guard against that. All three holes and the alias are checked at boot in the kernel root and in the probe process root that `verify_carve_out_attach_at_boot` builds, and `test-m9-low-va` checks them in a launched process's root. A kernel page fault in any hole prints `[FAIL] kernel page fault in identity hole=<null-page|local-apic-window|local-apic-direct-map> cr2=…` and exits QEMU with failure. `map_device_aperture_uncached` refuses an aperture that touches the APIC's 2 MiB window, because arming the direct-map hole would silently unmap it.
- **The kernel stays in the low half (owner decision, #217).** The image runs where UEFI loaded it, identity-mapped in the user half, and process roots reach it through the low carve-outs. Moving it to the high half (and with it KASLR, a normal per-CPU layout and dropping the carve-out machinery) is deferred until SMP or KASLR is wanted; stages A-C of #217 (supervisor guards, SMAP with the user-copy helper, and kernel W^X) deliver the guard rails without it.

`KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE` at `0xffff_a000_0000_0000` remains an unmapped diagnostic slot for deliberate fault probes.

## M2 interrupt and scheduling direction

M2 extends the kernel beyond the M1 page-fault-only path with a reusable IDT/exception foundation, a post-`ExitBootServices` timer source, and a minimal preemptive scheduler.

Keep interrupt entry/exit stubs, timer acknowledgement, and context-restore assembly narrowly scoped to the x86-64 architectural boundary. Task state, run-queue policy, and completion bookkeeping should remain ordinary Rust data structures so they can evolve independently of the interrupt ABI details.

Single-core correctness is the M2 target, but the design should not bake `current task` or timer ownership into a single global scheduling policy forever. The intended SMP shape is:

- **Per-CPU execution state:** each CPU owns its active interrupt stack, double-fault, NMI and machine-check IST stacks, GDT/TSS entries, current-task pointer, interrupt-disabled bookkeeping, and local run-queue cursor.
- **Shared task metadata:** task identity, saved register context, runnable/blocked/finished state, affinity or migration hints, and wakeup reasons stay in globally visible task records.
- **Synchronization boundary:** CPU-local fast paths may read/write only their currently owned task without contention; transitions that change runnable ownership, wake a remote CPU, or publish a newly created task cross an atomic/spinlock boundary.
- **Local APIC access:** every LAPIC register access (`arch/x86_64/apic.rs`: enable, EOI, timer programming and calibration, `send_self_ipi`) goes through the uncached alias described in [M1 virtual memory layout](#m1-virtual-memory-layout). An access before the alias is installed is a fatal kernel error, not a fallback to the identity address. The LAPIC's identity window is unmapped, so a stray store to it faults and names itself instead of reaching the APIC.
- **Interrupt and timer ownership:** timer acknowledgement stays CPU-local because LAPIC timer interrupts are delivered and acknowledged per CPU. M2 programs only the bootstrap processor timer, but the later SMP step should let each CPU own its local timer tick source without changing task context layout.
- **Cross-CPU wakeups:** a CPU that makes a task runnable for another CPU should enqueue or flag that task in shared state and then use an inter-processor interrupt to prompt rescheduling on the destination CPU.
- **AP startup ownership:** the bootstrap processor remains responsible for global scheduler/bootstrap initialization and for publishing per-CPU scheduler state before application processors start accepting timer interrupts.
- **Runnable ownership invariant:** at any moment a runnable task is owned by exactly one CPU run queue or by a shared handoff state during migration, never by two CPUs simultaneously.

That division keeps the M2 task model reusable when SMP arrives: only ownership and synchronization mechanics need to expand, not the saved-context format or the interrupt ABI.

## M3.1 userspace-entry direction

The first M3.1 step should keep privilege-transition code narrow and x86-64 specific. Extend the existing GDT/TSS only enough to add ring-3 code/data selectors and an `rsp0` privilege stack, then construct a single explicit `iretq` frame for a small purpose-built userspace payload.

That initial path should prove the CPU boundary itself before broader process or capability policy exists: the kernel owns the userspace code/stack mappings, marks them explicitly `USER_ACCESSIBLE`, returns through a controlled DPL3 gate only for test bring-up, and treats a ring-3 privileged-instruction fault as a first-class diagnostic rather than a hang or triple fault.

## M3.2 per-process address-space direction

The next M3 step should give each userspace process its own page-table root while preserving the kernel mappings required for controlled entry, exceptions, and teardown. Those inherited kernel mappings must remain supervisor-only, and user code/data/stack pages must be mapped explicitly with `USER_ACCESSIBLE` only inside the owning process root.

CR3 switching and page-table construction should stay behind narrow memory-management helpers rather than spreading raw register handling into scheduler or process policy. A bounded self-test should prove that two processes can use the same user virtual address for different private frames, that ring 3 cannot read kernel-private mappings, and that process-owned page-table frames and user frames are reclaimed deterministically during teardown.

## M3.3 native syscall boundary direction

M3.3 uses the x86-64 `syscall/sysretq` mechanism (not Linux ABI) as the first native userspace/kernel call boundary. Linux ABI dispatch is a separate process personality; see [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md).

- `IA32_STAR`, `IA32_LSTAR`, `IA32_FMASK`, and `IA32_EFER.SCE` are initialized before the first userspace syscall; boot also enables `IA32_EFER.NXE` on the BSP so `NO_EXECUTE` page-table bits are enforced (each additional core must set NXE and SCE before activating the kernel page tables).
- The GDT SYSRET selector triplet is ordered deliberately as `base`, `base+8` (user data/SS), `base+16` (user code/CS) so STAR-derived selectors are valid in normal builds.
- `IA32_FMASK` masks unsafe userspace flags on entry (`IF`, `DF`, `TF`, `IOPL`, `NT`, `RF`, `AC`) so Rust kernel code does not inherit user-controlled execution flags.
- The syscall entry stub immediately switches from untrusted userspace `RSP` to a trusted kernel stack before calling Rust.
- The entry/save frame preserves userspace `RIP` (`RCX`), `RSP`, and `RFLAGS` (`R11`) so `sysretq` can restore userspace deterministically.
- Return validation rejects non-canonical or non-userspace return `RIP`/`RSP` before `sysretq`.

The initial ABI is intentionally tiny and versioned for M3 testing:

- `rax=0` → ABI version (`1`)
- `rax=1` → validated userspace-pointer read of a `u64` (`rdi=ptr`, `rsi=len`)
- `rax=2` → self-test completion probe (`0` until criteria are met)
- unknown syscall numbers return deterministic `-ENOSYS`

If syscall caller resolution fails at the gate (trusted scheduler/registry/CR3
path), dispatch does not fall back to native: the kernel logs a bounded
`[SYSC] unresolved caller … fail-closed` diagnostic and contains the current
userspace process via production teardown (see [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md) #93).

This keeps assembly/unsafe logic isolated in the x86-64 boundary while exposing only a narrowly auditable contract for early userspace validation.

## M3.4 process/thread lifecycle direction

M3.4 separates process ownership from thread scheduling state:

- `Process` owns address-space root identity and a resource-domain container ID.
- `Thread` owns schedulable CPU context (`saved_stack_pointer`, launch entry) and kernel-stack identity.
- Scheduler run-queue decisions operate on `Thread` state (`Ready`/`Running`/`Blocked`/`Exited`) without conflating ownership (`owner_process_id`) with dispatch policy. Native blocking/wake (`sched/wait.rs`, #145) registers bounded waiters keyed by trusted process identity plus an opaque `WaitKey`; see [M9_BLOCK_WAKE.md](M9_BLOCK_WAKE.md).
- Linux runtime/memory/time/poll (#103): calibrated tick rate (`kernel/src/time/`), brk/mmap policy (`M9_ADDRESS_SPACE.md`), handlers in `syscall/linux/runtime.rs`; see [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md#m9-103--runtime--memory--time--poll--signals-state).

PID/TID assignment is monotonic and non-reusing for the life of a boot session. On userspace faults, ownership-aware diagnostics identify the faulting PID and the kernel transitions that process/thread through faulted → exited → reaped cleanup while preserving kernel control flow and unrelated runnable work.

**User processes cannot stop the kernel (#215).** `fatal_kernel_error` is for kernel invariants only. Anything derived from a user register or user memory, and any outcome a user process can cause, fails that process instead: an errno, or the CPL3 fault teardown (a bad RSP or RIP at `syscall` entry is a user-mode #GP). A `fatal_kernel_error` on a syscall or user-fault path carries a comment saying why user mode cannot reach it. When the last user thread exits or faults and nothing is blocked, the kernel logs `[KERN] no runnable thread remained after …; idling` and runs the idle thread, which keeps taking interrupts; it does not halt. In builds that launch init that cannot happen while init lives, and init's own death stays fatal by design.

## M3.5 initial capability-authorized IPC direction

The first IPC primitive should keep policy narrow and explicit:

- kernel-owned endpoint objects have explicit create/teardown lifecycle;
- kernel-owned endpoints may expose a narrow sink kind (for M3, a console/test sink) while keeping dispatch policy explicit and non-ambient;
- send permission is represented by an endpoint capability handle bound to one PID;
- syscall-side handle lookup validates slot, generation, and endpoint identity so stale handles cannot silently name reused objects;
- bounded message length and userspace pointer-range checks happen before any kernel dereference/copy;
- endpoint teardown revokes outstanding capabilities by generation, making later sends fail deterministically even if a slot is later reused for a new sink instance.

This initial implementation uses copying and intentionally defers shared-memory/zero-copy optimization to later milestones.

Syscall 3 (`SYSCALL_NR_IPC_SEND`) is native console output and nothing else (#220): init, the services, the compositor, the desktop shell and native apps write their `[IPC ] console pid=N: …` lines through it, and messages between processes go through the service port (syscall 17). It accepts a handle only if the endpoint the handle names (slot and generation) is a live console sink, and it checks that before the sender's capability. Any other handle is `EBADF`, including one naming a console sink that has been torn down. The kernel records the first 8 such refusals of a boot as `[IPC ] console write refused pid=N handle=…: not the console sink`, followed by one line saying later refusals are not logged: any native process can make the call, and serial output runs with interrupts masked. A live console sink's handle that the caller does not hold is `EACCES`, and the caller's capability revoked while the sink lives is `ESTALE`.

The Linux console write (`write(2)` on a console descriptor) checks in a different order: the caller's `IpcEndpoint` write right first (`EACCES`), then that the descriptor's endpoint is live (`EBADF`) and a console sink (`EBADF`). It records nothing.

Mailbox endpoints, and kernel delivery to them, compile only into the `m3-resources-self-test` and `m4-crash-service-self-test` builds, which use them to account for per-process IPC resources. Every other build, the system kernel included, has console sinks only.

At boot, init calls syscall 3 with its lifecycle handle, and `test-system-boot` requires the kernel's refusal record for init's pid. That handle (`0x200000000010000`) carries the lifecycle-control family tag, not the IPC one (see *Handle families* below), so the lane shows that the default image refuses a handle of another family with `EBADF` before it reads any of the handle's fields. Before #288 the same handle was `0x10000`, which decoded as init's own console capability and was refused only because its endpoint-generation field happened to be 0. The lane also fails if the probe text reaches serial, but only as a regression guard. Refusing a live endpoint of another kind is covered by the kernel host tests alone.

## M4.1 service lifecycle protocol direction

M4.1 defines the shared contract between the userspace supervisor, supervised services, and the kernel lifecycle-control path before implementation lanes fan out. The canonical types and wire encoding live in the workspace crate `clean-slate-service-lifecycle` (`service-lifecycle/`).

Ownership boundaries:

- **Kernel (M4.2+):** authoritative process spawn/teardown, capability-gated control IPC, and emission of lifecycle events tied to real PIDs/domains.
- **Supervisor (M4.3+):** service registry, dependency-aware orchestration, and translation between policy and control requests — but not reinterpretation of stale instance identity. The first implementation lives in `clean-slate-supervisor` (`supervisor/`): bounded `ServiceRegistry`, `Supervisor` runtime, `[SUP ]` diagnostics, and a narrow `LifecycleControl` transport (fake/scripted backends for host and QEMU tests; kernel IPC in #36).
- **Services / fixtures (M4.7+):** report `Ready`, health, and fault/exit events for their own instance generation only.

Model highlights:

- `ServiceId` is the stable logical identity; `ServiceInstanceId` binds `(service, generation, pid, domain)` so replacements never reuse stale instance handles silently.
- Lifecycle states are explicit (`Declared`, `Starting`, `Running`, `Stopping`, `Exited`, `Faulted`, `RestartPending`) with deterministic transition validation (`apply_transition` / `ServiceLifecycleRecord`).
- Control requests (`Start`, `Stop`, `Terminate`, `Restart`) are policy-free envelopes; restart backoff and dependency evaluation stay in later milestones.
- Wire messages are versioned (`LIFECYCLE_PROTOCOL_VERSION = 1`), bounded to 64 bytes (matching M3 IPC), and reject unknown versions/kinds before interpretation.
- `HealthReport` and `DependencyMetadata` provide stable extension fields for M4.4/M4.5 without embedding their algorithms here.

## M4.4 service health/liveness direction

M4.4 adds supervisor-side liveness tracking in `service-lifecycle` (`health_tracker`, `time`) without restart policy (#40). Dependency evaluation is M4.5 (#39).

- Health reports use the M4.1 `LifecycleMessage::HealthReport` envelope over explicit IPC.
- `ServiceHealthRecord` / `ServiceHealthTracker` track the active `InstanceGeneration`, last valid report, and a finite `deadline_ticks` derived from `LivenessConfig::report_period_ticks`.
- `MonotonicTicks` is an opaque `u64` in `tick_period_ns` units. The M4 recovery bootstrap feeds it calibrated TSC time (`time::monotonic_period_ticks()`), not a count of delivered LAPIC IRQs. Deadlines use saturating tick arithmetic only.
- Stale-generation reports are ignored and cannot refresh a replacement instance's deadline.
- `notify_lifecycle_failure` maps `Exited` / `Faulted` lifecycle events to immediate unhealthy state with distinct reasons (`exit`, `fault`, `timeout`, `self_reported`).
- `HealthFailureEvent` and `HealthReportOutcome` are narrow integration surfaces for the M4.3 supervisor (#37); they do not encode restart actions.

## M4.5 service dependency evaluation direction

M4.5 adds supervisor-owned, in-memory dependency metadata and deterministic start-readiness evaluation in `clean-slate-service-lifecycle` (`dependency_graph` module). The kernel does not interpret dependency graphs.

- **Supervisor (#37):** declares services in `DependencyGraph`, attaches bounded `DependencyMetadata` per logical `ServiceId`, and calls `evaluate_start_readiness` before issuing start side effects.
- **Evaluation inputs:** current lifecycle snapshots from `ServiceLifecycleTracker` plus optional `DependencyHealthSnapshot` (unhealthy upstream blocks even when lifecycle is `Running`; timeout policy remains M4.4).
- **Validation:** unknown dependency targets, self-dependencies, duplicate edges, inline edge overflow, and cycles are rejected at `set_dependencies` time.
- **Identity:** dependency keys are always logical `ServiceId`; PIDs and instance generations are never dependency identifiers.

Suggested serial diagnostics (`format_health_*_line`, `format_dependency_*_line`, `format_declared_line`, `format_instance_line`):

```text
[HLTH] service=<id> healthy gen=<n>
[HLTH] service=<id> unhealthy reason=<timeout|exit|fault|self_reported>
[DEP ] service=<id> blocked-by=<dep>
[DEP ] service=<id> ready
[SVC ] declared service=<id>
[SVC ] instance service=<id> pid=<pid> gen=<n>
[SVC ] launch service=<id> pid=<pid> gen=<n>
[SVC ] terminate service=<id> pid=<pid>
[SVC ] reaped service=<id> pid=<pid> residue=<owned objects left>
```

M4.2 adds kernel-owned lifecycle control:

- a dedicated **lifecycle-control capability** (distinct from IPC send capabilities) authorizes `SYSCALL_NR_LIFECYCLE_CONTROL` (4) and bounded M4.1 wire control requests. Each one is scoped to a list of services (#220): control requests and polls for a service outside it are refused (`EACCES`), and the lifecycle wait sees only in-scope messages. Init's scope is exactly its manifest rows, which `launch_init` checks at boot;
- authorized **Start** / **Terminate** / **Restart** requests spawn or tear down built-in service images through production M3 process/domain APIs and `teardown_process_by_id` (#24 coordinator path);
- **Restart** is terminate-then-launch with a bumped `InstanceGeneration` and monotonic PID allocation (IDs are never reused);
- stale instance handles fail through generation checks in the controller and `SYSCALL_ESTALE`.

## M6.1 capability model

M6.1 defines the shared capability contract in workspace crate `clean-slate-capability` (`capability/`). Later milestones implement the kernel table, adapters, delegation protocol, revocation graph, and audit sink; this section fixes vocabulary and invariants only.

### Vocabulary

- **Handle** (`CapabilityHandle`): opaque slot + generation presented by userspace. Knowing a raw handle value is not authority until the kernel validates it against the live table record.

### Handle families (#288)

Four kernel tables hand out handles, and the top byte of every handle names the table it belongs to. Each decoder refuses a handle with another family's tag, or with any bit set that its layout does not use, before it reads a slot or generation. So a handle from one table can never be read as a record of another, even when the two records sit in the same slot with the same generation.

| Family | Tag (bits 56..64) | Layout below the tag | Refused as |
|---|---|---|---|
| Capability table (`CapabilityHandle`) | `0x00` | `slot:16 \| generation:32`; bits 48..64 zero | `EINVAL` (`InvalidHandle`) |
| IPC console send (syscall 3) | `0x01` | `cap_slot:16 \| cap_gen:16 \| ep_slot:8 \| ep_gen:16` | `EBADF` (not the console sink) |
| Lifecycle control | `0x02` | `slot:16 \| generation:16`; bits 32..56 zero | `InvalidHandle` |
| Block device | `0x03` | `slot:16 \| generation:16`; bits 32..56 zero | `InvalidHandle` |

The capability table already refused bits 48..64, so its handles did not change. No tag sets bit 63, so no handle falls in the native status range. Handles stay opaque to userspace: programs pass back the value the kernel gave them and never build one. The tags are defined in `kernel/src/capability/handle_family.rs`.
- **Resource** (`ResourceRef`): stable identity of the protected object or control target (class, id, optional instance generation). Separate from handle identity — the same resource may have many capabilities over time in different slots.
- **Holder** (`HolderId`): trusted process identity for who may exercise a capability. Supplied only by the kernel from the current process context, never from an untrusted syscall argument.

### Invariants

- Knowing a PID or object id is **not** authority; only a matching live capability grants access.
- Caller-supplied identity is never trusted for authorization decisions.
- Rights only **shrink** across delegation (`attenuate` / subset checks); widening is rejected.
- When generation advancement reaches `u32::MAX`, the slot moves to **Retired** and is never reused.
- Resource ownership (e.g. which process created an object) is distinct from capability ownership (who holds delegable rights).
- Boot-local authority: root grants originate from the kernel bootstrap path (`HolderId::KERNEL` / trusted grant syscalls), not from userspace self-assertion.

### Revocation model (M6.6 implements the graph)

- **Revoking a capability** revokes its entire **delegation subtree**: every descendant linked via `Provenance.parent` chains is revoked. Siblings and ancestors are unaffected.
- **Holder exit** revokes every capability that lists the exiting holder, and therefore each holder’s delegation subtrees.
- **Resource destruction** revokes every capability whose `ResourceRef` matches (class, id, and instance generation when applicable).
- Revocation is **idempotent**; repeating revoke on an already-revoked slot is a no-op aside from audit.
- A revoked slot keeps its generation, holder, resource, and provenance (rights are cleared) until it is **released**, so the original handle deterministically reports `Revoked` and revocation code can still walk descendants. Releasing the slot back to `Empty` **bumps the generation**, so previously issued handles report `StaleHandle` even if the slot is later reused for a different resource (`Retired` slots, whose generation is exhausted, are never reused).

### M6.6 revocation and teardown

Implementation lives in `capability/src/revocation.rs` (generic graph) and `kernel/src/capability/revocation.rs` (syscall). The kernel teardown hooks (`revoke_for_holder`, `revoke_for_process_resource`, `revoke_for_resource`) call `revoke_holder_tree` / `revoke_resource_tree`, which revoke matching capabilities **and their delegation subtrees**, then **release** slots held by the exiting holder or destroyed resource so capacity is reclaimed. Descendant capabilities delegated to *other* holders are revoked but **not** released until those holders observe `Revoked` or a later lazy reclaim.

**Subtree algorithm:** bounded iterative closure over live slots (no recursion, no allocation): seed the target slot, repeatedly add live slots whose `provenance.parent` equals the handle of a slot already in the set (up to `MAX_DELEGATION_DEPTH` passes), then `revoke_slot` each member. Already-revoked members contribute count 0 (idempotent).

**Revoke-then-lazy-release:** `revoke_subtree` only marks slots `Revoked`; `release_revoked` returns them to `Empty` and bumps generation. `grant_root` calls `release_revoked` once on `CapacityExhausted` and retries so stale holders still see `Revoked` until the kernel needs the slot.

**Per-holder quota (#220):** the table has `MAX_SLOTS` (128) slots and no holder may occupy more than `HOLDER_SLOT_QUOTA` (16) of them; `HolderId::KERNEL` is exempt. The holder a record names is charged for it: a delegated record is charged to the receiver, a fork child to itself. A `Revoked` slot is charged until it is released, so at the quota the table first releases that holder's own revoked slots and, if it is still at the quota, refuses with `CapabilityError::QuotaExceeded` (`ENOSPC`; a fork refused for it fails with `EAGAIN`), audited like any other denial. The charge is not a separate counter: `CapabilityTable::charged_to` counts the holder's `Live` and `Revoked` slots, so teardown's `revoke_for_holder` (which releases the holder's revoked slots) returns the whole charge, and `HeldAuthority::revoked_records` lets the S8a teardown guard see any that remain. A fork that fails after copying records revokes and releases every copy (#212).

**Manifest slot allowances (#220):** a row of init's launch manifest may carry `slot_allowance`, a larger quota for each instance of that row. The kernel sets it for the instance's pid when it starts the row, before the row's grants (`CapabilityTable::set_slot_allowance`), and teardown's `revoke_for_holder` clears it. No syscall sets or raises one, and a fork child or a delegate is charged against its own default quota. An allowance must be above `HOLDER_SLOT_QUOTA` and at most `MAX_SLOT_ALLOWANCE` (32), and a manifest's allowances together may not exceed `MAX_SLOTS`. `validate_manifest` refuses either, in a `const` assertion for every built-in manifest and again in `launch_init`, which fails boot. The table refuses the same cases. The `[SVC ] authority` line shows `allowance=<n>` (0 for the default), the launch audit record (a `grant` from the kernel naming the launched process) carries it in `count`, and the instance's authority must match its row. Only the compositor has one:

| Service | Worst case charged to the pid | Allowance |
|---|---|---|
| init | console endpoint record (lifecycle control is in its own table): 1 | default (16) |
| storage | object-service role (the block device is in the lifecycle table): 1 | default |
| network | network-service record: 1 | default |
| serial shell (Linux) and each fork | console endpoint, network-client entitlement and client, `LINUX_TMP_MAX_FILES` (4) `/tmp` objects: 7 | default |
| compositor | 4 launch records, `MAX_REGISTERED_BUFFERS` (16) transferred buffer records, 4 registrations in flight past that limit: 24 | `COMPOSITOR_SLOT_ALLOWANCE` = 24 |
| desktop shell | console, `GFX_SHELL` role, `MAX_SHARED_BUFFERS_PER_OWNER` (8) owned buffers: 10 | default |
| playground app | console, `GFX_CONNECT` role, 8 owned buffers: 10 | default |

`COMPOSITOR_SLOT_ALLOWANCE` is computed from `graphics::limits::MAX_REGISTERED_BUFFERS` and the compositor row's grant count, so a change to either moves it.

**Who may revoke:** the holder of the target capability, or any holder of an ancestor capability (walk `provenance.parent` via `authorize_revoke`). Userspace uses `SYSCALL_NR_CAP_REVOKE` op `REVOKE` (subtree revoke); unauthorized attempts log `[CAP ] revoke denied`.

**PROBE:** `SYSCALL_NR_CAP_REVOKE` op `PROBE` runs the same `authorize_current_class` path as production operations (handle → record class → rights check). Used by fixtures and audit tests as a generic authority probe.

**DROP (#200):** `SYSCALL_NR_CAP_REVOKE` op `DROP` (5; 3 and 4 stay reserved for the M6.6 self-test kernel) with `rsi = handle` releases exactly the caller's own record: the slot returns to `Empty` with a bumped generation, so a repeat or reused handle is `ESTALE`. It never touches another holder, the parent or the owner. Statuses: `0`, `EINVAL` (malformed or never issued), `ESTALE`, `EACCES` (caller is not the holder — an ancestor must use `REVOKE`), `EAGAIN` (a live child was delegated from it, or it is the authority of the caller's Live shared-window row). DROP refuses rather than unmapping: the caller `UNMAP`s first, as for owner `RELEASE`. A record an ancestor already revoked can be dropped to reclaim its slot. Dropping an unmapped, undelegated `SharedBuffer` root retires the buffer as `RELEASE` would.

**Deferred:** distributed/persistent revocation (revocation lists surviving reboot), and rollback of mistaken revokes.

### Module ownership (M6.2–M6.7)

| Milestone | Owner |
|-----------|--------|
| M6.2 | Production capability table in `kernel/src/capability/` |
| M6.3 | Persistent-object adapter (`service-fixtures` / `store` userspace) |
| M6.4 | Process-control adapter in `kernel/src/capability/process_control.rs` |
| M6.5 | Delegation protocol |
| M6.6 | Revocation graph |
| M6.7 | Audit sink |
| M6.9 | Milestone gate (`cargo xtask test-m6`) |
| Legacy | `kernel/src/service/capability.rs` and `kernel/src/ipc` endpoint tables — migrate into the unified model |

### Capability substrate migration map (M6.2)

- **Production substrate (M6.2):** `kernel/src/capability/` — global `CapabilityTable<MAX_SLOTS>`, trusted `current_holder()` from scheduler context, and teardown hooks that revoke holder- and process-resource capabilities. **New M6 protected operations must use this module** (not ad-hoc tables).
- **Legacy IPC endpoint send capabilities:** `kernel/src/ipc` — per-endpoint capability table predating M6; kept until M6.8 migration re-homes grants onto the unified table.
- **Legacy lifecycle-control and block-device capabilities:** `kernel/src/service/capability.rs` — service-spawn grants for supervisor fixtures; kept until M6.8.

No new semantics were added to the legacy paths in M6.2; they remain **bounded migration debt** tracked for a future cutover (not performed in M6.8 — see below).

### M6.8 capability convergence (integration)

M6.8 is a single bounded QEMU constituent (`cargo xtask test-m6-capabilities`) that exercises the **production** M6 substrate in one boot: M5 object-service storage path, `SYSCALL_NR_CAP_OBJECT` / `CAP_DELEGATE` / `CAP_REVOKE` / `CAP_PROCESS_CONTROL` / `CAP_AUDIT_READ`, bootstrap grants, revocation on subtree and process teardown, and serial audit echo. Scripted CPL3 fixtures (`m6_fixture_userspace`) play owner, reader, unrelated, controller, target, auditor, and intruder roles; the kernel registers grants and orchestrates lifecycle only through existing `grant_*` / `register_bootstrap_grant` helpers.

The acceptance log order is enforced by blocking handshakes, not timing. The M6 self-test harness (fixture pids only, under `SYSCALL_NR_CAP_GRANT` subops `0x100..=0x103`) provides a turn counter (`WAIT_TURN n` blocks until turn `n`; `END_TURN n` advances to `n + 1` and wakes waiters), `WAIT_EXIT pid` (blocks until that process has left the registry; woken by every fixture teardown), and `PARK` (blocks for the rest of the test). Fixtures carry no spin steps or poll retries; a fixture step that returns an unexpected value reports `MISMATCH` with the offending step, and the host fails fast on any guest `[FAIL]` line or on a PASS line printed before earlier ordered markers.

**Explicit deferred debt (document only):** legacy per-endpoint IPC send capabilities (`kernel/src/ipc`), lifecycle/block tables in `kernel/src/service/capability.rs`, and M3/M4/M5 service-spawn capability paths are **not** migrated onto the unified `kernel/src/capability/` table in M6.8; they continue to serve their original milestones until a later adapter cutover.

### M6.9 capability-control milestone gate

Authoritative M6 acceptance is `cargo xtask test-m6` (aliases `m6`, `m6.9`): host capability crate and kernel `capability` module tests, then ordered QEMU constituents through M6.8 convergence, ending with `[M6  ] PASS`. See `docs/DEVELOPMENT.md` for constituent order, markers, and debugging flow.

### M6.5 delegation and attenuation

Delegation creates a new capability record for a target holder with a **subset** of the parent’s rights. The kernel path is: resolve the parent record, [`validate_delegation`](../../capability/src/authorize.rs) (parent must hold `DELEGATE`; no widening; class-valid bits only), [`Provenance::child_of`](../../capability/src/provenance.rs) (bounded depth, parent handle stored for M6.6 subtree revocation), then a single transactional [`CapabilityTable::install`](../../capability/src/table.rs). The delegator is always the trusted current holder; target PIDs are validated against the live process registry. **Transfer to the recipient** uses the same bounded bootstrap-grant table as root grants: after a successful `SYSCALL_NR_CAP_DELEGATE`, the kernel registers the new handle for `SYSCALL_NR_CAP_GRANT` claim by the target. Rights never widen; depth is capped at `MAX_DELEGATION_DEPTH` (4 hops below root). Deferred: user-facing sharing UI, cross-machine delegation, and persistent capability state across reboot.

### M6.3 persistent object capability surface

Persistent **object identity** (numeric object id) is separate from **authority** (a `PersistentObject` capability naming that id with a rights subset). Client processes never receive raw block-device authority; they submit bounded read/write requests through `SYSCALL_NR_CAP_OBJECT` while the kernel authorizes the caller’s capability against the requested object id, copies payloads into a fixed-depth request queue, and exposes a **service-role** capability (`ResourceRef::object(OBJECT_SERVICE_ROLE_ID)` with `INSPECT`) only to the userspace storage service. That service dequeues work with `OBJECT_SUBOP_SERVICE_NEXT`, which blocks on the object-service work key (`0x47 << 56`, no deadline, `BlockedResume::RestartSyscall`) while no request is pending; every submit (native and the Linux `/tmp` projection) and the requeue after a service exit wake it, and the restarted syscall dequeues the request. The storage service loop (`store/src/bin/userspace.rs`) no longer polls `SERVICE_NEXT` / `VERSION` on an empty queue: an empty return is an invariant violation and ends the service with an error. The service then performs `ObjectStore` operations over the existing block-capability path, and completes requests back through the same syscall. Each slot carries a monotonic `request_id` (generation per submission); `service_complete` matches on that id **and** `InService` state so completions after client reclaim or id reuse fail with `EINVAL` without touching another client’s slot. A client `OBJECT_SUBOP_POLL` of a still-pending request **blocks** on that request’s wait key until `service_complete` wakes it or the caller’s deadline passes (`r8`: absolute `WORK_SET` `NOW` nanoseconds; `OBJECT_POLL_NO_DEADLINE` = 0 waits for completion). On a wake it restarts and returns the completion; on expiry, or at once for a deadline that has already passed, it returns `ETIMEDOUT` and leaves the request queued for a later poll. The deadline is absolute, so restarting the blocked syscall does not extend it. It never returns `OBJECT_STATUS_PENDING` to native callers (the Linux `/tmp` projection blocks on the same key, without a deadline). `service_complete` wakes the key only if a waiter is registered and records no pending wake: every poll re-checks the queue before it blocks, within one masked syscall, and a record nothing consumes would leak a slot of the bounded pending-wake table.

**Native offset ops (#312).** `OBJECT_SUBOP_SUBMIT` keeps the whole-object ops (`READ`, `WRITE`, `DELETE`); it has no register left for an offset. `OBJECT_SUBOP_SUBMIT_AT` (6) takes the capability handle in `rsi` and a 64-byte `ObjectSubmitAt` descriptor (`clean-slate-native-abi::object`) at `rdx`, length in `r10`: op, object id, offset, length, data pointer, shared-buffer handle and the offset in that buffer. It takes `READ_AT` (`READ`; at most 512 bytes), `WRITE_AT` and `TRUNCATE` (`WRITE`; staged, not durable) and `COMMIT` (7, `WRITE`; commits every staged change in the store, other holders' too, since the store has one commit point). Rights and the capability's object epoch are checked exactly as for `SUBMIT`; the storage service applies the live-byte budget (`NO_SPACE`) and the epoch check (`STALE`) in `clean_slate_store::service::serve`, the same code the Linux `/home` broker's requests run through. A failed `SUBMIT_AT` request polls as a native status (`ENOENT`, `ENOSPC`, `ESTALE`, `EFBIG`, `EIO`), never as a small number that could be a read length; `SUBMIT`'s requests keep the raw object status. **Shared-buffer payloads (#312).** With a shared-buffer handle in the descriptor, a `READ_AT` or `WRITE_AT` moves up to 128 KiB (`OBJECT_MAX_BUFFER_PAYLOAD_BYTES`) between the object and the caller's buffer instead of 512 bytes through the request frame: a write needs `READ` on the buffer and a read `WRITE`, and the range must lie inside it. The kernel pins the buffer at submit (`mm::shared_buffer::object_io`), so its frames outlive a release or exit of the client until the request completes or is reclaimed. The storage service passes a staging area of its own to `SERVICE_NEXT` (`r10`, `r8`); for a staged write (`ObjectServiceRequest::flags = OBJECT_REQUEST_STAGED`) the kernel copies the client's bytes there before returning the request, and for a staged read the service completes with up to the request's length of bytes, which the kernel copies into the client's buffer. A staged request polls its byte count and copies nothing to the poll's output. Requeue after a service exit keeps the pin; client reclaim releases it. The runtime's `storage::Object` wraps both forms: `read_at` and `write_at` (any length, in 512-byte requests), `read_into` and `write_from` (through a shared buffer, in 128 KiB requests: a 1 MiB object is eight), `truncate` and `commit`.

**Directory capability (#312).** A directory is a name table object `D` and up to 15 entry objects `D + 1 + slot` after it (`clean-slate-native-abi::directory`): a 512-byte table of each live slot's name (1 to 27 bytes) and length, in the `/home` format (magic `CSHOME01`). A `PersistentObject` capability on `D` with `Rights::DIRECTORY` authorises its `READ` and `WRITE` on every entry object as well as the table, so one capability covers the directory; the kernel checks only that rule (`object_epoch` for a native `SUBMIT_AT`, `authorize_holder_directory_op` for the Linux broker), and entry requests are not bound to an epoch. The table is managed by its client: the runtime's `storage::Directory` reads it afresh on each call and has `open`, `create`, `set_len`, `rename` and `unlink`, each of which ends by writing the table with `WRITE_AT` and committing, so names, lengths and the entries' staged bytes become durable together. Unlink and the target of a rename empty the entry's object (it stays in the store, empty, until its slot is reused). The Linux `/home` broker is a client of the same model: its table type is `DirectoryTable`, its files are the table's entry objects, and its `TmpObjects` grant carries `DIRECTORY` on the table. Known gaps: two writers to one directory are not ordered beyond the storage queue, and a table that does not decode is refused (`EIO`), never repaired. `test-m10-storage` runs a native app (`storage-probe/`) through all of it across three reboots. This interface (`SUBMIT_AT`, its ops and statuses, the buffer rules and the directory table format) is what native apps store files through until a filesystem milestone replaces the table; changes to it are ABI changes.

**Ops and epochs (#224).** `OBJECT_OP_READ` needs `READ`; `OBJECT_OP_WRITE` and `OBJECT_OP_DELETE` need `WRITE`, since deleting an object changes it as much as rewriting it. The storage service commits a write or delete before completing it, so `OBJECT_STATUS_OK` means the change is durable. It names each object `o` plus its id in hex. Every request carries the authorizing capability's `instance_generation` as an object epoch (`ObjectServiceRequest::epoch`). A non-zero epoch binds the capability to one incarnation of the object: when the object is gone, or was deleted and re-created under the same id (which gives it a new, larger epoch; see M5 storage layering), the service answers `OBJECT_STATUS_STALE` (4) and does not create, read or delete anything. An epoch of 0 (`OBJECT_EPOCH_UNBOUND`) reaches whatever object has the id now. Every grant minted today is unbound, including the manifest and `/tmp` grants: binding needs an op that returns the epoch of the object it creates, so the kernel can mint a capability for it, and that belongs to the writable filesystem milestone. The service's heap is a free-list allocator (`store::heap`), so memory each request and commit uses is reused rather than exhausting a bump heap.

Process teardown (normal or fault) reclaims every queue slot whose `client` matches the exiting holder (`Pending`, `InService`, or unpollled `Done`), preventing fixed-slot exhaustion when clients exit without polling. When the exiting holder still holds a live object **service-role** capability (the same `INSPECT` grant used to authorize `service_next`), any `InService` slots are **requeued to `Pending`** so a replacement storage-service instance can dequeue them; payloads remain kernel-buffered and whole-object read/write operations are retried idempotently at the store layer. Storage-service **restart** issues a new holder PID and a fresh role grant; stale role handles from a prior instance do not authorize. Explicitly deferred: paths/VFS, directories, POSIX permissions, mmap, and persistent process capabilities.

### M6.7 capability audit events

Security decisions emit fixed **64-byte** `AuditEvent` records: `sequence`, `timestamp_ns` (monotonic; 0 before the TSC is calibrated), `kind` (`authorize`, `grant`, `delegate`, `revoke`, `drop`, `inherit`, or `lost`), trusted `actor` (`HolderId::KERNEL` for kernel grants and revocations), `subject` (the holder a grant, delegation, revocation or inheritance lands on), resource class/id, requested rights, wire handle, `AuditOutcome` (allowed, denied with a capability error, or refused with a `PolicyRefusal`), delegation `depth`, and `count` (records revoked or inherited). **No payloads or secrets** are stored. The bounded kernel ring (`BoundedAuditLog<N>`, 64 records, kept in sequence order) is the **sole authority for `sequence`** (starts at 1, contiguous). A new record is always stored. Each record is charged to one holder (`AuditEvent::charged_holder`: the actor, or the subject when the kernel acted, so a grant or teardown revocation counts against the holder it lands on); a holder already holding `AUDIT_HOLDER_BUDGET` (16) records loses its **own** oldest, otherwise a full ring drops the **oldest** record overall, and either way `dropped` increments — authorization outcomes are unaffected. A holder flooding the ring therefore cannot push out another holder's records once it is at its budget (#219). Audit records are history, not authority, so teardown does not remove them; pids are never reused, so no later process is charged for them. **Merging:** an allowed `authorize` identical, but for sequence, time and count, to the same holder's newest record is merged into it when no reader has been handed that record yet (`SYSCALL_NR_CAP_AUDIT_READ` marks what it returned); the record's `count` becomes the number of uses (2, 3, …, saturating, after which a new record starts). The exception is a read of the log itself (`Audit` class, `AUDIT_READ`): it merges into its holder's newest identical record even after that record was handed over, so a reader polling an idle log holds one record and consumes no sequences rather than storing a record per poll for the next poll to read. Nothing an auditor needs is hidden: the reader's first read stays a record, the grant that gave it the capability is recorded, a refused read or any other use still stores a new record, and only the count of a reader's own repeated successful reads goes unreported to that reader, which made them. A merge consumes no sequence and no space, and a denial or different use in between ends the run. Loss is never silent: a read returns an in-band `lost` record (`sequence` = first missing, `resource_id` = how many) in place of every run of sequences the ring no longer holds, so a reader that follows sequences always knows what it missed. Every kernel function that reaches the capability space, the lifecycle/block tables or the port engine records its decision or names why it decides nothing; the `audit_coverage` host test enforces that by scanning `kernel/src`. **Reading** the log requires an `Audit` class capability (`Rights::AUDIT_READ`) via `SYSCALL_NR_CAP_AUDIT_READ` (12); unauthorized reads are denied and audited like any other authorization. Optional serial echo of `Audit`-class records formats lines as `[AUD ] seq=… kind=… actor=… class=… resource=… op=… outcome=… depth=…[ subject=…][ count=…] t=…` for self-tests. **Reader service** (#219 stage B): the default manifest's audit service (0x5500, grants `AuditReader` and `Console`, no dependencies; `supervisor/src/bin/audit.rs`, decoding in `supervisor/src/audit_reader.rs`) holds the system's only `AUDIT_READ` capability. It drains the log from sequence 1, eight records per read, once a second, never moves its cursor back, and prints each denied or refused record (`[ADT ] #S WHO OUTCOME [KIND] CLASS`, with fixed short names so that a record fits one 64-byte console message while its sequence, actor and subject stay below 10^10) and each `lost` run as an `[ADT ]` console line, plus a `drained through=… records=… lost=…` summary after its first drain and after any drain that printed something; a gap in sequences with no `lost` record is a `[ADT ] FAIL`. It reports ready after its first drain, and the kernel's ready line for it carries the log's own read cursor (`audit-read-through`), so a lane can check the service really read what it says. The cursor is held by the service alone: a restarted instance drains again from sequence 1, so records still in the ring are printed twice (recognisable by their sequence), and the ready-line cross-check is exact only for the first instance. Stage D (#219) persists the cursor. The manifest allows at most one row to hold `AuditReader`. Deferred (#219): tamper-evident persistence, wall-clock time, repair-engine (M18) correlation, and operator viewer UI.

The audit service's record lines (`[ADT ] #S WHO OUTCOME [KIND] CLASS`; `WHO` is `A`, `A>H`, `A>kernel`, `kernel>H` or `kernel`) use these short names, so that a record fits one 64-byte console message with a sequence, actor and subject of up to 10 digits each. An unknown byte prints as `deny<n>`, `rfsd<n>` or `tag<n>` (outcome), `k<n>` (kind) or `c<n>` (class).

| Short name | Meaning | Short name | Meaning |
|---|---|---|---|
| `invalid` | denied: `CapabilityError::InvalidHandle` | `staletgt` | refused: `PolicyRefusal::StaleTarget` |
| `stale` | denied: `StaleHandle` | `selfterm` | refused: `SelfTerminate` |
| `revoked` | denied: `Revoked` | `notlive` | refused: `TargetNotLive` |
| `wronghld` | denied: `UnauthorizedHolder` | `badreq` | refused: `InvalidRequest` |
| `wrongres` | denied: `WrongResource` | `mismatch` | refused: `AuthorityMismatch` |
| `noright` | denied: `MissingRight` | `unavail` | refused: `Unavailable` |
| `badright` | denied: `InvalidRights` | `busy` | refused: `Busy` |
| `widening` | denied: `RightsWidening` | `allowed` | allowed (not printed by the service) |
| `depth` | denied: `DelegationDepthExceeded` | `grant` | kind `AuditKind::Grant` |
| `capacity` | denied: `CapacityExhausted` | `deleg` | kind `Delegate` |
| `genexh` | denied: `GenerationExhausted` | `revoke` | kind `Revoke` |
| `nodeleg` | denied: `NotDelegable` | `drop` | kind `Drop` |
| `quota` | denied: `QuotaExceeded` | `fork` | kind `Inherit` |
| `object` | class `ResourceClass::PersistentObject` | `lost` | kind `Lost` (`authorize` is not named) |
| `process` | class `ProcessControl` | `net` | class `Network` |
| `ipc` | class `IpcEndpoint` | `buffer` | class `SharedBuffer` |
| `block` | class `BlockDevice` | `gfx` | class `Graphics` |
| `svcctl` | class `LifecycleControl` | `display` | class `Display` |
| `audit` | class `Audit` | `input` | class `Input` |
| `console` | class `Console` | | |

### M6.4 process/domain control capabilities

**Process-control** capabilities (`ResourceClass::ProcessControl`, `ResourceRef::process(pid, instance_generation)`) authorize bounded supervision of another live process: `OBSERVE` fills a fixed 32-byte `ProcessObservation` (pid, generation, coarse state, thread count — no memory or register access); `TERMINATE` drives the same **`teardown_process_by_id`** path M4 lifecycle **Terminate** uses (external force-exit, domain resource release, capability revocation for the target). Authorization always uses the **trusted current holder** from scheduler context, never a syscall-supplied PID; the target pid and **instance generation** come only from the capability record and must match a **live registry entry** and that entry's process instance generation exactly (#220). `grant_process_control` binds the target's live generation, so a record never authorizes a later process that reuses the pid, and a record bound to generation 0 matches no live process. Missing rights, wrong holder, and invalid handles map to the shared `CapabilityError` syscall statuses; stale targets (gone, or another incarnation) return `SYSCALL_ESTALE`. Self-terminate is rejected; `OBSERVE` reports the live generation. Trusted launch policy registers grants through `grant_process_control` plus the bootstrap-claim table (`SYSCALL_NR_CAP_GRANT`). Deferred: signals, debugger attach, and scheduler policy overrides.

## Language strategy

The kernel and first-party low-level services should primarily use Rust.

Unsafe Rust and assembly should be concentrated at hardware and ABI boundaries. Most policy, scheduling logic, IPC, capabilities, service orchestration, and userspace code should remain safe Rust wherever practical.

Assembly is expected for narrowly defined x86-64 boundaries such as interrupt stubs, syscall entry, context switching, CPU bootstrap, and special register transitions.
