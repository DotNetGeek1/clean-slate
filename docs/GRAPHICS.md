# M10 graphics contract

This document is the frozen M10 graphics, surface, input and window contract (#110). The Wave 1–5 lanes (#195, #111–#119, #196, #197 and the service-port issue, referred to below as **#200**) build against it.

The code is authoritative. Offsets, constants and error codes live in three crates; this document summarises them and records the rules that are not visible in a type signature:

| Crate | Path | Contents |
|---|---|---|
| `clean-slate-graphics` | `graphics/` | geometry, pixels, reference mode, ids, limits, 64-byte protocol codecs, display/input ABI wire types, raw input records, and the reference state machines (roles, surfaces, buffers, windows, input trackers, object tables, connection admission, `FakeDisplay`) |
| `clean-slate-native-abi` | `native-abi/` | `SharedBufferId`, `SharedBufferAccess`, #195 memory limits and syscall-16 wire types; port and work-set ABI (`port.rs`, `work_set.rs`, `status.rs`, #200) |
| `clean-slate-capability` | `capability/` | `ResourceClass`, `Rights`, `ResourceRef` constructors, delegation checks, syscall numbers and status sentinels |
| `clean-slate-raster` | `raster/` | CPU rasterizer and bootstrap text over `clean-slate-graphics` buffer layouts; Spleen 8x16 vendored under BSD-2-Clause. The kernel depends on it (GOP RGBX conversion, framebuffer lane), so it must stay `no_std`, `forbid(unsafe_code)` and allocation-free, with `clean-slate-graphics` as its only dependency |

Items marked **(planned)** are fixed in shape but not implemented; their owning lane implements them without changing this contract. Everything else is landed and host-tested (`cargo xtask test-m10-contract`).

## Layering and authority split

```text
 apps (playground, ...)        shell (desktop-shell)
 Graphics{GFX_CONNECT}         Graphics{GFX_CONNECT|GFX_SHELL}   (root grant)
 own SharedBuffers (R/W)       own SharedBuffers (R/W)
        |  64-byte frames + SharedBuffer transfer over the service port (#200)
        v
 compositor (userspace, single-threaded; contains the #115 wm module)
 Graphics{GFX_SERVE}   Display{DISPLAY_PRESENT|INSPECT}   Input{INPUT_CONSUME|INSPECT}
 SharedBuffer{READ} child per registered client buffer
        |  syscall 18 DISPLAY (present from kernel-owned scanout buffers)
        |  syscall 19 INPUT   (drain normalised raw input)
        v
 kernel (mechanism only)
 shared-buffer objects and mappings (#195), service port and work sets (#200),
 ScanoutBackend: GOP (#111) | VirtIO-GPU (#114), VirtIO modern transport (#196),
 i8042 driver and RawInputQueue (#113), launch policy and grants (P5), teardown hooks (P4)
```

**Kernel.** Owns every device, the scanout aperture, GPU BARs and MMIO, VirtIO queues, IRQs, DMA memory and physical addresses. In M10 the display backend is kernel-resident behind a `ScanoutBackend` trait (planned), the same bootstrap compromise M5 made for block; a later driver domain must be able to speak the same contract unchanged. The kernel knows nothing about surfaces, windows, z-order, focus, decorations or layout.

**Compositor.** An ordinary CPL3 service under supervisor lifecycle (#112). It holds the only `Display` and `Input` capabilities, is the only holder of `GFX_SERVE`, and owns composition and window policy (#115 `wm` module). It sees scanout only as two kernel-owned buffers mapped into its address space; it never sees the aperture, a BAR, a queue or a physical address.

**Shell and apps.** Ordinary compositor clients. They render into shared buffers they own and hand the compositor a read-only view through `RegisterBuffer`. The shell differs from an app only by the root-granted `GFX_SHELL` right, which unlocks the `Background` and `ShellPanel` roles.

**What apps never get:** the raw framebuffer or aperture; GPU BARs or MMIO; VirtIO queues or descriptors; physical addresses or frame numbers; a scanout buffer mapping; `Display` or `Input` capabilities; `GFX_SHELL`, `GFX_OVERLAY` or `GFX_SERVE`; any id that resolves outside their own connection.

**Input consumer.** In M10 the compositor drains the kernel raw input queue directly. There is no separate input service. The vocabulary leaves room for one later (it would hold `Input{INPUT_CONSUME}` and speak to the compositor) without a protocol change.

## Process and thread boundaries

Native processes are single-threaded in M10. Each process runs one event loop that blocks; nothing spins or polls.

```text
compositor: WAIT_WORK(mask) -> port notices -> requests -> raw input (READ_BATCH until 0)
            -> route -> latch + composite damage -> DISPLAY PRESENT -> post events -> loop
client:     PORT_RECV_EVENT (blocks) -> handle -> maybe render + commit -> loop
kernel:     IRQ handlers enqueue and signal work-set bits only
```

`WAIT_WORK` (syscall 20 `WORK_SET WAIT`), `PORT_RECV_EVENT` (syscall 17) and the work-set bits are landed in #200. Display and input syscalls never block (see [Display ABI](#display-abi-syscall-18)).

Process boundaries:

- one compositor process; one shell process; one process per app;
- the display backend, input driver, port and shared-buffer mechanism are kernel code, not processes;
- a compositor restart gives every client `ServerGone` (#200); clients exit and are relaunched by supervisor policy. There is no transparent reconnection, and old `Graphics` capabilities are stale (`ResourceRef::graphics` binds the compositor instance generation).

## Module ownership

Wave order follows #109. A lane may start when every issue it depends on has merged.

| Wave | Issue | Owns |
|---|---|---|
| 0 | #110 | `graphics/` (whole crate); `native-abi/` skeleton; M10 classes, rights and syscall reservations in `capability/`; `cargo xtask test-m10-contract`; this document |
| 1 | #195 | **Core landed:** `native-abi/src/shared_buffer.rs`; `kernel/src/mm/shared_buffer/` (object table, per-process window, syscall 16, kernel-owned buffers W7); process teardown step 5 (`SharedMappings` — drop every window row before private address-space destroy); `EFER.NXE` at boot; gates `test-m10-nxe` and `test-m10-shared-buffer`. **(planned)** Transfer attestation W6 (`attest_for_transfer`) exists host-tested only (`cfg(test)`) until a port SEND consumes it (#211) |
| 1 | #200 | port and work-set ABI in `native-abi` (`port.rs`, `work_set.rs`, `status.rs`); class-agnostic port engine in `port/` (`clean-slate-port`, feature `fake` for host tests); `kernel/src/service/port.rs`, `kernel/src/service/port_syscall.rs`, `kernel/src/sched/work_set.rs`; syscalls 17 and 20; capability transfer on send; gate `test-m10-port` |
| 1 | #111 | **Landed:** GOP framebuffer backend at 1280x800 Xrgb8888 (BGRX; RGBX converted at present-copy), aperture excluded from the write-back direct map and mapped uncached (UC) where the write path is built (WC via PAT deferred, P10 limitation; the inherited firmware identity alias is covered in ARCHITECTURE.md "M1 virtual memory layout"); `raster/` (`clean-slate-raster`, kernel dependency by design); `kernel/src/boot/gop.rs`; `kernel/src/device/display/{mod.rs, gop.rs}`; syscall 18 `FIND_HANDLE` / `QUERY_MODE` / `PRESENT_STATUS` live (`MAP_SCANOUT` / `PRESENT` `ENOSYS` until #195 S6; `BIND_WAKE` `ENOSYS` until a later #111 stage wires it to the #200 work sets); missing GOP/mode => no backend (`ENODEV`), boot continues; gate `cargo xtask test-m10-framebuffer` (`-vga std`) |
| 1 | #113 | `kernel/src/device/input/{mod.rs, i8042.rs}`; `kernel/src/service/input_syscall.rs`; syscall 19; scancode to HID usage table in `graphics::input` (all planned) |
| 1 | #196 | `kernel/src/device/virtio/{modern.rs, modern/, virtqueue.rs, dma.rs}`; `kernel/src/sched/timeout.rs` (W3); `cargo xtask test-m10-virtio-modern` |
| 1 | #197 | `xtask/src/qmp/` (QMP endpoint, client, input and screendump helpers, PPM to PNG, marker-paced script driver); `AcceptanceDriver` hooks in `xtask/src/main.rs`; gate `test-qmp-smoke` |
| 1–3 | #116 | `ui/` (`clean-slate-ui`), `desktop-shell/`, `docs/design/DESIGN-SYSTEM.md` (planned). Token and documentation work may start in Wave 1 |
| 2 | #112 | `compositor/` (`clean-slate-compositor`); P5 launch policy, grant policy (`kernel/src/capability/graphics.rs`) and sizing (planned) |
| 2 | #114 | `kernel/src/device/display/virtio_gpu.rs`; gate `test-m10-virtio-gpu` (planned) |
| 3 | #115 | `compositor::wm` (planned) |
| 3 | #117 | `playground/` (`clean-slate-playground`) (planned) |
| 4 | #118 | integration; P4 teardown ordering and `ResourceSnapshot` counters in `kernel/src/process/domain.rs`; gate `test-m10-desktop` (planned) |
| 5 | #119 | `cargo xtask test-m10` and `[M10 ] PASS` (planned) |

`graphics` has no dependencies at all, including dev-dependencies, so the kernel, every userspace binary and xtask can depend on it. `native-abi` depends on `capability` and uses `graphics` only as a dev-dependency for cross-crate checks; production `native-abi` never depends on `graphics`, and no graphics type may appear in the port ABI.

## Capability classes and rights

The kernel gains exactly four capability classes. Surfaces, windows and client buffer registrations are **not** kernel capabilities: they are compositor-minted, connection-scoped protocol objects (see [Identities](#identities-and-generations)). This keeps window policy out of the kernel and keeps per-frame objects out of the single global 64-slot capability table.

Authoritative source: `capability/src/{resource,rights,authorize,error}.rs`.

| `ResourceClass` | Value | `Rights::valid_for` | `ResourceRef` constructor |
|---|---|---|---|
| `SharedBuffer` | 8 | `READ \| WRITE \| DELEGATE \| REVOKE` | `shared_buffer(raw)`: `id` = full `SharedBufferId` encoding (slot and generation), `instance_generation = 0` |
| `Graphics` | 9 | `GFX_CONNECT \| GFX_SHELL \| GFX_OVERLAY \| GFX_SERVE \| DELEGATE \| REVOKE` | `graphics(service_id, instance_generation)`: the compositor service id and live instance, stale after restart (as `network`) |
| `Display` | 10 | `DISPLAY_PRESENT \| INSPECT` | `display(output_index)`: `id` = output index, `instance_generation = 0` (S10) |
| `Input` | 11 | `INPUT_CONSUME \| INSPECT` | `input(seat)`: `id` = seat index (0 in M10), `instance_generation = 0` |

`revoke_resource_tree` matches class and id only and ignores `instance_generation`. Reincarnation is encoded in `id` (`SharedBuffer`), or in `instance_generation` (`Network`, `Graphics`). `Display` and `Input` name a stable physical slot in `id` only; the display backend epoch is not part of the capability resource (S10).

| Right | Bit | Meaning |
|---|---|---|
| `GFX_CONNECT` | `1 << 14` | open a compositor connection; `Toplevel` and `Popup` roles |
| `GFX_SHELL` | `1 << 15` | `Background` and `ShellPanel` roles; reserved for global window tokens |
| `GFX_OVERLAY` | `1 << 16` | `SystemOverlay` role; **no holder in M10** |
| `GFX_SERVE` | `1 << 17` | serve the compositor port (receive, post, disconnect) |
| `DISPLAY_PRESENT` | `1 << 18` | map scanout buffers, present, query mode |
| `INPUT_CONSUME` | `1 << 19` | drain the normalised raw input queue |

**Root-only rights.** `Rights::root_only_for(Graphics)` is `GFX_SHELL | GFX_OVERLAY | GFX_SERVE`; every other class returns the empty set. `validate_delegation` refuses any request whose rights intersect that mask with `CapabilityError::NotDelegable` (`EACCES`), even when the parent holds them. A delegated `Graphics` capability therefore carries at most `GFX_CONNECT | DELEGATE | REVOKE`, and role authority cannot be laundered through delegation.

**SharedBuffer delegation.** `Rights::root_only_for(SharedBuffer)` is `WRITE | DELEGATE | REVOKE`. The owner's root grant is `READ | WRITE | DELEGATE | REVOKE`; every delegated child is `READ` only (`shared_buffer_delegation_allows_only_read_children`). `validate_delegation` enforces this on every delegation path. Fork capability inheritance (#203) is out of scope; a Linux `fork` duplicate cannot widen rights.

**Display authority (S10).** `ResourceRef::display(i)` names physical output `i`. The backend epoch lives only in wire `OutputId` values (`PresentRequest`, `PresentStatus`, `DisplayModeInfo`); `PresentRequest::validate` returns `StaleEpoch` when the caller's epoch does not match the kernel's current output. Revoking display id `i` drops every capability for that output index, independent of epoch.

**No `DELEGATE` for Display and Input.** `DELEGATE` is outside `valid_for(Display)` and `valid_for(Input)`, so a grant that includes it fails with `InvalidRights`, and no holder can ever delegate either class. They are structurally non-delegable.

**Role-bit mirrors.** `graphics` cannot depend on `capability`, so `graphics::role` mirrors the three role bits as `GFX_CONNECT_BIT`, `GFX_SHELL_BIT` and `GFX_OVERLAY_BIT`. `native-abi` cross-checks them against `Rights` (module `graphics_role_crosscheck`, e.g. `graphics_role_bit_mirrors_equal_capability_rights`).

**Grant and transfer policy (P2 landed in #200; P5 in #112/#118 planned).**

- A port transfer of a `SharedBuffer` capability installs a child for the server holder with `READ` only. The sender must hold `DELEGATE`. The kernel rolls the child back if the enqueue fails.
- `Display` and `Input` are granted only to the live compositor PID.
- The two scanout buffers are owned by the kernel and reach the presenter only through `MAP_SCANOUT`, never through a transferable `SharedBuffer` capability.
- Launch-policy service ids: compositor `0x5300`, desktop shell `0x5301`, playground `0x5302`, denial fixture `0x5303`.

| Holder (M10 desktop) | Capabilities |
|---|---|
| kernel (`HolderId::KERNEL`) | root of every grant; owner of the scanout buffers and of the `Display` and `Input` resources |
| compositor | `Graphics{GFX_SERVE}`; `Display{DISPLAY_PRESENT \| INSPECT}`; `Input{INPUT_CONSUME \| INSPECT}`; one `SharedBuffer{READ}` child per registered client buffer |
| shell | `Graphics{GFX_CONNECT \| GFX_SHELL}` (root grant); owner capabilities for its own buffers |
| apps | `Graphics{GFX_CONNECT}`; owner capabilities for their own buffers |

Shared-buffer allocation is ambient but bounded by a per-owner quota (#195); sharing is the capability-controlled act.

## Reserved syscalls

Numbers are reserved in `clean_slate_capability::syscall_abi` and aliased in `native-abi`. Each row gives that syscall's status on this tree; an unimplemented number returns `SYSCALL_ENOSYS` (`u64::MAX - 37`) for every subop. Status sentinels live in `native-abi/src/status.rs`.

| Number | Constant | Owner | Status |
|---|---|---|---|
| 16 | `SYSCALL_NR_SHARED_BUFFER` | #195 | implemented for the native personality (Linux-personality callers never reach it): subops 1-5 ([Shared buffers](#shared-buffers-syscall-16-195)); 0 and 6.. `EINVAL` |
| 17 | `SYSCALL_NR_SERVICE_PORT` | #200 | implemented: subops 1–9 ([Service port ABI](#service-port-abi-syscall-17)); 0 and 10.. → `EINVAL` |
| 18 | `SYSCALL_NR_DISPLAY` | #111, #114 | subops 1, 2, 5 (`FIND_HANDLE`, `QUERY_MODE`, `PRESENT_STATUS`) implemented; 3, 4 (`MAP_SCANOUT`, `PRESENT`) `ENOSYS` until #195 S6; 6 (`BIND_WAKE`) `ENOSYS` until a later #111 stage wires it to the #200 work sets; 0 and 7.. `EINVAL`; subops frozen in `graphics::abi::display` |
| 19 | `SYSCALL_NR_INPUT` | #113 | `ENOSYS` for every subop; subops frozen in `graphics::abi::input` |
| 20 | `SYSCALL_NR_WORK_SET` | #200 | implemented: subops 1–4 ([Work set ABI](#work-set-abi-syscall-20)); 0 and 5.. → `EINVAL` |

Subop numbers belong to `native-abi` (16, 17, 20) and `graphics::abi` (18, 19), never to `service-fixtures`.

## Service port ABI (syscall 17)

Authoritative: `native-abi/src/port.rs`, `native-abi/src/status.rs`. Port state machine: `clean-slate-port` (`port/`); kernel glue: `kernel/src/service/port.rs`, `kernel/src/service/port_syscall.rs`.

Register convention: `rax = 17`, `rdi = subop`; `rsi` = capability handle for capability-authorised subops, or flags on the connection data path (`SEND`, `RECV_EVENT`); arguments in `rdx`, `r10`, `r8`, `r9`; result in `rax`. Deadlines are absolute monotonic nanoseconds (`0` = none). A nonzero deadline requires a calibrated clock, otherwise `EINVAL`. `NONBLOCK` combined with a deadline gives `EINVAL`. Nonzero unused registers give `EINVAL`.

| # | Subop | `rsi` | `rdx` | `r10` | `r8` | `r9` | Success |
|---|---|---|---|---|---|---|---|
| 0 | reserved | — | — | — | — | — | `EINVAL` |
| 1 | `FIND_HANDLE` | 0 | class (`u8`) | resource id | role: `PORT_ROLE_CONNECT` (1) or `PORT_ROLE_SERVE` (2) | 0 | handle raw |
| 2 | `CONNECT` | client cap | class | resource id | 0 | 0 | `ConnectionId` raw |
| 3 | `SEND` | flags: bit 0 `PORT_SEND_WAIT` | conn | frame ptr (64 B) | transfer handle or 0 | deadline | 0 |
| 4 | `RECV_EVENT` | flags: bit 0 `PORT_RECV_NONBLOCK` | conn | out ptr | out len (80) | deadline | `EventKind` (1–3) |
| 5 | `CLOSE` | 0 | conn | reason (`u32`) | 0 | 0 | 0 |
| 6 | `RECV` | serve cap | out ptr | out len (152) | flags: bit 0 `PORT_RECV_NONBLOCK` | deadline | `RecvKind` (1–4) |
| 7 | `POST` | serve cap | conn | frame ptr | 0 | 0 | 0 |
| 8 | `DISCONNECT` | serve cap | conn | reason (`u32`) | 0 | 0 | 0 |
| 9 | `BIND_WAKE` | serve cap | work-set id | request bit (0..=31) | notice bit (0..=31) | 0 | 0 |
| 10.. | reserved | — | — | — | — | — | `EINVAL` |

`TrustedEnvelope` (80 bytes), `PortRecvRecord` (152 bytes) and `PortEventRecord` (80 bytes) use explicit little-endian `encode`/`decode` with the offsets documented on the types in `native-abi/src/port.rs` (no `repr(C)` transmute). The kernel stamps every envelope field; frame bytes are opaque.

| Name | Value | Used for |
|---|---|---|
| `STATUS_EACCES` | `u64::MAX - 12` | wrong resource, missing right, wrong holder |
| `STATUS_EINVAL` | `u64::MAX - 21` | bad subop, flags, pointer, length or class |
| `STATUS_ENOSPC` | `u64::MAX - 28` | connection or transfer limits; capability table full |
| `STATUS_ENOSYS` | `u64::MAX - 37` | unchanged |
| `STATUS_EAGAIN` | `u64::MAX - 10` | queue full or nothing pending with `NONBLOCK` |
| `STATUS_EEXIST` | `u64::MAX - 16` | second `WORK_SET CREATE` by the same holder |
| `STATUS_EPIPE` | `u64::MAX - 31` | peer closed |
| `STATUS_ETIMEDOUT` | `u64::MAX - 109` | deadline expiry |
| `STATUS_ECONNREFUSED` | `u64::MAX - 110` | no live port for `(class, id)` |
| `STATUS_ESTALE` | `u64::MAX - 116` | stale connection, capability or work set |

`u64::MAX - 15` is the network pending value and is never returned as a port status. Success values are at most 2^48 or a small kind, so they never fall in `STATUS_RANGE_START` (`u64::MAX - 4095`).

ABI maxima (`PORT_MAX_*`, `PortParams::validate`) and `port_rights_for` are in `native-abi/src/port.rs`. Blocking uses `block_current_thread_unless` with `RestartSyscall` and absolute deadlines; port wakes use `wake_all_registered` (never the pending-wake table).

## Work set ABI (syscall 20)

Authoritative: `native-abi/src/work_set.rs`. Kernel table: `kernel/src/sched/work_set.rs` (`WORK_SET_CAPACITY` = 8 slots; at most one work set per holder).

Register convention: `rax = 20`, `rdi = subop`; arguments in `rsi`, `rdx`, `r10`, `r8`; result in `rax`. Deadlines match the port rules above.

| # | Subop | `rsi` | `rdx` | `r10` | `r8` | Success |
|---|---|---|---|---|---|---|
| 0 | reserved | — | — | — | — | `EINVAL` |
| 1 | `CREATE` | 0 | 0 | 0 | 0 | `WorkSetId` raw (`EEXIST` if the holder already has one; `ENOSPC` if full) |
| 2 | `WAIT` | ws | mask (`u32`, nonzero) | deadline (abs ns, 0 = none) | flags: bit 0 `WORK_SET_WAIT_NONBLOCK` | `ready & mask`, cleared on return; `ETIMEDOUT`; `EAGAIN` with `NONBLOCK` |
| 3 | `DESTROY` | ws | 0 | 0 | 0 | 0 |
| 4 | `NOW` | 0 | 0 | 0 | 0 | monotonic ns (`EINVAL` if uncalibrated) |
| 5.. | reserved | — | — | — | — | `EINVAL` |

`WorkSetId` uses the same encoding as `ConnectionId` (slot 0..16, generation 16..48). `work_set::signal` is kernel-internal and IRQ-safe; stale ids are a silent no-op. Port `BIND_WAKE`, and (when they land) display and input `BIND_WAKE`, store `(WorkSetId, bit)` and signal through `work_set::signal`.

## Shared buffers (syscall 16, #195)

Authoritative constants and limits: `clean_slate_native_abi::shared_buffer`. Kernel object model: `kernel/src/mm/shared_buffer/`. Process teardown ordering for the window is in [ARCHITECTURE.md](ARCHITECTURE.md) (step 5).

### Syscall contract

All subops use `rdi` = subop, `rax` = return value (0 or a positive handle/VA on success; a `STATUS_*` sentinel on failure). Status sentinels match `SHARED_BUFFER_STATUS_*` in `native-abi` (`EINVAL`, `EACCES`, `ESTALE`, `ENOSPC`, `EAGAIN`, `EBADF`; unknown subop → `EINVAL`).

| Subop | `rdi` | `rsi` | `rdx` | `r10` | Success `rax` | Typical errors |
|---|---|---|---|---|---|---|
| `ALLOCATE` (1) | 1 | — | `byte_len` (1..`MAX_SHARED_BUFFER_BYTES`) | `flags` (must be 0) | root capability handle (encoded) | `EINVAL`, `ENOSPC` |
| `MAP` (2) | 2 | capability handle | `access` (`0` = read, `1` = read/write) | — | mapped VA in the shared window | `EINVAL`, `EACCES`, `ESTALE`, `ENOSPC`, `EAGAIN` |
| `UNMAP` (3) | 3 | — | slot VA from `MAP` | — | 0 | `EINVAL`, `EBADF` |
| `QUERY` (4) | 4 | capability handle | user `out` pointer | `out_len` (= 40) | 0 | `EINVAL`, `EACCES`, `ESTALE` |
| `RELEASE` (5) | 5 | capability handle | — | — | 0 | `EACCES`, `ESTALE`, `EAGAIN` |

`MAP` checks the handle's rights against the requested access (`READ` for read-only, `READ|WRITE` for read/write). `RELEASE` requires `REVOKE`, owner depth 0, and no live row for that buffer in the caller's window (`EAGAIN` if still mapped).

`QUERY` writes a 40-byte `SharedBufferInfo` (little-endian): `id@0`, `byte_len@8`, `page_count@16`, `rights_bits@20`, `flags@24`, reserved zero `@28`, `mapped_va@32` (0 when unmapped). Flags: `CALLER_IS_OWNER` (1), `CALLER_MAPPED_READ_WRITE` (2).

### Limits and rationale

| Constant | Value | Role |
|---|---|---|
| `MAX_SHARED_BUFFERS` | 32 | system-wide buffer objects |
| `MAX_SHARED_BUFFERS_PER_OWNER` | 8 | per owning process (≥ `MAX_BUFFERS_PER_CLIENT`) |
| `MAX_SHARED_PAGES_TOTAL` | 8192 (32 MiB) | system-wide backing pages |
| `MAX_SHARED_PAGES_PER_OWNER` | 4096 | per owner (≥ `MAX_BUFFER_BYTES` in pages) |
| `MAX_ATTACHMENTS_PER_BUFFER` | 2 | live window rows per buffer (owner map + one reader, e.g. compositor) |
| `MAX_SHARED_MAPPINGS_PER_PROCESS` | 20 | window rows per process (≥ `MAX_REGISTERED_BUFFERS` + `SCANOUT_BUFFER_COUNT`) |
| `MAX_EXTENTS_PER_BUFFER` | 16 | physical extents per buffer |
| `MAX_SHARED_BUFFER_BYTES` | 8 MiB | max `byte_len` (= `MAX_BUFFER_BYTES`) |
| `SHARED_WINDOW_BASE` | `0x0000_5000_0000_0000` | fixed VA window base |
| `SHARED_WINDOW_SLOT_STRIDE` | 16 MiB | per-row span (≥ 2× `MAX_SHARED_BUFFER_BYTES`, 2 MiB-aligned) |

`proposed_limits_satisfy_graphics_protocol_budget` (`native-abi`) checks compositor headroom: mapping slots, per-owner page quota, and per-owner buffer count versus protocol caps.

### Kernel semantics

- **Identity.** `SharedBufferId`: slot in bits 0..16, generation in 16..48 (generation 0 invalid). Slot reuse bumps generation (`ESTALE` on stale handles).
- **Allocate.** Frames are zero-filled; the owner receives a root capability with `READ | WRITE | DELEGATE | REVOKE`.
- **Map / unmap.** At most one row per (process, buffer); `MAX_ATTACHMENTS_PER_BUFFER` caps cross-process maps. Window page tables are NX at every level; leaves are writable only for `ReadWrite` mappings.
- **Revocation and owner release.** `revoke_for_resource` / `revoke_for_holder` (teardown step 4) call `RevokedBuffers::reconcile`: O(attachments) per noted buffer, no table scans. When the root capability dies or the owner `RELEASE`s, the buffer becomes `Dying`; each attachment whose buffer or capability authority is gone is retargeted to a shared zero page (reads as zeros) and detached. Buffer frames are queued on a pending-free list and reclaimed exactly once when an allocator is available.
- **W6 — `attest_for_transfer`.** Host-tested; no production caller until port SEND (#200). Confirms `DELEGATE` on a live buffer and returns kernel-attested `(id, byte_len)` for the transfer slot. Transferred children remain `READ` only.
- **W7 — kernel-owned buffers and pins.** Host-tested; consumers land with presenter (#111) and scanout. Kernel-owned buffers have no capability; `allocate_kernel_owned`, `map_kernel_owned_into`, `pin` / `unpin` support scanout without widening app authority.

Acceptance: `cargo xtask test-m10-nxe` and `cargo xtask test-m10-shared-buffer` ([DEVELOPMENT.md](DEVELOPMENT.md)). The shared-buffer QEMU lane runs an NX baseline plus production syscall-16 phases (cross-process map/read, denial, stale generation, exhaustion, reuse zeroing, kernel-owned pin, read-only write fault, shared-window exec fault, owner exit, reader exit, CAP_REVOKE of the root while mapped) and a resource baseline check. The exit, fault and revoke phases prove each path ends in teardown step 5 (`SharedMappings`) rather than `fatal_kernel_error`.

## Reference mode

`graphics::mode::REFERENCE_MODE` is the single M10 output geometry. Lanes must not choose their own.

| Field | Value |
|---|---|
| size | 1280×800 physical pixels |
| format | `PixelFormat::Xrgb8888` (memory bytes B, G, R, X) |
| scale | `Scale120::ONE` (1.0) |
| scanout stride | 5120 bytes |
| frame size | `REFERENCE_FRAME_BYTES` = 4,096,000 bytes = 1000 pages |
| `refresh_mhz` | 0 (unknown) |

Why: 1280×800 is QEMU `virtio-gpu`'s default and is in OVMF's bochs/stdvga mode list; BGRX matches GOP `PixelBlueGreenRedReserved8BitPerColor`, VirtIO-GPU `B8G8R8X8_UNORM` and Linux DRM `XRGB8888` (M11), so opaque surfaces copy to scanout without conversion.

Pinning (planned, per lane):

- **GOP lane (#111):** `-vga std`. Before `ExitBootServices` the kernel iterates GOP modes and calls `SetMode` for exactly 1280×800, and fails closed if the mode is absent. `PixelBlueGreenRedReserved8BitPerColor` copies unchanged; `PixelRedGreenBlueReserved8BitPerColor` is converted at present-copy time; `PixelBitMask` and `PixelBltOnly` are rejected. The aperture stride is backend-private; the compositor always sees 5120.
- **VirtIO lane (#114):** `-vga none -device virtio-gpu-pci,xres=1280,yres=800`. `GET_DISPLAY_INFO` must report an enabled 1280×800 scanout 0, otherwise the backend fails closed. OVMF's VirtIO-GPU GOP is blit-only, so this lane must not require GOP capture.

## Pixels, alpha and colour

| `PixelFormat` | Value | Layout | Semantics |
|---|---|---|---|
| `Xrgb8888` | 1 | little-endian `0xXXRRGGBB`; bytes B, G, R, X | always opaque; consumers ignore X, producers write `0xFF` |
| `Argb8888Premultiplied` | 2 | little-endian `0xAARRGGBB`; bytes B, G, R, A | R, G, B premultiplied by A; each colour channel ≤ A |

There is no straight-alpha format.

**`over`.** `graphics::pixel::over(src, dst)` is the reference premultiplied source-over for B, G, R, A byte arrays: `out = src + div255(dst × (255 − src.a))` per channel, where `div255(x) = (x + 128 + ((x + 128) >> 8)) >> 8`. A source channel above its alpha is clamped to alpha before blending (never undefined behaviour), and the output never exceeds 255. Raster (#111), compositor (#112) and tests all use this exact rounding.

**Colour space.** `ColorSpace::Srgb = 0` is the only value. Pixel values are sRGB-encoded and M10 blends in encoded space, a documented approximation. `ColorSpace` is carried on every `Commit` so linear-light blending can arrive later as a compositor quality tier without a protocol change.

**Buffer layout.** `BufferLayout::new(width, height, stride_bytes, format)` is the only constructor path (fields are private), and every product is checked:

- `width` and `height` in `1..=MAX_SURFACE_EXTENT` (4096), else `EmptyExtent` or `ExtentTooLarge`;
- `stride_bytes % 4 == 0`, else `StrideMisaligned`;
- `width × 4 ≤ stride_bytes ≤ MAX_STRIDE_BYTES` (16384), else `StrideTooSmall` or `StrideTooLarge`;
- `stride_bytes × height ≤ MAX_BUFFER_BYTES` (8 MiB), else `BufferTooLarge`;
- `BufferLayout::packed` uses `align_up(width × 4, 64)` as the stride;
- the compositor also requires `layout.fits_in(byte_len)` against the kernel-attested buffer length (`BufferTooSmall`, planned in #112).

## Coordinate model

| Space | Type | Origin and units | Used for |
|---|---|---|---|
| global logical | `Point`, `Rect` (i32 position, u32 size) | output top-left; +x right, +y down | compositor placement (never client-set) |
| surface-local logical | `Rect`, `Fixed24_8` | surface top-left | opaque and input regions; pointer positions |
| buffer | `BufferRect` (u16 fields) | buffer pixel (0, 0) | damage; present damage |

- **Scale.** `Scale120` counts 1/120 steps; `Scale120::ONE` = 120 = 1.0. Physical = logical × scale / 120, positions rounded down and sizes up. M10 accepts only `ONE`, so the mapping is the identity; any other value is `InvalidScale` (value 0 is rejected by the codec, other values by `SurfaceState::attach` and `WindowConfig::validate_m10`).
- **Output.** `Welcome` carries `OutputInfo { id, mode, logical_size }`: the physical mode and the logical size are separate fields.
- **Pointer.** Positions are `Fixed24_8` (signed 24.8 fixed point), surface-local.
- **Rectangles** are half-open `[x, x + width) × [y, y + height)`.
- **Checked arithmetic.** `Rect::validate` rejects a width or height above `i32::MAX` and any right or bottom edge that overflows i32. `intersect`, `union_bounds` and `clip_to` return `Result<Option<Rect>, GeometryError>`; an empty intersection is `Ok(None)`. `BufferRect::clip_to_extent` works in u32, so u16 damage cannot overflow.
- **`RectSet<N>`** is bounded: zero-area rects are dropped, and an insert beyond `N` collapses the set to its bounding box (`is_collapsed`). A set never grows.
- **Buffer versus surface rects.** Damage is in buffer pixels and is clipped to `[0, 4096)²` at request time and to the committed buffer size at commit and latch. Regions are surface-local logical rects with the same two clip points. Clients never set their absolute window position; they may only request `BeginMove` or `BeginResize` with a live input serial, and placement is compositor policy.

## Identities and generations

Every generation starts at 1; generation 0 is invalid on the wire. Releasing a slot bumps its generation, and a slot whose generation reaches the maximum retires instead of wrapping.

| Id | Width | Layout | Minted by | Scope |
|---|---|---|---|---|
| `SharedBufferId` | u64 | slot 0..16, generation 16..48, bits 48..64 zero | kernel (#195) | global; also `ResourceRef.id` |
| `ConnectionId` | u64 | same shape as `SharedBufferId` | kernel port (#200) | bound to (client holder, compositor instance) |
| `ObjectId` (`SurfaceId`, `WindowId`, `ClientBufferId`) | u32 | slot 0..8, generation 8..32 (max `MAX_OBJECT_GENERATION` = `0xFF_FFFF`) | compositor | one connection |
| `OutputId` | u32 | output index 0..8, backend epoch 8..32 | kernel display module | global; epoch bumps on reset or mode change |
| `InputDeviceId` | u32 | device index 0..8 (`KEYBOARD_INDEX` 0, `MOUSE_INDEX` 1), generation 8..32 | kernel input module | informational, never authority |
| `Serial` | u32 | 0 reserved as "none" | compositor, one `SerialMinter` per connection | one connection; compared by equality only |
| `RawInputRecord.seq` | u64 | starts at 1, +1 per queued record | kernel | per boot |

**Connection-scoped objects (S1).** Each connection has one `ObjectTable<S, W, B>` holding surfaces, windows and buffers in a single generational id space of `MAX_OBJECTS_PER_CLIENT` (20) slots. Consequences:

- an id resolves only in the caller's own table, so guessing another client's id is meaningless, and the same raw id in two tables names each table's own object or nothing;
- lookup errors map through `lookup_error_code`: never-issued or malformed → `InvalidObject`; stale or retired → `StaleObject`; a live id of another kind → `WrongObjectKind`;
- insert checks the per-kind per-client cap, then the per-kind compositor-wide cap (`GlobalBudget`), then table capacity; every failure is `LimitExceeded` and changes nothing. Per-kind caps mean no kind can starve another;
- slot retirement exhausts only the retiring connection's table. There is no cross-connection generation floor, because one would be a shared exhaustible resource;
- any compositor state that spans connections (focus, grabs, stacking order, pending release or frame bookkeeping, damage history) **must be keyed by a generation-safe connection id plus the object id**, never by the object id alone (#112).

**Serials.** `SerialMinter` starts at 1, increments by one and skips 0 on wrap. One minter per connection is shared by every window of that connection and by input serials, so an ack meant for one window can never match another.

**Reserved.** `GlobalWindowToken(u64)`: compositor-global, issued only to `GFX_SHELL` holders, for a future rail task list. Not issued in M10.

## Lifecycles

### Connection

```text
AwaitingHello --Hello, negotiate ok--> Established --fatal error / close()--> Closed
      |                                     |
      +--any other frame, failed Hello------+--second Hello--> Closed (UnsupportedVersion)
```

`ConnectionPhase::admit(frame)` decides every inbound frame:

1. `Closed` → `Discard`.
2. Decode. On a decode error before `Hello`, a recoverable code is escalated to `UnsupportedVersion`, because nothing may precede `Hello`.
3. `Hello` while `AwaitingHello` → `negotiate(v, f, SERVER_VERSION, M10_SERVER_FEATURES)`. Success → `Welcome` and `Established`; failure → fatal `UnsupportedVersion` with the Hello tag and no `Welcome` (S9: the code is always `UnsupportedVersion`, never forwarded).
4. Any other request before `Hello`, or a second `Hello` → fatal `UnsupportedVersion`.
5. Otherwise → `Dispatch { tag, object, request }`.

Handlers route their semantic errors through `ConnectionPhase::fail`, so fatality is decided in one place. The compositor then resolves object ids in field order (header `object` first, then body ids such as `AssignRole.parent`) before any semantic check.

### Buffers

```text
client: allocate SharedBuffer (#195) -> render
        -> RegisterBuffer{layout} + transfer ---------> BufferRegistered(ClientBufferId)
        -> Attach{buffer} -> Damage -> Commit ---------> buffer is BUSY (client must not write)
compositor latch (composition start) -----------------> BufferReleased(previous current)
newer Commit before latch ----------------------------> BufferReleased(superseded latest)
        -> UnregisterBuffer (only when idle) ---------> BufferUnregistered
```

Synchronisation is ownership handoff; there are no fences. After `Commit` a buffer is busy until `BufferReleased`. No control data lives in shared memory, and pixel bytes are untrusted data: a misbehaving writer corrupts only its own surface.

- **Register (planned, #112/#200).** `RegisterBuffer { layout }` carries only the layout; the `SharedBuffer` capability travels in the port transfer slot, never in the frame. The kernel-attested `byte_len` must satisfy `layout.fits_in(byte_len)` (`BufferTooSmall`); a missing or wrong-class transfer is `TransferMissing` or `TransferWrongClass`. At most `MAX_BUFFERS_PER_CLIENT` (8) per connection and `MAX_REGISTERED_BUFFERS` (16) compositor-wide.
- **Attach.** `SurfaceState::attach` stores the pending buffer. Scale ≠ 120 → `InvalidScale` (checked first). A buffer that is busy anywhere on the connection → `BufferBusy`. `None` means detach.
- **Commit.** See [Surfaces](#surfaces). `BufferTracker::commit` releases the superseded `latest`.
- **Latch.** `SurfaceState::latch` calls `BufferTracker::composited`, which promotes `latest` to `current` and releases the old `current`.
- **Unregister.** A busy buffer → `BufferBusy`, and it stays registered. A pending attach of a buffer that was unregistered before commit fails at commit through the resolver (`StaleObject`).

`BufferTracker<N>` keeps one entry per surface holding a busy buffer: `current` (composited; the compositor may re-read it) and `latest` (committed, not yet composited: empty, a buffer, or detach). Busy buffers per surface never exceed `MAX_IN_FLIGHT_BUFFERS_PER_SURFACE` (2). `ConnectionBufferTracker` has `MAX_BUFFERS_PER_CLIENT` entries, so a compositor that enforces the buffer cap never sees `LimitExceeded` from it. Release ordering, proven by `superseded_latest_is_released_at_commit_and_old_current_at_latch`:

| Step | Released |
|---|---|
| commit A | — |
| latch | — |
| commit B | — |
| commit C | B (never composited; released at supersede) |
| latch | A (the old current) |
| detach commit | — |
| latch | C |

`DestroySurface` calls `BufferTracker::remove_surface`, which returns `[current, latest]`; the compositor posts `BufferReleased` in that order.

### Surfaces

A surface is double-buffered: requests change `PendingState`; `Commit` applies it atomically to `CommittedState`.

```text
CreateSurface -> SurfaceCreated
AssignRole (once) | Attach | Damage | SetOpaqueRegion | SetInputRegion   (pending only)
Commit -> validate (no mutation) -> apply (infallible) -> CommitOutcome
composite -> latch -> Latch{released, damage, geometry_changed}
DestroySurface -> window destroyed first, then [current, latest] released
```

**Role.** `assign_role` checks `RoleAlreadyAssigned` first, then `validate_role`, then `validate_parent`; the role is recorded only on success, so a denied surface stays role-less and may try again. See [Roles](#surface-roles).

**Damage** (`damage`): more than 5 rects in one call → `InvalidDamage`. Rects are clipped to `[0, 4096)²`; zero-area and fully-outside rects are dropped. Overflow of the 16-rect set collapses to the bounding box and never errors.

**Regions** (`set_opaque_region`, `set_input_region`): more than 3 rects, or any rect failing `Rect::validate`, → `InvalidRegion`, all-or-nothing. `replace = true` starts from empty; `replace = false` appends.

- Opaque overflow past `MAX_REGION_RECTS` (8) degrades to `OpaqueRegion::Degraded`, which means "not opaque" (a safe hint). It is sticky until the next `replace = true`.
- Input overflow fails the request with `InvalidRegion` and leaves pending unchanged (S2). There is no overflowed input state.
- A clipped rect equal to `EXTENT_RECT` (`{0, 0, 4096, 4096}`) normalises the input region to `WholeSurface` before the capacity check (C21). This is how a client restores the default. `replace = true` with count 0 means no input. Appending to `WholeSurface` is a no-op.

**Commit validation order** (first failure wins; on any error the surface, the tracker and the configure state are unchanged):

1. `ack = Some(s)`: no window, or `window.check_ack(s)` fails → `SerialMismatch`.
2. A window that was never configured and `ack = None` → `NotConfigured`.
3. Pending `Attach(b)` → `resolve(b)` (the compositor's lookup; its error passes through unchanged). The resolver runs exactly once, and only for `Attach`.
4. `tracker.check_commit` → `BufferBusy`, then `LimitExceeded`.

**Apply** (infallible):

- the ack is applied atomically with the commit (`outcome.acked`);
- `outcome.released` is the superseded `latest`;
- `geometry_changed` is true when (mapped, width, height) changed; commit damage is empty when unmapped, the full buffer when geometry changed, otherwise pending damage clipped to the buffer;
- commit damage accumulates into unlatched damage (collapsing at 16);
- the opaque and input regions are clipped to the buffer size (`Degraded` commits as empty);
- the pending buffer resets to `Unchanged` and pending damage clears; regions and scale persist;
- a commit on a role-less or window-less surface is allowed.

**Composite scheduling (S6).** `CommitOutcome.schedule_composite = geometry_changed || !commit_damage.is_empty() || request_frame || buffer_identity_changed`, where the buffer identity changed on `Attach` of a different id or on `Detach` of a committed buffer. A damage-less buffer swap therefore still schedules a composite, so a double-buffered client's handoff never waits for unrelated damage. A redundant commit schedules nothing, and a composite with no damage still submits no present (S3).

**Latch damage clipping (S7).** `Latch.damage` is the accumulated unlatched damage clipped to the size of the committed buffer being latched, so damage recorded before a shrink never escapes the new buffer. A second latch with no new commit hands over nothing and releases nothing.

**Input hit-testing.** `CommittedState::accepts_input_at(point)` is bounded by the committed surface size and the committed input region.

### Windows

A window is the role object of one `Toplevel` surface. `WindowId` is distinct from `SurfaceId` and from process identity.

```text
CreateWindow(surface) -> WindowCreated
compositor: ConfigureState::send(minter, cfg) -> Configure{serial, size, scale, decoration, states, bounds}
client:     AckConfigure(serial)  or  Commit{ack: serial}  -> configured
Show | Hide | SetTitle | SetSizeLimits | BeginMove | BeginResize
compositor: CloseRequested -> client: DestroyWindow
```

- **Create (S4).** `CreateWindow` on a role-less or non-`Toplevel` surface → `NotPermitted`; a second `CreateWindow` on the same surface → `RoleAlreadyAssigned`. One window per surface. Enforced in #112 (planned).
- **Configure vocabulary.** `WindowConfig::validate_m10` checks, in order: size or bounds above 4096 → `InvalidLayout`; scale ≠ `ONE` → `InvalidScale`; decoration ≠ `Server` or any state other than `ACTIVATED` → `UnsupportedFeature`. `WindowStates` reserves `MAXIMIZED`, `MINIMIZED`, `FULLSCREEN` and `RESIZING` on the wire for later milestones. Size 0 means the client chooses; bounds 0 means unbounded.
- **Outstanding configures (D12).** At most `MAX_OUTSTANDING_CONFIGURES` (4) per window. A refused `send` consumes no serial. On `LimitExceeded` the compositor keeps the newest wanted config and re-sends after the client acks; clients never see this error.
- **Ack (D10, C24).** `AckConfigure(s)` and `Commit.ack = s` are the same operation; the commit form is applied atomically with the commit and only if the whole commit succeeds (D9). Acking `s` consumes `s` and every older outstanding serial. A re-ack, a superseded serial, an unknown serial or serial 0 → `SerialMismatch` with state unchanged.
- **First configure (D11).** A windowed surface cannot commit before its first ack (`NotConfigured`) unless the commit itself carries a valid ack.
- **Placement.** `BeginMove` and `BeginResize` must reference a live pointer-press serial; `ResizeEdges` accepts a single edge or one vertical plus one horizontal edge. Placement, focus, z-order and decorations are compositor policy (#115).
- **Decorations** are server-side (`DecorationMode::Server`); `Client` is reserved for the `CLIENT_DECORATIONS` feature.

### Frames

`FrameState` is `Idle`, `Armed` or `AwaitingPresent { present_seq }`, with at most one callback per surface.

```text
Commit{request_frame}          Idle -> Armed     (a request while Armed/Awaiting merges)
real present (in flight/next)  Armed -> AwaitingPresent{seq}   via frame_submitted(seq)
completion with seq' >= seq    AwaitingPresent -> Idle, FrameDone{presented_ns, output_seq}
```

Rules (S3):

- A composition with no damage submits **no** `PRESENT`. The compositor never presents just to answer a frame request.
- An armed callback rides the present already in flight, or the next real present; `FrameDone` is **never** fired immediately, which would create a client–compositor spin loop.
- `FrameDone` fires on the first observed completion with `completed_seq ≥ present_seq`, whether the present succeeded or timed out, so a timed-out present still unblocks a render loop (D16). `presented_ns` and `output_seq` are the display's `completed_ns` and `completed_seq`.
- The compositor may withhold `FrameDone` indefinitely from occluded surfaces.
- Clients must not gate input handling or commits on `FrameDone`: a commit is always allowed.

### Teardown

- **Connection close (S8).** Every connection teardown path (client exit, revoke, protocol disconnect, queue overflow) calls `ObjectTable::close(&mut budget)`. It returns every live object's budget to the `GlobalBudget` and resets the table in place; the next connection starts with a table equivalent to `ObjectTable::new()`. Budget release `debug_assert!`s against underflow (a foreign or mismatched budget) and saturates in release builds.
- **Storage (S8).** An `ObjectTable<SurfaceState, _, _>` is about 24 KB per connection. The compositor keeps its tables in static or heap memory, never on the stack; `close` works in place so no by-value move is needed.
- **Kernel ordering (P4).** Port teardown and work-set release are landed in #200 (`port::on_holder_exit`, `work_set::on_holder_exit` in the shared teardown hook order before `revoke_for_holder`). Display presenter release, input-consumer release, shared-mapping teardown and the #118 baseline proof remain planned (#111/#114, #113, #195, #118). On every registered teardown path: port teardown (close the holder's connections and notify the server, or mark every connection `ServerGone` if the holder was the server); display presenter release (planned); input-consumer release (planned); `revoke_for_holder`; shared-mapping teardown (planned); `destroy_process_address_space` for private pages. `ResourceSnapshot` includes `port_connections`, `ports_served` and `work_sets` (#200); shared mappings and presenter/consumer bindings remain planned for later lanes.

## Surface roles

Role authority comes only from the kernel-stamped rights of the caller's `Graphics` capability, via `RoleGrant::from_rights_bits` (all bits other than the three role bits are ignored), and never from request fields. The layer is derived by the compositor and is not on the wire.

| `SurfaceRole` | Value | Requires | `Layer` |
|---|---|---|---|
| `Toplevel` | 1 | `GFX_CONNECT` | `Windows` (1) |
| `Popup` | 2 | `GFX_CONNECT`; parent is another `Toplevel` or `Popup` surface of the same connection | `Windows` (1) |
| `Background` | 3 | `GFX_CONNECT \| GFX_SHELL` | `Background` (0) |
| `ShellPanel` | 4 | `GFX_CONNECT \| GFX_SHELL` | `ShellFurniture` (2) |
| `SystemOverlay` | 5 | `GFX_CONNECT \| GFX_OVERLAY` | `TrustedOverlay` (3) |
| `Cursor` | 6 | reserved | — |
| `Subsurface` | 7 | reserved | — |

`Layer::Cursor` (4) is compositor-internal: the M10 pointer is drawn by the compositor. `validate_role` precedence:

1. `Cursor` or `Subsurface` → `UnsupportedFeature`, regardless of the grant.
2. No `GFX_CONNECT` → `RoleForbidden` for every role.
3. The role-specific right is missing → `RoleForbidden`.

`GFX_OVERLAY` does not imply `GFX_SHELL`. `GFX_SERVE` alone authorises no role. `validate_parent`: `Popup` without a valid non-self parent → `InvalidParent`; any other role with a parent → `InvalidParent`.

Z-order, bottom to top: `Background`, `Windows` (compositor stacking), `ShellFurniture`, `TrustedOverlay`, cursor. Only the compositor draws the trusted overlay; no process holds `GFX_OVERLAY` in M10.

## Wire protocol summary

Authoritative: `graphics::protocol` (`mod.rs`, `request.rs`, `event.rs`, `frame_spec.rs`), with every body table in the rustdoc of `protocol/reference.rs`. Do not re-derive offsets from this document.

Every compositor message is exactly one 64-byte frame (`FRAME_BYTES`), little-endian, carried as the payload of one port message (#200). Pixels never travel in frames; they live in shared buffers.

| Offset | Width | Field | Rule |
|---|---|---|---|
| 0 | 2 | `opcode` | requests `0x0001..=0x7FFF`, events `0x8001..=0xFFFF`; `0x0000` and `0x8000` are never valid |
| 2 | 1 | `flags` | must be 0 |
| 3 | 1 | reserved | must be 0 |
| 4 | 4 | `tag` | client-chosen; reply events echo it; unsolicited events use 0 |
| 8 | 4 | `object` | the target object, and only here (A1): per opcode, must be 0, required, optional, or raw echo (`Error` only) |
| 12 | 52 | body | per opcode (`BODY_OFFSET`, `BODY_BYTES`); every unassigned byte is padding and must be 0 |

Protocol version `1.0` (`PROTOCOL_MAJOR`, `PROTOCOL_MINOR`); `M10_SERVER_FEATURES` = `Features(0)`. No magic and no in-frame version.

**Decode order** (the first failing step decides the error):

1. length ≠ 64 → `MalformedFrame`;
2. `flags` ≠ 0 → `ReservedBitsSet`;
3. reserved byte ≠ 0 → `ReservedBitsSet`;
4. opcode not in this direction's table, including every reserved-range opcode → `UnknownOpcode`;
5. header `object` rule: nonzero when it must be 0 → `ReservedBitsSet`; required and 0, or generation 0 → `InvalidObject`;
6. static padding → `ReservedBitsSet`;
7. fields in ascending offset order, each with its own rule (unused counted-array slots must be zero).

`encode` applies the same field validation as `decode` and returns the same error. `decode(encode(v, t))` is the identity for every canonical value (`golden_frames`, `all_requests_round_trip`, `all_events_round_trip`).

**Fatality.** `ProtocolError::is_fatal` is true for `UnsupportedVersion`, `MalformedFrame` and `ReservedBitsSet` only. A recoverable error produces `Event::Error { object, request_opcode, code }`, with the request's tag and raw header object echoed, and the connection stays open. A fatal error produces a best-effort `Error` followed by disconnect with `DisconnectReason::ProtocolViolation(code)`. A client that fails to decode an event treats it as fatal and closes. `UnknownOpcode` is recoverable, so a newer client can probe.

| `DisconnectReason` | u32 |
|---|---|
| `ClientExit` | 1 |
| `ServerExit` | 2 |
| `QueueOverflow` | 3 |
| `Revoked` | 4 |
| `ProtocolViolation(code)` | `0x0001_0000 \| code` (fatal codes only) |

**Messages.**

| Group | Requests | Events |
|---|---|---|
| connection | `Hello` 0x0001 | `Welcome` 0x8001, `Error` 0x8002 |
| buffers | `RegisterBuffer` 0x0010, `UnregisterBuffer` 0x0011 | `BufferRegistered` 0x8010, `BufferReleased` 0x8011, `BufferUnregistered` 0x8012 |
| surfaces | `CreateSurface` 0x0020, `DestroySurface` 0x0021, `AssignRole` 0x0022, `Attach` 0x0023, `Damage` 0x0024, `SetOpaqueRegion` 0x0025, `SetInputRegion` 0x0026, `Commit` 0x0027 | `SurfaceCreated` 0x8020, `FrameDone` 0x8021 |
| windows | `CreateWindow` 0x0030, `DestroyWindow` 0x0031, `SetTitle` 0x0032, `SetSizeLimits` 0x0033, `Show` 0x0034, `Hide` 0x0035, `BeginMove` 0x0036, `BeginResize` 0x0037, `AckConfigure` 0x0038 | `WindowCreated` 0x8030, `Configure` 0x8031, `CloseRequested` 0x8032 |
| keyboard | — | `KeyboardFocus` 0x8040, `Key` 0x8041, `ModifiersChanged` 0x8042 |
| pointer | — | `PointerEnter` 0x8050, `PointerLeave` 0x8051, `PointerMotion` 0x8052, `PointerButton` 0x8053, `PointerAxis` 0x8054 |
| seat | — | `InputReset` 0x8060 |

Per-frame limits: `Damage` carries at most `DAMAGE_RECTS_PER_FRAME` (5) `BufferRect`s and the region requests at most `REGION_RECTS_PER_FRAME` (3) `Rect`s; larger sets use several requests before one `Commit`. `SetTitle` carries a `WindowTitle` of at most `MAX_TITLE_BYTES` (40) bytes of UTF-8, truncated on a character boundary by the encoder. `Commit` carries `request_frame`, `color_space` and an optional configure `ack`.

**Input events** are raw and focus-routed by the compositor: `Key` carries a HID usage (`KeyUsage`, page 0x07) and `KeyState`, not text. Clients never name the surface that receives input; they receive `KeyboardFocus`, `PointerEnter` and `PointerLeave` for their own surfaces only, with surface-local `Fixed24_8` positions. `Key`, `PointerEnter`, `PointerLeave` and `PointerButton` carry a `Serial` from the connection's minter (move, resize and future popup grabs quote it); `Key`, `PointerMotion`, `PointerButton` and `PointerAxis` carry a monotonic `time_ns`. `Key` also carries the current `Modifiers`.

**Negotiation.** `Hello { version, features }` must be the first request; `Welcome` replies with the negotiated version and features and the output (`OutputInfo`: id, mode, logical size). `negotiate`:

- major mismatch → `UnsupportedVersion`;
- minor = min(client, server);
- features = client ∩ server ∩ `Features::KNOWN`; unknown bits are masked, never rejected.

## Display ABI (syscall 18)

Authoritative: `graphics::abi::display`, `graphics::abi::status`. Kernel implementation: #111 GOP (landed) and #114 VirtIO-GPU (planned), both behind one `ScanoutBackend`.

Register convention (matches the network syscall, `SYSCALL_NR_NETWORK_CAPABILITY` = 14): `rax` = 18, `rdi` = subop, `rsi` = capability handle (ignored by `FIND_HANDLE`), `rdx`, `r10`, `r8`, `r9` = arguments; `rax` out = success value or a status sentinel. User pointers are validated over the exact declared struct length; a wrong length is `EINVAL`. **Non-blocking**: waiting happens only through work sets.

| Subop | Name | Arguments | Authority | Returns |
|---|---|---|---|---|
| 1 | `FIND_HANDLE` | `rdx` = `DISPLAY_ABI_VERSION` (1) | a live `Display` capability | handle for that output index (S10) |
| 2 | `QUERY_MODE` | out ptr, len 32 (`DisplayModeInfo`) | `INSPECT` or `DISPLAY_PRESENT` | 0; `DisplayModeInfo.output` is the current `OutputId` |
| 3 | `MAP_SCANOUT` | buffer index, out ptr, len 32 (`ScanoutMapping`) | `DISPLAY_PRESENT`; binds the presenter | 0 |
| 4 | `PRESENT` | in ptr, len 136 (`PresentRequest`) | `DISPLAY_PRESENT` + bound presenter | `present_seq` ≥ 1 |
| 5 | `PRESENT_STATUS` | out ptr, len 40 (`PresentStatus`) | `INSPECT` or `DISPLAY_PRESENT` | 0 |
| 6 | `BIND_WAKE` | work-set handle, bit 0..=31 | `DISPLAY_PRESENT` + bound presenter | 0 |
| 0, 7.. | reserved | — | — | `EINVAL` |

Until the owning stage lands: `BIND_WAKE` returns `ENOSYS` until a later #111 stage wires it to the work sets (syscall 20); `MAP_SCANOUT` and `PRESENT` return `ENOSYS` until #111 wires presenter scanout onto #195's kernel-owned buffers (R2). The kernel-owned allocation and pin APIs exist (W7, host-tested). Before then #111 proves `test-m10-framebuffer` with a kernel-internal present.

- **Presenter.** The first successful `MAP_SCANOUT` binds the caller's holder. `MAP_SCANOUT`, `PRESENT` and `BIND_WAKE` from any other holder → `NotPresenter`. Only process teardown releases the binding. `MAP_SCANOUT` is idempotent per index. Mappings are user read-write and NX, and persist across epoch bumps.
- **Scanout buffers.** `SCANOUT_BUFFER_COUNT` (2) kernel-owned buffers of the reference mode (stride 5120, `byte_len` 4,096,000). The compositor renders into the one that is not in flight.
- **`PRESENT` evaluation order** (the first failure wins): length or pointer (`EINVAL`) → capability authorisation (`EINVAL` / `ESTALE` / `EACCES`) → `PresentRequest::decode` (`EINVAL`) → no backend (`ENODEV`), `Poisoned` (`ENOTRECOVERABLE`), `ResetRequired` (`EIO`) → presenter binding (`EACCES`) → `PresentRequest::validate` (output ≠ current → `ESTALE`; index ≥ 2 → `EBADF`; `damage_count` ∉ `1..=16` or a zero-area or out-of-mode rect → `ERANGE`) → index not mapped (`EBADF`) → a present in flight (`EAGAIN`, `MAX_PRESENTS_IN_FLIGHT` = 1) → accept, `present_seq += 1`.
- **Damage** is exact and in bounds; the kernel does not clip.
- **Copy semantics (R8).** On every backend, the kernel copies only the damaged rects of the named buffer to scanout; pixels outside the damage keep their previously presented content. No backend may flip a whole buffer and expose stale undamaged content.
- **Completion.** `PresentStatus { output, state, in_flight_index, last_error, submitted_seq, completed_seq, completed_ns }`. `PresentState`: `Idle` 0, `InFlight` 1, `ResetRequired` 2, `Poisoned` 3. The bound wake bit is signalled on every completion (success or failure), every state change and every epoch bump; the consumer reads `PRESENT_STATUS` after each wake. A synchronous backend may complete inside `PRESENT` and still signals.

| `DisplayError` | Code | Status | Raised when |
|---|---|---|---|
| `NotPresenter` | 1 | `EACCES` | caller is not the bound presenter |
| `StaleEpoch` | 2 | `ESTALE` | `PresentRequest.output` ≠ current `OutputId` |
| `InvalidBuffer` | 3 | `EBADF` | index out of range or not mapped |
| `BufferBusy` | 4 | `EAGAIN` | a present is already in flight |
| `InvalidDamage` | 5 | `ERANGE` | bad damage count or rect |
| `ModeUnavailable` | 6 | `ENODEV` | no active backend (fail-closed boot) |
| `DeviceTimeout` | 7 | `ETIMEDOUT` | only in `PresentStatus.last_error`; never a syscall return |
| `ResetRequired` | 8 | `EIO` | backend timed out and is resetting |
| `Poisoned` | 9 | `ENOTRECOVERABLE` | reset failed; permanent for this boot |

`DisplayError::from_status` is lossy for `EACCES` and `ESTALE`, which capability failures share.

## Input ABI (syscall 19)

Authoritative: `graphics::abi::input`, `graphics::raw_input`, `graphics::input`. Kernel implementation: #113 (planned). Same register convention as the display ABI; non-blocking.

| Subop | Name | Arguments | Authority | Returns |
|---|---|---|---|---|
| 1 | `FIND_HANDLE` | `rdx` = `INPUT_ABI_VERSION` (1) | a live `Input` capability | handle |
| 2 | `QUERY_DEVICES` | out ptr, len 16 (`InputDeviceInfo`) | `INSPECT` or `INPUT_CONSUME` | 0 |
| 3 | `READ_BATCH` | out ptr, `max_count` in `1..=READ_BATCH_MAX_RECORDS` (128) | `INPUT_CONSUME` | records written, `0..=max_count` |
| 4 | `BIND_WAKE` | work-set handle, bit 0..=31 | `INPUT_CONSUME` | 0 (`ENOSYS` until syscall 20) |
| 0, 5.. | reserved | — | — | `EINVAL` |

- **`READ_BATCH` never blocks**; an empty queue returns 0.
- **Copy rule (R9).** The kernel copies one 32-byte record at a time to user memory and never stages a whole batch (up to 4096 bytes) on the kernel stack. Only fixed structs of at most 256 bytes (`PresentRequest`, 136 bytes, is the largest) are staged on the stack.
- **Wake is edge-triggered.** The bound bit is signalled when a record is queued into an empty queue or an `Overflow` becomes pending on an empty queue. The consumer must drain with `READ_BATCH` until it returns 0 before waiting again.

## Raw input records

`RawInputRecord` is 32 bytes (`RAW_INPUT_RECORD_BYTES`), little-endian:

| Offset | Width | Field |
|---|---|---|
| 0 | 8 | `seq` (0 invalid) |
| 8 | 8 | `time_ns` (monotonic, non-decreasing) |
| 16 | 4 | `device` (`InputDeviceId`) |
| 20 | 1 | kind: `Key` 1, `RelMotion` 2, `Button` 3, `Wheel` 4, `Overflow` 5 |
| 21 | 3 | padding, zero |
| 24 | 8 | payload per kind |

Kernel semantics, binding on #113 (planned):

- **Queue.** `RAW_INPUT_QUEUE_DEPTH` (128) records, filled in IRQ context without allocation.
- **Sequence.** `seq` starts at 1 and increases by exactly 1 per queued record, including `Overflow` records; dropped records get no seq, so the consumer always sees contiguous seqs.
- **Coalescing.** At or above `RAW_INPUT_COALESCE_HIGH_WATER` (96) queued records, a new `RelMotion` merges into an unread tail `RelMotion` from the same device with a saturating add per axis. Nothing else is coalesced: keys, buttons and wheel steps are never merged.
- **Loss (C5).** A record that cannot be queued is dropped and counted. `Overflow { dropped }` is materialised **in order** at the first free slot, so every record before it happened before the first loss and every record after it happened after the last loss.
- **Signs.** `dx > 0` is right; `dy > 0` is **down** (the driver negates PS/2 Y). Wheel `vertical > 0` is scroll down, `horizontal > 0` is right; 120 is one detent (`AxisValue120`).
- **Keys.** `KeyUsage` is a USB HID page 0x07 usage; `is_valid` accepts `0x04..=0xA4`, `0xB0..=0xDD` and `0xE0..=0xE7`. The driver emits `Pressed` and `Released` only on transitions, so typematic repeat is suppressed (repeat is compositor or client policy). Unmapped scancodes are dropped and counted in a driver statistic, not in `Overflow`. Buttons are `PointerButton` 1..=5.

**Compositor seat rule (#113, #112).** On `Overflow`, or whenever the compositor decides to send `InputReset`, it calls `reset_seat(&mut ModifierTracker, &mut ButtonTracker)`. That clears held keys and buttons (lock bits survive) and returns `[InputReset, ModifiersChanged]`; the compositor sends **both**, in that order, to the focused client. `ModifiersChanged` is sent even if nothing changed. Outside a reset, `ModifierTracker::fold` returns `Some` only on a real change, and the compositor sends `ModifiersChanged` exactly then.

## Bounds

Every table and queue is fixed-size. Protocol bounds live in `graphics::limits`; memory bounds for shared buffers live in `clean_slate_native_abi::shared_buffer` (#195 owns them and may adjust within `MAX_BUFFER_BYTES`). Exceeding an object bound is `LimitExceeded`.

| Constant | Value | Bounds |
|---|---|---|
| `MAX_CLIENTS` | 8 | compositor port connections |
| `MAX_SURFACES_PER_CLIENT` / `MAX_SURFACES` | 8 / 32 | surfaces per connection / compositor-wide |
| `MAX_WINDOWS_PER_CLIENT` / `MAX_WINDOWS` | 4 / 16 | windows per connection / compositor-wide |
| `MAX_BUFFERS_PER_CLIENT` / `MAX_REGISTERED_BUFFERS` | 8 / 16 | registered client buffers per connection / compositor-wide |
| `MAX_OBJECTS_PER_CLIENT` | 20 | per-connection object table (8 + 4 + 8; asserted ≤ 256 slots) |
| `MAX_IN_FLIGHT_BUFFERS_PER_SURFACE` | 2 | current plus latest |
| `MAX_DAMAGE_RECTS_PER_COMMIT` | 16 | pending, commit and latch damage; overflow collapses to the bounding box |
| `MAX_REGION_RECTS` | 8 | opaque or input region |
| `DAMAGE_RECTS_PER_FRAME` / `REGION_RECTS_PER_FRAME` | 5 / 3 | rects in one `Damage` / region request |
| `MAX_SURFACE_EXTENT` | 4096 | per-axis buffer pixels and logical units |
| `MAX_STRIDE_BYTES` | 16384 | `MAX_SURFACE_EXTENT × 4` |
| `MAX_BUFFER_BYTES` | 8 MiB | attested client buffer length (covers 1920×1080×4) |
| `MAX_TITLE_BYTES` | 40 | UTF-8 bytes in `SetTitle` |
| `MAX_OUTSTANDING_CONFIGURES` | 4 | unacknowledged configures per window |
| `CLIENT_EVENT_QUEUE_DEPTH` | 64 | per-connection event ring (#200) |
| `SERVER_REQUEST_QUEUE_DEPTH` | 64 | port-wide request ring (#200) |
| `MAX_OUTSTANDING_REQUESTS_PER_CLIENT` | 16 | per-client share of the request ring (#200) |
| `MAX_CLIENT_STALL_ITERATIONS` | 8 | consecutive compositor iterations with a full client event ring before `QueueOverflow` disconnect (#112) |
| `RAW_INPUT_QUEUE_DEPTH` | 128 | kernel raw input queue; also `READ_BATCH_MAX_RECORDS` |
| `RAW_INPUT_COALESCE_HIGH_WATER` | 96 | relative-motion coalescing threshold |
| `SCANOUT_BUFFER_COUNT` | 2 | kernel-owned scanout buffers |
| `MAX_PRESENT_DAMAGE_RECTS` | 16 | rects per `PRESENT` |
| `MAX_PRESENTS_IN_FLIGHT` | 1 | per backend (`graphics::abi::display`) |
| `MAX_OUTPUTS` | 1 | physical outputs |
| `DISPLAY_COMMAND_TIMEOUT_NS` | 1,000,000,000 | backend command deadline before `ResetRequired` |
| `MAX_SHARED_BUFFERS` | 32 | shared-buffer objects system-wide (#195) |
| `MAX_SHARED_BUFFERS_PER_OWNER` | 8 | per owner (#195) |
| `MAX_SHARED_PAGES_TOTAL` | 8192 | 32 MiB system-wide (#195) |
| `MAX_SHARED_PAGES_PER_OWNER` | 4096 | per owner (#195) |
| `MAX_ATTACHMENTS_PER_BUFFER` | 2 | mappings of one buffer (#195) |
| `MAX_SHARED_MAPPINGS_PER_PROCESS` | 20 | shared mappings per process (#195) |
| `MAX_EXTENTS_PER_BUFFER` | 16 | physical extents per buffer (#195) |

`proposed_limits_satisfy_graphics_protocol_budget` (`native-abi`) checks that the memory limits can hold the protocol limits: `MAX_SHARED_MAPPINGS_PER_PROCESS` ≥ `MAX_REGISTERED_BUFFERS` + `SCANOUT_BUFFER_COUNT` (the compositor maps every registered buffer plus both scanout buffers), the per-owner page quota covers `MAX_BUFFER_BYTES`, and `MAX_SHARED_BUFFERS_PER_OWNER` ≥ `MAX_BUFFERS_PER_CLIENT`.

## Errors

### Protocol

`ProtocolError` is `#[repr(u16)]`; `from_u16` rejects any other value. Codec errors come from `Request::decode` / `Event::decode`; semantic errors come from the Stage D state machines and the compositor.

| Code | Name | Fatal | Raised by |
|---|---|---|---|
| 1 | `UnsupportedVersion` | yes | major mismatch; any request before a successful `Hello`; a second `Hello`; any failed `Hello` (S9) |
| 2 | `UnknownOpcode` | no | opcode not assigned in this direction, including reserved ranges |
| 3 | `MalformedFrame` | yes | length; bad bool or discriminant; invalid or over-long title; bad resize edges; event range violations |
| 4 | `ReservedBitsSet` | yes | header flags or reserved byte; object present when it must be 0; padding; unused slots; reserved bits in bitsets |
| 10 | `InvalidObject` | no | object 0 when required; generation-0 id; never-issued slot |
| 11 | `StaleObject` | no | stale generation; retired slot |
| 12 | `WrongObjectKind` | no | live id of another kind |
| 13 | `LimitExceeded` | no | per-connection or compositor-wide cap; outstanding configures (compositor-internal) |
| 20 | `RoleForbidden` | no | `validate_role` |
| 21 | `RoleAlreadyAssigned` | no | second `AssignRole`; second `CreateWindow` on a surface |
| 22 | `InvalidParent` | no | `validate_parent` |
| 30 | `InvalidFormat` | no | `PixelFormat` or `ColorSpace` discriminant |
| 31 | `InvalidScale` | no | scale 0 (codec); scale ≠ 120 (M10 semantics) |
| 32 | `InvalidLayout` | no | any `BufferLayout::new` failure; `SetSizeLimits` range; configure size or bounds > 4096 |
| 33 | `BufferTooSmall` | no | layout does not fit the attested `byte_len` (#112) |
| 34 | `BufferBusy` | no | attach or commit of a busy buffer; unregister of a busy buffer |
| 35 | `TransferMissing` | no | `RegisterBuffer` without a transfer (#112) |
| 36 | `TransferWrongClass` | no | transfer is not `SharedBuffer` (#112) |
| 40 | `InvalidDamage` | no | more than 5 rects in one `Damage` |
| 41 | `InvalidRegion` | no | more than 3 rects; `Rect::validate` failure; input-region overflow |
| 42 | `NotConfigured` | no | window commit before the first ack |
| 43 | `SerialMismatch` | no | required request serial 0; unknown, consumed or superseded serial; ack on a window-less surface |
| 50 | `UnsupportedFeature` | no | `Cursor` or `Subsurface` roles; non-M10 configure vocabulary; non-negotiated features |
| 51 | `NotPermitted` | no | `CreateWindow` on a role-less or non-`Toplevel` surface; other state violations (#112) |

### Other enums

| Enum | Variants | Maps to |
|---|---|---|
| `GeometryError` | `Overflow`, `EmptyExtent`, `ExtentTooLarge`, `StrideTooSmall`, `StrideTooLarge`, `StrideMisaligned`, `BufferTooLarge`, `OutOfBounds` | `InvalidLayout` in `RegisterBuffer`; `InvalidRegion` in region requests |
| `LookupError` | `Invalid`, `Stale`, `Retired` | `lookup_error_code`: `InvalidObject`, `StaleObject`, `StaleObject` |
| `LimitError` | `Exhausted` | `LimitExceeded` |
| `RawInputDecodeError` | `Truncated`, `ReservedBitsSet`, `UnknownKind`, `InvalidField` | kernel-to-compositor only; never a client protocol error |
| `DisplayWireError`, `InputWireError` | `Malformed` | `EINVAL` |
| `DisplayError` | see [Display ABI](#display-abi-syscall-18) | status sentinels |

### Status sentinels

`graphics::abi::status` mirrors the capability sentinels numerically (`graphics_status_mirrors_capability_syscall_abi` checks this) and adds display statuses. Every status is at least `STATUS_RANGE_START` (`u64::MAX - 4095`); success values are always below it.

| Status | Value | Status | Value |
|---|---|---|---|
| `STATUS_EIO` | `u64::MAX - 4` | `STATUS_ENOSPC` | `u64::MAX - 28` |
| `STATUS_EBADF` | `u64::MAX - 8` | `STATUS_ERANGE` | `u64::MAX - 33` |
| `STATUS_EAGAIN` | `u64::MAX - 10` | `STATUS_ENOSYS` | `u64::MAX - 37` |
| `STATUS_EACCES` | `u64::MAX - 12` | `STATUS_ETIMEDOUT` | `u64::MAX - 109` |
| `STATUS_ENODEV` | `u64::MAX - 18` | `STATUS_ESTALE` | `u64::MAX - 116` |
| `STATUS_EINVAL` | `u64::MAX - 21` | `STATUS_ENOTRECOVERABLE` | `u64::MAX - 130` |

None collides with `NETWORK_STATUS_PENDING` (`u64::MAX - 15`). Capability failures map through `CapabilityError::syscall_status`: bad handle or rights → `EINVAL`; stale or revoked → `ESTALE`; wrong holder, class or right, or not delegable → `EACCES`; capacity → `ENOSPC`.

## Versioning and extension points

- **Version.** `ProtocolVersion { major, minor }`, 1.0 in M10. A major bump is incompatible and rejected at `Hello`. A minor bump may only add opcodes inside the reserved ranges below, and the server may use them only when the negotiated minor allows it.
- **Opcodes.** In 1.0 every reserved or unassigned opcode decodes to `UnknownOpcode` (recoverable). Core growth: requests `0x0002..=0x000F` and unused holes in `0x0010..=0x00FF`; events `0x8003..=0x800F` (`0x8003` is earmarked for `OutputChanged` when `MAX_OUTPUTS > 1`) and unused holes in `0x8010..=0x80FF`. Unassigned: `0x0700..=0x7FFF` and `0x8700..=0xFFFF`.
- **Features.** `Features(u64)`; `Features::KNOWN` = `0x3F` (the OR of `Features::TEXT_INPUT` … `Features::SUBSURFACES`). The M10 compositor offers `Features(0)`, so every feature below is negotiated off and its opcodes are `UnknownOpcode`. The bit assignments and opcode ranges are frozen in `graphics::protocol`.

| Bit | Feature | Opcodes (request / event) | Future content |
|---|---|---|---|
| `1 << 0` | text input | `0x0100..=0x01FF` / `0x8100..=0x81FF` | text commit and preedit, enable and disable (IME) |
| `1 << 1` | presentation detail | `0x0200..=0x02FF` / `0x8200..=0x82FF` | detailed presentation feedback |
| `1 << 2` | relative pointer | `0x0300..=0x03FF` / `0x8300..=0x83FF` | relative motion, pointer lock |
| `1 << 3` | fractional scale | `0x0400..=0x04FF` / `0x8400..=0x84FF` | preferred-scale event; `Scale120` ≠ 120 |
| `1 << 4` | client decorations | `0x0500..=0x05FF` / `0x8500..=0x85FF` | decoration negotiation (`DecorationMode::Client`) |
| `1 << 5` | subsurfaces | `0x0600..=0x06FF` / `0x8600..=0x86FF` | `SurfaceRole::Subsurface`, position and stacking |

Other reserved vocabulary: `SurfaceRole::Cursor` (client cursors), `Layer::Cursor`, `WindowStates` bits other than `ACTIVATED`, `GlobalWindowToken` (shell task list, `GFX_SHELL` only), `ColorSpace` values other than `Srgb`, display subops 7 and above (`SET_MODE`, `RELEASE_PRESENTER`), `OutputChanged`.

**Compatibility shims.** The contract leaves room for Linux (M11: DRM/KMS subset, evdev) and Windows (M13) guest surfaces without adopting their semantics. Shims translate into this protocol as ordinary clients; for example the evdev shim negates `vertical` for `REL_WHEEL`. Nothing in the protocol is a Wayland, X11, DRM or GDI object.

## Event-driven rule and failure states

- **Nothing redraws because time passed.** The compositor wakes only for port notices, raw input, display completions and state changes. Clients render only in response to events (`Configure`, input, `FrameDone`, their own state). There is no periodic tick in any M10 graphics path, and no busy polling.
- **Finite timeouts only.** Every kernel wait on a device has a deadline: `DISPLAY_COMMAND_TIMEOUT_NS` (1 s) per display backend command. A timed-out present completes with `last_error = DeviceTimeout`, moves the backend to `ResetRequired`, and copies nothing (`timeout_enters_reset_required_without_copying`).
- **`ResetRequired`.** `PRESENT` returns `EIO` while the backend resets. A successful reset bumps the `OutputId` epoch and returns to `Idle`; the compositor re-queries the mode, the old epoch is `StaleEpoch`, and it redraws everything.
- **`Poisoned`.** A failed reset, or a reset that would overflow the epoch (`finish_reset_at_max_epoch_poisons`), is permanent for the boot; `PRESENT` returns `ENOTRECOVERABLE`. The compositor keeps serving clients with the last frame on screen.
- **Slow clients.** A client whose event ring stays full for `MAX_CLIENT_STALL_ITERATIONS` (8) consecutive compositor iterations is disconnected with `QueueOverflow`; the compositor never blocks on one client (#112/#200).
- **Input loss** yields `Overflow`, then `InputReset` plus `ModifiersChanged` to the focused client; clients drop pressed-key and button state.

## Scanout ownership

**No direct scanout of client buffers in M10 (S5).** The compositor always composites into a kernel-owned scanout buffer and presents that; a client `SharedBuffer` is never handed to a display backend, never becomes a GOP copy source, and is never attached as a VirtIO-GPU resource. Consequences:

- a client can never change or tear scanout content outside its surface, and cannot observe scanout;
- R8 copy semantics hold on every backend, since only kernel buffers are ever presented;
- `FakeDisplay` never modifies client buffers (`the_display_never_modifies_client_buffers`).

Direct scanout of a fullscreen client buffer is a possible later optimisation. It would need a new feature bit and a new backend contract.

## Non-goals and visual target

M10 non-goals (#109): 3D; OpenGL or Vulkan; Wayland or X11 compatibility; full text shaping; an accessibility stack; multiple monitors; HiDPI perfection (the scale path exists but only 1.0 is accepted); an animation system; any dependency on blur; vendor GPU drivers; an application suite; search, calendar, weather and media widgets. In addition, the #110 contract itself implements no renderer, compositor, driver, visual theme, font shaping or IME.

Visual target (#109, #116; north star `docs/Desktop-design.png`):

- a dark, cinematic desktop with a persistent **left rail**; **no bottom dock**;
- understated, monochrome server-side window chrome; **no macOS-style red, yellow and green traffic-light controls**;
- restrained cyan, magenta and blue accents;
- quality tier **Q0** is fully opaque (`Xrgb8888` everywhere) and must look intentional with effects disabled; **Q1** adds restrained translucency through `Argb8888Premultiplied` surfaces and `over`, with no blur.

## Tests and gate

`cargo xtask test-m10-contract` (alias `m10-contract`) is the #110 gate. It runs:

1. `cargo test -p clean-slate-graphics -p clean-slate-native-abi -p clean-slate-capability`;
2. a `x86_64-unknown-uefi` build of `clean-slate-graphics --features fake`, proving the crate stays `no_std` with the test fakes compiled in;
3. a `x86_64-unknown-uefi` build of `clean-slate-native-abi`.

On success it prints `[M10.contract] PASS`. It is a runner constituent (`scripts/run-tests.sh`, `scripts/run-tests.ps1`) and runs under `--exhaustive`. It boots nothing.

`cargo xtask test-m10-port` (aliases `m10-port`, `m10.200`) is the #200 gate. In order it runs:

1. `cargo test -p clean-slate-native-abi`;
2. `cargo test -p clean-slate-port --features fake`;
3. a `x86_64-unknown-uefi` build of `clean-slate-port` with feature `fake`;
4. `cargo test -p clean-slate-kernel -- service::port sched::work_set sched::wait`;
5. `build_m6_fixture_userspace` and `build_storage_userspace`, since the feature embeds both ELFs;
6. QEMU with feature `m10-port-self-test`, ordered `[M10.port]` markers and a 60 s timeout.

On success it prints `[M10.port] PASS` (not `[M10  ] PASS`, which belongs to #119). It is a runner constituent and runs under `--exhaustive`.

The `fake` feature enables `graphics::fake`: `FakeDisplay`, a model of the display ABI with R8 copy semantics, a single present in flight, timeouts, reset and poisoning. It is for host tests only; production code must not enable it. `clean-slate-port` exposes `FakePort` / `FakeConnection` behind feature `fake` for the same port semantics in host tests (#112).

<<<<<<< HEAD
`cargo xtask test-m10-framebuffer` (alias `m10-framebuffer`) is the #111 gate: `cargo test -p clean-slate-raster`, then a QEMU boot with `-vga std` that proves kernel-internal present, damage-only scanout copy, and guest aperture readback against host `clean-slate-raster` expectations (`[M10.2] PASS`). Screenshot validation is a separate #111 stage: a `QmpScriptDriver` `Screendump` step with a `check` against the host render, writing under `xtask_artifact_root()` (`target/xtask-artifacts/m10-framebuffer/`).

#195 gates (landed): `cargo xtask test-m10-nxe` (alias `m10-nxe`) and `cargo xtask test-m10-shared-buffer` (alias `m10-shared-buffer`); see [DEVELOPMENT.md](DEVELOPMENT.md).

Planned gates, each owned by its lane: `test-m10-virtio-gpu` (#114), `test-m10-desktop` (#118), and `test-m10` with `[M10 ] PASS` (#119).

Contract-level properties that are host-tested today: the size and layout assertions (`frame_layout_assertions`, `abi_size_assertions`, `state_sizes_stay_bounded`), golden frames and round trips for every message, the malformed-frame matrices, negotiation, the role matrix, the buffer handoff property test (`property_buffer_handoff_conserves_buffers`), the scanout model property test (`property_double_buffered_producer_matches_scanout_model`), and the capability `valid_for` and delegation matrices.

## #110 acceptance checklist

Each acceptance item of #110, with the section of this document that records it and the host tests that prove it. "Planned" marks enforcement that lands in a later lane against this contract.

| # | #110 acceptance item | Section | Evidence |
|---|---|---|---|
| 1 | `no_std`-friendly shared types with host tests | [Tests and gate](#tests-and-gate); [Module ownership](#module-ownership) | `cargo xtask test-m10-contract` (host tests plus UEFI builds); `frame_layout_assertions`; `state_sizes_stay_bounded` |
| 2 | Surface memory ownership and producer/compositor synchronization are explicit | [Buffers](#buffers); [Layering and authority split](#layering-and-authority-split) | `superseded_latest_is_released_at_commit_and_old_current_at_latch`; `attaching_a_busy_buffer_fails_on_every_surface_of_the_connection`; `reattaching_the_current_or_latest_buffer_is_buffer_busy`; `property_buffer_handoff_conserves_buffers`; `in_flight_buffer_is_not_writable_and_the_other_one_is`; `the_display_never_modifies_client_buffers` |
| 3 | The protocol references #195 shared buffers through opaque generation-safe handles; no physical addresses cross the app-facing ABI | [Identities and generations](#identities-and-generations); [Buffers](#buffers) | `shared_buffer_id_round_trip_and_rejections`; `shared_buffer_resource_ref_fields`; `shared_buffer_resource_ref_and_revoke_by_full_id`; `object_id_round_trip_and_generation_zero`; `request_body_layout_tiles_with_spec_fields` (`RegisterBuffer` carries only the layout) |
| 4 | No design requires full pixel frames to travel through 64-byte IPC messages | [Wire protocol summary](#wire-protocol-summary) | `frame_layout_assertions`; `golden_frames`; `abi_size_assertions` |
| 5 | Buffer acquire/submit/release lifetime is explicit and stale-safe | [Buffers](#buffers); [Surfaces](#surfaces) | `superseded_latest_is_released_at_commit_and_old_current_at_latch`; `remove_surface_releases_current_then_latest`; `commit_rolls_back_and_passes_resolver_errors_through`; `destroyed_ids_are_stale_for_every_operation_and_reuse_mints_a_new_generation`; `a_released_buffer_can_be_attached_again` |
| 6 | Apps cannot address another surface by guessing an ID | [Identities and generations](#identities-and-generations) (S1) | `the_same_raw_id_names_each_tables_own_object_or_nothing`; `the_same_raw_id_resolves_independently_per_table`; `retirement_only_exhausts_the_retiring_connection`; `retiring_connection_leaves_no_trace_for_the_next_connection`; `wrong_kind_lookups_and_removes_fail_without_side_effects`; `live_slot_with_other_generation_is_stale`. The kernel-stamped `ConnectionId` that selects the table is landed (#200) |
| 7 | Damage and coordinates use checked arithmetic and clipping rules | [Coordinate model](#coordinate-model); [Surfaces](#surfaces) | `checked_right_bottom_extremes`; `validate_rejects_non_representable_extent`; `clip_to_err_on_overflowing_rect_or_bounds`; `buffer_rect_clip_at_u16_max_and_extent`; `rect_set_overflow_collapses_to_bbox`; `buffer_layout_matrix`; `damage_drops_empty_and_out_of_extent_rects_and_clips_the_rest`; `damage_overflow_collapses_to_the_bounding_box_instead_of_failing`; `region_requests_with_an_overflowing_rect_fail_atomically`; `latch_damage_is_clipped_to_the_latched_buffer`; `present_request_validate_matrix` |
| 8 | Logical coordinates and output scale are represented even if M10 uses only scale 1 | [Coordinate model](#coordinate-model) | `attach_rejects_non_unit_scale_first_and_leaves_pending_unchanged`; `send_enforces_m10_vocabulary_without_consuming_a_serial`; `window_config_new_uses_m10_scale_and_server_decorations`; `all_events_round_trip` (`Welcome` with `REFERENCE_MODE` and a separate logical size); `encode_parity_invalid_values` |
| 9 | Alpha-capable surface semantics are defined without requiring translucency/blur in M10 | [Pixels, alpha and colour](#pixels-alpha-and-colour); [Non-goals and visual target](#non-goals-and-visual-target) | `over_fixed_vectors`; `over_clamps_invariant_violating_src`; `over_never_exceeds_255`; `div255_accepts_full_blend_domain`; `opaque_overflow_degrades_to_not_opaque_and_is_sticky_until_replace` |
| 10 | Input events carry no caller-trusted focus identity | [Wire protocol summary](#wire-protocol-summary) (input events); [Raw input records](#raw-input-records) | `raw_input_round_trips_all_kinds` (records carry a device, never a surface); `key_record_layout_tiles`; `event_body_layout_tiles_with_spec_fields`. Focus routing is planned (#112, #115) |
| 11 | Raw key events are distinct from future text-input events | [Versioning and extension points](#versioning-and-extension-points) | `unknown_opcodes` (text-input range is `UnknownOpcode` in 1.0); `negotiate_matrix`; `key_usage_boundaries` |
| 12 | One concrete M10 reference mode/pixel format is frozen for deterministic acceptance | [Reference mode](#reference-mode) | const assertions in `graphics/src/mode.rs`; `buffer_layout_matrix`; `present_request_validate_matrix`; `all_events_round_trip` |
| 13 | Backend-independent API supports UEFI framebuffer and VirtIO-GPU | [Display ABI](#display-abi-syscall-18); [Reference mode](#reference-mode) | `display_abi_round_trips`; `present_request_validate_matrix`; `present_status_decode_matrix`; `completion_copies_only_damaged_pixels`; `property_double_buffered_producer_matches_scanout_model`; `timeout_enters_reset_required_without_copying`. The GOP and VirtIO-GPU backends are planned (#111, #114) |
| 14 | Display/raw-device authority is distinct from application surface authority | [Capability classes and rights](#capability-classes-and-rights) (S10) | `m10_valid_for_masks_exact`; `display_and_input_grant_reject_delegate_via_valid_for`; `display_resource_ref_names_output_index_only`; `display_resource_ref_revoke_is_per_output_index`; `graphics_delegation_refuses_root_only_rights`; `gfx_serve_alone_authorises_no_client_role` |
| 15 | Surface roles cannot be forged to gain trusted-system-overlay authority | [Surface roles](#surface-roles) | `system_overlay_requires_overlay_right`; `overlay_right_does_not_imply_shell_roles`; `delegated_graphics_rights_never_authorise_shell_or_overlay_roles`; `shell_and_overlay_are_root_only_and_connect_is_delegable`; `validate_role_full_matrix_matches_spec_table`; `grant_ignores_every_non_role_bit`; `failed_role_assignment_leaves_the_surface_role_less` |
| 16 | Protocol leaves room for later Linux/Windows surfaces without adopting Wayland/X11/Win32 semantics | [Versioning and extension points](#versioning-and-extension-points); [Non-goals and visual target](#non-goals-and-visual-target) | design property; `negotiate_matrix` and `unknown_opcodes` prove the growth mechanism only |
| 17 | Protocol has a version/feature-negotiation story | [Connection](#connection); [Versioning and extension points](#versioning-and-extension-points) | `negotiate_matrix`; `hello_establishes_and_welcomes_with_negotiated_version_and_features`; `failed_negotiation_is_fatal_with_hello_tag_and_no_welcome`; `second_hello_is_fatal_unsupported_version`; `first_request_other_than_hello_is_fatal_unsupported_version` |
| 18 | Architecture docs record module ownership and thread/process boundaries | [Module ownership](#module-ownership); [Process and thread boundaries](#process-and-thread-boundaries) | [ARCHITECTURE.md](ARCHITECTURE.md) "M10 graphics layering"; [DEVELOPMENT.md](DEVELOPMENT.md) "Kernel source layout" |

Scope notes against the #110 issue text:

- **Capability classes.** The scope lists "shared-buffer/surface" and "window authority" classes. Surfaces and windows are deliberately *not* kernel capabilities: they are connection-scoped compositor objects, and window authority is the `Graphics` role rights. The kernel classes are exactly `SharedBuffer`, `Graphics`, `Display` and `Input`.
- **Focus.** "create/show/hide/move/resize/focus/close" maps to `CreateWindow`, `Show`, `Hide`, `BeginMove`, `BeginResize`, `CloseRequested` / `DestroyWindow`. Focus is compositor policy, reported by `KeyboardFocus` and `Configure` `ACTIVATED`; there is no client focus request.
- **Frame opportunities.** Withholding frame callbacks from occluded surfaces, and the no-busy-poll wake model, are recorded in [Frames](#frames) and [Event-driven rule and failure states](#event-driven-rule-and-failure-states).
- **Reserved syscalls.** Each row of the syscall table above carries its own status. Syscalls 16 and 19 fall through the dispatcher's default arm to `ENOSYS`; 17 and 20 are dispatched to the port and work-set handlers, and 18 to the display handler. Kernel host tests cover the default arm with `dispatch_native_unknown_nr_returns_native_enosys_sentinel` (unrelated number) and `dispatch_native_reserved_m10_nrs_return_enosys`, which lists exactly what is still unimplemented on this tree: 16 and 19, plus syscall 18 subops 3, 4 and 6 (`ENOSYS`) with subop 0 `EINVAL`. The PR that lands later re-composes it (W12).
