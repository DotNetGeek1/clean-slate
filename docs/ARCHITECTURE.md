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
- `clean-slate-store` is the first transport-independent on-disk policy layer. Version 1 uses two redundant one-block superblocks at LBA 0 and 1, each containing magic/version/geometry/checksum fields plus a fixed object table; committed object data lives in two disjoint copy-on-write arenas after LBA 1 so a newer generation never overwrites payload blocks still referenced by the currently committed superblock.
- Persistent-store code must depend only on this contract. It must not import VirtIO queue structures, PCI configuration details, MMIO register layouts, or raw DMA descriptors.
- The initial real backend may live in the kernel for bring-up, but that is an implementation detail. The long-term direction remains a restricted driver/service domain once MMIO/IRQ/DMA capabilities exist.
- M5 uses a bounded request/response block wire contract between the userspace storage service and a kernel-hosted bootstrap backend. The public wire format carries only protocol/version/op/request-id/device-id/LBA/count/length/status/geometry fields, never kernel pointers or physical addresses.
- Bootstrap compromise: only the dedicated storage service instance receives raw-block authority at launch time. Ordinary userspace processes must not gain raw block access through generic syscalls or IPC.
- Future direction: replace the kernel-hosted bootstrap backend with a restricted driver domain that speaks the same bounded block wire contract so persistent-store code is unchanged.
- A successful `flush` is the only M5 durability guarantee. Callers may assume that writes completed before the flush survive the backend's reboot/crash model only after the flush succeeds; successful writes without a later successful flush are readable but not yet durable.
- The `clean-slate-store` commit point is the successful return from the `flush` issued after the next-generation superblock write. Because object data for a new generation is written only into the inactive copy-on-write arena and the superblock only into the inactive slot, recovery may expose either the previously committed generation or the new generation, but never metadata from one generation paired with object data from another.
- Host crash tests inject deterministic power loss or I/O failure only at counted block write/flush boundaries via `clean_slate_block::fault::FaultInjectingBlockDevice`, covering every boundary between the first object-data write and the commit flush. Recovery must validate superblock magic/version/checksum, geometry, generation, and object extents/lengths before selecting a committed state, and a corrupted newer superblock must fall back to the older valid one.
- Buffer ownership remains synchronous and call-scoped: backends may inspect caller slices only for the duration of `read_blocks`/`write_blocks` and must not retain raw userspace pointers after the call returns.

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

### Userspace VA window (critical for #92 / #96)

With `PHYSICAL_MEMORY_OFFSET = 0`, the kernel identity-maps physical RAM into the
low half of the canonical address space (low PML4 slots).
`create_process_address_space(user_region_base)` gives each process exactly one
private PML4 slot: `user_region_base >> 39`. Native services use
`user_region_base = 0x0000_4000_0000_0000` (slot 128), so the private user window
is `[0x0000_4000_0000_0000, 0x0000_4080_0000_0000)`.

**All** userspace mappings for a process — native embedded images and any Linux
personality image in M8 — must fall inside that single-slot window.
`LoadPlanPolicy::absolute_user_x86_64()` encodes the broader policy half starting
at `0x0000_4000_0000_0000` (canonical user top exclusive at `1<<47`); in practice
launch paths also stay inside the one owned PML4 slot.

A conventional Linux `ET_EXEC` linked at `0x400000` **cannot** be mapped under
this layout: page zero / low PML4 is kernel identity map, not a private process
slot. M8 Linux fixtures must therefore be linked (or relocated) into the
`0x0000_4000_0000_0000` window. M9+ debt: move the kernel to a higher-half /
non-identity layout so processes can own low PML4 slots and host classic low
`ET_EXEC` bases without a slide.

Execution personality metadata and Linux syscall/errno/stack contracts are owned
by #91 (`clean-slate-linux-abi`); syscall dispatch routing is #93.

M8.2 (#92) reserves the top of the slot for the Linux user stack: two NX+W
stack pages `[0x0000_407F_FFFF_D000, 0x0000_407F_FFFF_F000)`, an unmapped guard
page below at `0x0000_407F_FFFF_C000`, and the slot's last page
`0x0000_407F_FFFF_F000` left unmapped so the stack top is never the window end.
Any PT_LOAD intersecting `[0x0000_407F_FFFF_C000, 0x0000_4080_0000_0000)` is
rejected (`SegmentOverlapsStackReservation`). See
[LINUX_PERSONALITY.md](LINUX_PERSONALITY.md), "M8.2 — ELF loader and process image".

### Linux personality end-to-end path (#97)

With `m8-linux-hello`, boot Starts `LINUX_HELLO_SERVICE_ID` through
`ServiceLifecycleController` (`BuiltinServiceImage::LinuxHello`): runtime load
(#92) → `LinuxX86_64` process → console grant + stdio projection (#95) → Linux
syscall dispatch (#93) → `write`/`exit` (#94) → production teardown. Both demo
kernel tasks keep running alongside Linux (scheduler slot 2). Controller-owned
re-Start yields a new generation and a fresh fd table. See
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

M1 keeps paging and physical-memory policy inside the kernel. The initial implementation intentionally stays conservative:

- only `EfiConventionalMemory` pages from the post-`ExitBootServices` UEFI map are considered allocator-usable;
- the running kernel image and the current early stack are reserved explicitly before allocator setup;
- the kernel relies on the firmware-provided early identity mapping (`phys + 0`) to inspect existing page tables and bootstrap new mappings;
- a high-half test slot at `0xffff_8000_0000_0000` is reserved for controlled map/unmap and page-fault diagnostics.

This keeps M1 trustworthy while leaving a clear path to a richer higher-half kernel layout once dedicated bootstrap page tables and stacks exist.

## M2 interrupt and scheduling direction

M2 extends the kernel beyond the M1 page-fault-only path with a reusable IDT/exception foundation, a post-`ExitBootServices` timer source, and a minimal preemptive scheduler.

Keep interrupt entry/exit stubs, timer acknowledgement, and context-restore assembly narrowly scoped to the x86-64 architectural boundary. Task state, run-queue policy, and completion bookkeeping should remain ordinary Rust data structures so they can evolve independently of the interrupt ABI details.

Single-core correctness is the M2 target, but the design should not bake `current task` or timer ownership into a single global scheduling policy forever. The intended SMP shape is:

- **Per-CPU execution state:** each CPU owns its active interrupt stack, double-fault IST stack, GDT/TSS entries, current-task pointer, interrupt-disabled bookkeeping, and local run-queue cursor.
- **Shared task metadata:** task identity, saved register context, runnable/blocked/finished state, affinity or migration hints, and wakeup reasons stay in globally visible task records.
- **Synchronization boundary:** CPU-local fast paths may read/write only their currently owned task without contention; transitions that change runnable ownership, wake a remote CPU, or publish a newly created task cross an atomic/spinlock boundary.
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

- `IA32_STAR`, `IA32_LSTAR`, `IA32_FMASK`, and `IA32_EFER.SCE` are initialized before the first userspace syscall.
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
- Scheduler run-queue decisions operate on `Thread` state (`Ready`/`Running`/`Exited`) without conflating ownership (`owner_process_id`) with dispatch policy.

PID/TID assignment is monotonic and non-reusing for the life of a boot session. On userspace faults, ownership-aware diagnostics identify the faulting PID and the kernel transitions that process/thread through faulted → exited → reaped cleanup while preserving kernel control flow and unrelated runnable work.

## M3.5 initial capability-authorized IPC direction

The first IPC primitive should keep policy narrow and explicit:

- kernel-owned endpoint objects have explicit create/teardown lifecycle;
- kernel-owned endpoints may expose a narrow sink kind (for M3, a console/test sink) while keeping dispatch policy explicit and non-ambient;
- send permission is represented by an endpoint capability handle bound to one PID;
- syscall-side handle lookup validates slot, generation, and endpoint identity so stale handles cannot silently name reused objects;
- bounded message length and userspace pointer-range checks happen before any kernel dereference/copy;
- endpoint teardown revokes outstanding capabilities by generation, making later sends fail deterministically even if a slot is later reused for a new sink instance.

This initial implementation uses copying and intentionally defers shared-memory/zero-copy optimization to later milestones.

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
- `MonotonicTicks` is an opaque `u64` mapped from kernel LAPIC ticks (`kernel_ticks()` today; userspace syscall later). Deadlines use saturating tick arithmetic only — no wall-clock time.
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
[SVC ] reaped service=<id> pid=<pid>
```

M4.2 adds kernel-owned lifecycle control:

- a dedicated **lifecycle-control capability** (distinct from IPC send capabilities) authorizes `SYSCALL_NR_LIFECYCLE_CONTROL` (4) and bounded M4.1 wire control requests;
- authorized **Start** / **Terminate** / **Restart** requests spawn or tear down built-in service images through production M3 process/domain APIs and `teardown_process_by_id` (#24 coordinator path);
- **Restart** is terminate-then-launch with a bumped `InstanceGeneration` and monotonic PID allocation (IDs are never reused);
- stale instance handles fail through generation checks in the controller and `SYSCALL_ESTALE`.

## M6.1 capability model

M6.1 defines the shared capability contract in workspace crate `clean-slate-capability` (`capability/`). Later milestones implement the kernel table, adapters, delegation protocol, revocation graph, and audit sink; this section fixes vocabulary and invariants only.

### Vocabulary

- **Handle** (`CapabilityHandle`): opaque slot + generation presented by userspace. Knowing a raw handle value is not authority until the kernel validates it against the live table record.
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

**Who may revoke:** the holder of the target capability, or any holder of an ancestor capability (walk `provenance.parent` via `authorize_revoke`). Userspace uses `SYSCALL_NR_CAP_REVOKE` op `REVOKE` (subtree revoke); unauthorized attempts log `[CAP ] revoke denied`.

**PROBE:** `SYSCALL_NR_CAP_REVOKE` op `PROBE` runs the same `authorize_current_class` path as production operations (handle → record class → rights check). Used by fixtures and audit tests as a generic authority probe.

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

**Explicit deferred debt (document only):** legacy per-endpoint IPC send capabilities (`kernel/src/ipc`), lifecycle/block tables in `kernel/src/service/capability.rs`, and M3/M4/M5 service-spawn capability paths are **not** migrated onto the unified `kernel/src/capability/` table in M6.8; they continue to serve their original milestones until a later adapter cutover.

### M6.9 capability-control milestone gate

Authoritative M6 acceptance is `cargo xtask test-m6` (aliases `m6`, `m6.9`): host capability crate and kernel `capability` module tests, then ordered QEMU constituents through M6.8 convergence, ending with `[M6  ] PASS`. See `docs/DEVELOPMENT.md` for constituent order, markers, and debugging flow.

### M6.5 delegation and attenuation

Delegation creates a new capability record for a target holder with a **subset** of the parent’s rights. The kernel path is: resolve the parent record, [`validate_delegation`](../../capability/src/authorize.rs) (parent must hold `DELEGATE`; no widening; class-valid bits only), [`Provenance::child_of`](../../capability/src/provenance.rs) (bounded depth, parent handle stored for M6.6 subtree revocation), then a single transactional [`CapabilityTable::install`](../../capability/src/table.rs). The delegator is always the trusted current holder; target PIDs are validated against the live process registry. **Transfer to the recipient** uses the same bounded bootstrap-grant table as root grants: after a successful `SYSCALL_NR_CAP_DELEGATE`, the kernel registers the new handle for `SYSCALL_NR_CAP_GRANT` claim by the target. Rights never widen; depth is capped at `MAX_DELEGATION_DEPTH` (4 hops below root). Deferred: user-facing sharing UI, cross-machine delegation, and persistent capability state across reboot.

### M6.3 persistent object capability surface

Persistent **object identity** (numeric object id) is separate from **authority** (a `PersistentObject` capability naming that id with a rights subset). Client processes never receive raw block-device authority; they submit bounded read/write requests through `SYSCALL_NR_CAP_OBJECT` while the kernel authorizes the caller’s capability against the requested object id, copies payloads into a fixed-depth request queue, and exposes a **service-role** capability (`ResourceRef::object(OBJECT_SERVICE_ROLE_ID)` with `INSPECT`) only to the userspace storage service. That service dequeues work, performs `ObjectStore` operations over the existing block-capability path, and completes requests back through the same syscall. Each slot carries a monotonic `request_id` (generation per submission); `service_complete` matches on that id **and** `InService` state so completions after client reclaim or id reuse fail with `EINVAL` without touching another client’s slot.

Process teardown (normal or fault) reclaims every queue slot whose `client` matches the exiting holder (`Pending`, `InService`, or unpollled `Done`), preventing fixed-slot exhaustion when clients exit without polling. When the exiting holder still holds a live object **service-role** capability (the same `INSPECT` grant used to authorize `service_next`), any `InService` slots are **requeued to `Pending`** so a replacement storage-service instance can dequeue them; payloads remain kernel-buffered and whole-object read/write operations are retried idempotently at the store layer. Storage-service **restart** issues a new holder PID and a fresh role grant; stale role handles from a prior instance do not authorize. Explicitly deferred: paths/VFS, directories, POSIX permissions, mmap, and persistent process capabilities.

### M6.7 capability audit events

Authorization decisions emit fixed **64-byte** `AuditEvent` records (`sequence`, trusted `actor` holder id, resource class/id, requested rights, wire handle, `AuditOutcome`, delegation `depth`). **No payloads or secrets** are stored. The bounded kernel ring (`BoundedAuditLog<N>`) is the **sole authority for `sequence`** (starts at 1); on overflow the **oldest** event is dropped and a `dropped` counter increments — authorization outcomes are unaffected. Events are recorded from the shared `authorize_current` / `authorize_current_class` hooks so object/process/delegation lanes do not duplicate emission. **Reading** the log requires an `Audit` class capability (`Rights::AUDIT_READ`) via `SYSCALL_NR_CAP_AUDIT_READ` (12); unauthorized reads are denied and audited like any other authorization. Optional serial echo formats lines as `[AUD ] seq=… actor=… class=… resource=… op=… outcome=… depth=…` for self-tests. Deferred: durable persistence, repair-engine (M18) correlation, and operator viewer UI.

### M6.4 process/domain control capabilities

**Process-control** capabilities (`ResourceClass::ProcessControl`, `ResourceRef::process(pid, instance_generation)`) authorize bounded supervision of another live process: `OBSERVE` fills a fixed 32-byte `ProcessObservation` (pid, generation, coarse state, thread count — no memory or register access); `TERMINATE` drives the same **`teardown_process_by_id`** path M4 lifecycle **Terminate** uses (external force-exit, domain resource release, capability revocation for the target). Authorization always uses the **trusted current holder** from scheduler context, never a syscall-supplied PID; the target pid and optional **instance generation** come only from the capability record and must match a **live registry entry** (and generation when nonzero). Missing rights, wrong holder, and invalid handles map to the shared `CapabilityError` syscall statuses; stale targets return `SYSCALL_ESTALE`. Self-terminate is rejected. `ResourceRef.instance_generation` is currently **0** for all processes because PIDs are not reused within a boot (registry liveness lookup already makes stale targets deterministic via `ESTALE`); wiring service `InstanceGeneration` into the lookup is deferred to M6.8/M7. Trusted launch policy registers grants through `grant_process_control` plus the bootstrap-claim table (`SYSCALL_NR_CAP_GRANT`). PIDs are never reused, so caps for torn-down processes go stale without explicit revoke on every syscall. Deferred: signals, debugger attach, and scheduler policy overrides.

## Language strategy

The kernel and first-party low-level services should primarily use Rust.

Unsafe Rust and assembly should be concentrated at hardware and ABI boundaries. Most policy, scheduling logic, IPC, capabilities, service orchestration, and userspace code should remain safe Rust wherever practical.

Assembly is expected for narrowly defined x86-64 boundaries such as interrupt stubs, syscall entry, context switching, CPU bootstrap, and special register transitions.
