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

M3.3 uses the x86-64 `syscall/sysretq` mechanism (not Linux ABI) as the first native userspace/kernel call boundary.

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
- When a slot is revoked, its **generation is bumped** so previously issued handles remain stale even if the slot is later reused for a different resource (reuse policy is separate from `Retired` slots, which are never reused).

### Module ownership (M6.2–M6.7)

| Milestone | Owner |
|-----------|--------|
| M6.2 | Production capability table in `kernel/src/capability/` |
| M6.3 | Persistent-object adapter (`service-fixtures` / `store` userspace) |
| M6.4 | Process-control adapter in `kernel/src/process/` |
| M6.5 | Delegation protocol |
| M6.6 | Revocation graph |
| M6.7 | Audit sink |
| Legacy | `kernel/src/service/capability.rs` and `kernel/src/ipc` endpoint tables — migrate into the unified model |

## Language strategy

The kernel and first-party low-level services should primarily use Rust.

Unsafe Rust and assembly should be concentrated at hardware and ABI boundaries. Most policy, scheduling logic, IPC, capabilities, service orchestration, and userspace code should remain safe Rust wherever practical.

Assembly is expected for narrowly defined x86-64 boundaries such as interrupt stubs, syscall entry, context switching, CPU bootstrap, and special register transitions.
