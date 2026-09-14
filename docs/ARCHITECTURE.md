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

## Language strategy

The kernel and first-party low-level services should primarily use Rust.

Unsafe Rust and assembly should be concentrated at hardware and ABI boundaries. Most policy, scheduling logic, IPC, capabilities, service orchestration, and userspace code should remain safe Rust wherever practical.

Assembly is expected for narrowly defined x86-64 boundaries such as interrupt stubs, syscall entry, context switching, CPU bootstrap, and special register transitions.
