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

## Language strategy

The kernel and first-party low-level services should primarily use Rust.

Unsafe Rust and assembly should be concentrated at hardware and ABI boundaries. Most policy, scheduling logic, IPC, capabilities, service orchestration, and userspace code should remain safe Rust wherever practical.

Assembly is expected for narrowly defined x86-64 boundaries such as interrupt stubs, syscall entry, context switching, CPU bootstrap, and special register transitions.
