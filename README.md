# Clean-Slate

**Clean-Slate** is an experimental x86-64 desktop operating system project built around a simple question:

> What would a personal computer operating system look like if reliability, efficiency, isolation, privacy, compatibility, and machine-assisted maintenance were requirements from line one?

The project is intentionally a clean-sheet design. It is not intended to be another Unix clone with a different desktop, nor a rewrite of Windows. The aim is to explore a small, deterministic core surrounded by isolated, restartable services and application domains, while retaining practical compatibility with existing Linux and Windows software.

## Project status

Very early research/design phase. The immediate engineering target is a Rust kernel booting under UEFI in QEMU with serial diagnostics. Real hardware comes later, after the execution, memory, IPC, capability, and device models are stable enough to debug sensibly.

## Design principles

- **Boring kernel, ambitious userspace.** Keep scheduling, virtual memory, IPC, interrupts, capabilities, timers, and essential hardware control in the kernel. Push fallible components outward.
- **Everything disposable where possible.** Drivers, system services, applications, and compatibility runtimes should be restartable or replaceable without rebooting the machine.
- **Capability security.** Applications receive explicit authority to resources rather than inheriting ambient access to a user's whole machine.
- **Application isolation by default.** Every application runs in its own revocable security domain; risky or legacy workloads can escalate to a hardware-backed microVM.
- **Local-first privacy.** No mandatory cloud account. No implicit telemetry. Network access is a capability, not a birthright.
- **Observable systems.** Changes, failures, resource use, dependencies, and data flows should be attributable and auditable.
- **Transactional state.** System and application updates should be atomic and rollback-friendly.
- **Resource efficiency is a feature.** Memory, CPU, disk, GPU, and network use should be measurable and accountable.
- **Compatibility is first-class.** Existing Linux and Windows applications should be usable without forcing the Clean-Slate core to inherit all of their historical assumptions.
- **Adaptive, not magical.** Self-healing should come from health models, dependency graphs, anomaly detection, policy, rollback, and controlled experiments—not an unbounded AI with kernel privileges.

## Definition of success

A meaningful end-user acceptance test for the project is:

1. Boot Clean-Slate on an ordinary x86-64 UEFI PC.
2. Log into a local account.
3. Discover storage, input, graphics, network, and audio hardware.
4. Install and run real Linux applications such as Git, VS Code, Doom, Firefox, and VLC or GIMP.
5. Install and run Windows versions of representative applications, including VS Code and Doom.
6. Allow Linux, Windows, and native Clean-Slate applications to safely operate on shared user-selected data.
7. Suspend/resume and reboot without losing application state or corrupting the system.
8. Keep applications isolated from one another except where the user explicitly grants communication.

And yes: **it must run Doom.**

## High-level architecture

```text
Hardware
   |
   v
+-------------------------------+
|        Clean-Slate Kernel     |
| scheduler / VM / IPC / IRQ    |
| capabilities / IOMMU / timers |
+---------------+---------------+
                |
   +------------+-------------+------------------+
   |            |             |                  |
 Device      System       Application       Compatibility
 Runtime     Services        Domains           Runtimes
   |            |             |                  |
 Drivers     FS / Net      Native Apps      Linux / Windows
   |         GPU / Audio       |                  |
   +------------+-------------+------------------+
                |
        Supervisor / Repair
        Observability / Policy
```

The kernel is expected to be primarily Rust (`#![no_std]`) with narrowly contained `unsafe` code and small architecture-specific assembly where x86-64 requires it.

## Documentation

- [Vision](docs/VISION.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Security & Privacy](docs/SECURITY-PRIVACY.md)
- [Compatibility Strategy](docs/COMPATIBILITY.md)
- [Native SDK & Applications](docs/SDK-APPLICATIONS.md)
- [Development & Testing](docs/DEVELOPMENT.md)
- [Roadmap](docs/ROADMAP.md)

## Initial technical direction

The first development environment will use x86-64, UEFI, Rust, QEMU, OVMF, VirtIO devices, serial logging, and GDB/debug-symbol support.

The first milestone is deliberately tiny:

```text
QEMU + UEFI
     |
     v
Clean-Slate kernel
     |
     v
serial console

CLEAN-SLATE 0.0.1
x86_64
Hello world.
```

From there: memory management, exceptions, scheduling, userspace, IPC, capabilities, device isolation, storage, recovery, Linux compatibility, graphics, and eventually Windows compatibility.

## Non-goals (for now)

- Reimplement every Windows API from scratch.
- Support arbitrary physical PC hardware during the first kernel milestones.
- Put an LLM in the kernel.
- Make Linux the hidden foundation of the OS.
- Build a browser, IDE, media stack, and office suite before the OS becomes useful.
- Sacrifice architecture for a one-off application demo.

Clean-Slate should be architecturally new **without requiring the software and hardware world to start over with it**.
