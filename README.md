# Clean-Slate

**Clean-Slate** is an experimental x86-64 desktop operating system project built around a simple question:

> What would a personal computer operating system look like if reliability, efficiency, isolation, privacy, compatibility, and machine-assisted maintenance were requirements from line one?

The project is intentionally a clean-sheet design. It is not intended to be another Unix clone with a different desktop, nor a rewrite of Windows. The aim is to explore a small, deterministic core surrounded by isolated, restartable services and application domains, while retaining practical compatibility with existing Linux and Windows software.

## Project status

`cargo xtask run` builds the kernel with no Cargo features and boots it under QEMU with a persistent data disk, `target/system-data.img`. The boot tail in `kernel/src/boot/mod.rs` launches userspace init (`supervisor/src/bin/init.rs`), which starts the storage service, waits for it to report ready, starts the network service, and then sleeps until a service changes state. The first boot formats the data disk and later boots mount it. Without `--net` there is no network device; `cargo xtask run --net` adds one connected to the hermetic network fixture. The default image does not run a shell, a desktop or a Linux process; those are separate feature builds. Feature builds (other than `gdb-entry` alone) that reach the end of boot start the two kernel demo threads (`kernel/src/sched/demo_tasks.rs`) instead of init.

The milestone gates are separate kernels, each checking the markers named by `cargo xtask` help:

- `test-m1` and `test-m2` build those self-test kernels and check their PASS markers.
- `test-m3` runs the M3 acceptance boots in order.
- `test-m4` is the recovery QEMU boot plus the M4.6 host policy tests.
- `test-m5` is the block, storage, persistence, and crash-recovery acceptance.
- `test-m6` is the capability host tests plus the fixture-smoke and QEMU constituents.
- `test-m7` checks the network service against the hermetic fixture, whose TLS trust anchor is the committed test CA.
- `test-m8` runs one static Linux hello ELF.
- `test-m9` runs the 18 BusyBox commands in `fixtures/busybox/frozen/commands.toml`. `install_stdio_entries` opens file descriptors 1 and 2 only, so that gate has no stdin and is not an interactive shell.
- `test-m10` runs every `test-m10-*` constituent, the `clean-slate-ui` host tests, and `test-qmp-smoke`, then `test-m10-desktop`. The compositor, desktop shell, and playground are in this tree. `cargo xtask run` does not enable `m10-desktop`, so it does not launch them.

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

This section records the original plan. Current state is under [Project status](#project-status).

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

## Licence

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

That dual licence covers the Rust code in this repository. It does not cover
third-party material listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). `fixtures/busybox/frozen/busybox`
is BusyBox 1.37.0 under GPL-2.0 only.
