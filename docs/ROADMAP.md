# Roadmap

This roadmap is intentionally milestone-driven. Each milestone should produce a concrete, testable capability rather than simply accumulating subsystems.

## M0 — Alive

**Goal:** Boot a Rust Clean-Slate kernel under UEFI in QEMU and print diagnostics to serial.

Acceptance:

```text
CLEAN-SLATE 0.0.1
x86_64
Hello world.
```

Deliverables:

- reproducible QEMU + OVMF launch;
- Rust `#![no_std]` kernel entry;
- serial output;
- development build with symbols;
- debugger attachment path.

## M1 — Memory exists

**Goal:** Establish trustworthy basic memory management.

Deliverables:

- parse boot/UEFI memory map;
- physical page allocator;
- kernel virtual memory layout;
- page-table management;
- page-fault handler with diagnostics;
- host-side tests for allocator/data structures where possible.

## M2 — Time, interrupts, and more than one task

**Goal:** Execute multiple kernel tasks safely.

Deliverables:

- IDT/exception handling;
- timer source;
- scheduler prototype;
- context switching;
- early SMP plan, with single-core correctness first but no architecture that prevents multicore later.

## M3 — Userspace and isolation

**Goal:** Run a process outside the kernel privilege boundary.

Deliverables:

- userspace address spaces;
- syscall entry/exit;
- process/thread model;
- initial IPC primitive;
- domain/resource accounting;
- capability object prototype.

Acceptance: a userspace test process can print through a granted channel and cannot read kernel memory or another process's private pages.

## M4 — Supervisor and recovery prototype

**Goal:** Demonstrate a defining Clean-Slate behaviour early: a failed component can be detected and restarted.

Deliverables:

- userspace supervisor;
- service lifecycle protocol;
- health status;
- dependency metadata;
- restart action;
- fault-injection test.

Acceptance:

```text
service starts
service deliberately crashes
supervisor detects failure
service restarts
system continues without reboot
```

## M5 — Storage

**Goal:** Persist data across a reboot in QEMU.

Deliverables:

- VirtIO block support;
- block service/driver domain direction established;
- minimal persistent filesystem or object store;
- crash-safe test strategy;
- create/read/write/reboot/read acceptance test.

## M6 — Capability-controlled system services

**Goal:** Move useful operations behind explicit capabilities.

Deliverables:

- file/object capabilities;
- process/domain capabilities;
- capability delegation/attenuation design;
- revocation strategy;
- resource teardown on domain exit;
- audit events for capability use.

## M7 — Network foundation

**Goal:** Establish isolated networking suitable for later compatibility runtimes.

Deliverables:

- VirtIO net;
- userspace network service direction;
- network capability/broker prototype;
- DNS/TCP/TLS path, whether native or initially via imported userspace components;
- per-domain network attribution.

## M8 — Linux says hello

**Goal:** Execute an unmodified x86-64 Linux ELF binary expecting Linux ABI behaviour.

Acceptance:

```text
$ ./hello-linux
Hello from Linux.
```

This must be compatibility execution, not a binary rebuilt against Clean-Slate.

## M9 — Useful Linux userspace

**Goal:** Run a meaningful shell/tool environment.

Deliverables:

- enough Linux syscall coverage for BusyBox-class tooling;
- Linux filesystem/path projection;
- process/thread primitives required by common software;
- networking integration.

Acceptance: common shell commands and basic network tooling function inside a Linux application domain.

## M10 — First graphics

**Goal:** Produce a usable graphical surface without touching physical vendor GPUs.

Progression:

1. UEFI framebuffer;
2. basic compositor;
3. keyboard/mouse input;
4. VirtIO GPU;
5. window lifecycle.

Acceptance: native graphical test application opens, renders, receives input, and exits cleanly.

## M11 — Can it run Doom? (Linux)

**Goal:** Run a real Linux Doom port/binary through generic Linux compatibility infrastructure.

This milestone proves a useful combination of:

- graphics;
- input;
- audio/timing as implemented;
- Linux ABI compatibility;
- file access through capability mappings.

Mandatory acceptance activity: actually play it for a few minutes. This is an engineering standard of ancient and impeccable provenance.

## M12 — Linux desktop applications

**Goal:** Demonstrate substantial real application compatibility.

Target sequence:

- Git;
- VLC/GIMP-class app;
- VS Code;
- Firefox.

VS Code is particularly valuable because it exercises Electron/Chromium-style userspace assumptions, filesystem access, threading, graphics, IPC, and networking.

## M13 — Windows runtime bootstrap

**Goal:** Execute a simple unmodified Windows PE application.

Preferred strategy:

- bootstrap using Wine/Proton technology rather than reimplementing NT/Win32 from zero;
- initially host through Linux compatibility if that accelerates delivery;
- keep Windows state inside a per-application domain.

Acceptance: a simple representative Windows application launches through generic compatibility infrastructure.

## M14 — Can it run Doom? (Windows)

**Goal:** Run the Windows version of Doom through the Windows compatibility path.

This introduces/validates graphics API translation and Windows runtime behaviour.

## M15 — Windows VS Code

**Goal:** Run Windows VS Code alongside Linux VS Code and native Clean-Slate applications.

Acceptance includes shared user-selected project data without granting either runtime ambient access to the entire machine.

## M16 — Cross-runtime interoperability

**Goal:** Make compatibility useful rather than merely demonstrative.

Canonical test:

1. Linux Firefox downloads an archive.
2. Windows 7-Zip opens it.
3. A project is extracted.
4. Linux VS Code opens it.
5. Linux tooling builds it.
6. A native or compatibility application consumes the output.
7. Clipboard and explicit file sharing work across domains.
8. Reboot and continue.

## M17 — Real hardware bring-up

Real hardware starts earlier in limited form, but this milestone means practical bare-metal operation is becoming a first-class target.

Target capabilities:

- UEFI boot from USB/disk;
- real memory map/ACPI handling;
- NVMe;
- USB input;
- framebuffer/display path;
- Ethernet;
- controlled use of Linux driver domains for unsupported hardware.

Use a dedicated expendable test disk during early write support.

## M18 — Repair engine

**Goal:** Move from simple restart logic toward structured diagnosis and recovery.

Deliverables:

- system dependency graph;
- event/change history;
- behavioural baselines;
- anomaly detection;
- bounded repair policy;
- rollback;
- disposable test environments for candidate fixes;
- measurable repair outcomes.

Example acceptance: introduce a deliberately faulty driver/service update, detect the regression, test rollback, restore the previous working component, and record the causal chain without rebooting where possible.

## M19 — Privacy/security demonstrator

**Goal:** Prove that isolation is visible and enforceable.

Acceptance examples:

- app without network capability cannot connect;
- app granted one file cannot enumerate unrelated files;
- application-to-application IPC is denied without an explicit channel;
- a compromised test domain cannot access another domain's memory;
- privacy ledger attributes file/device/network access;
- driver DMA is constrained by IOMMU on supported real hardware.

## Clean-Slate 1.0 acceptance target

Boot an ordinary x86-64 UEFI PC, log into a local account, connect to the network, and run representative native, Linux, and Windows applications side by side.

Required demonstration set should include at least:

- Linux Git;
- Linux VS Code;
- Linux Doom;
- Linux Firefox;
- Linux VLC or GIMP;
- Windows VS Code;
- Windows Doom;
- Windows 7-Zip or Notepad++-class application;
- one native Clean-Slate GUI application.

Applications must interoperate through explicit Clean-Slate-controlled resources, survive reboot, remain independently sandboxed, and expose attributable resource/network behaviour.

That is the line at which Clean-Slate stops being merely a hobby kernel and becomes a credible compatibility-focused operating system research platform.
