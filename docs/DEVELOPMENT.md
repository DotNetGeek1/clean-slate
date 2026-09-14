# Development & Testing

## Primary environment

Clean-Slate should be developed in a virtual machine first and moved to real hardware deliberately.

The primary early stack is:

- QEMU;
- OVMF UEFI firmware;
- x86-64;
- Rust;
- VirtIO devices;
- serial diagnostics;
- GDB/debug symbols.

QEMU is the laboratory. Real hardware is the exam.

## Why VM-first

A VM makes early kernel work reproducible and observable:

- crashes are cheap;
- machine configuration is deterministic;
- CPU/RAM/device configurations are scriptable;
- serial output is easy to capture;
- a debugger can attach before execution;
- snapshots make destructive tests repeatable;
- automated integration tests can boot the real kernel in CI.

Physical hardware remains essential later because firmware, interrupt routing, power management, storage, USB, GPUs, and platform quirks eventually need real validation.

## First development loop

The current loop is one command:

```bash
cargo xtask run
```

This command:

1. builds the Rust `#![no_std]` UEFI kernel artifact;
2. creates an EFI boot directory at `target/esp/EFI/BOOT/BOOTX64.EFI`;
3. launches QEMU with OVMF firmware;
4. connects serial output to the host terminal.

To launch paused for debugger attach:

```bash
cargo xtask run-gdb
```

That mode enables a GDB endpoint on `localhost:1234` and starts with CPU execution paused.

To make kernel-entry stop reproducible in M0:

```bash
cargo xtask run-gdb-entry
```

This builds the kernel with a debug-entry trap at the start of `efi_main`, then launches paused with GDB endpoint `localhost:1234`.

If OVMF is not installed in common distro paths, set:

```bash
export OVMF_CODE=/path/to/OVMF_CODE.fd
export OVMF_VARS=/path/to/OVMF_VARS.fd
```

## Diagnostics first

Serial logging should exist before significant kernel subsystems are added.

Example output:

```text
[BOOT] Clean-Slate 0.0.1
[BOOT] UEFI handoff OK
[MEM ] physical allocator initialized
[MM  ] paging initialized
[INT ] exception handlers installed
[KERN] initialization complete
```

A page fault should report enough state to investigate without a graphical console.

## Debugging

QEMU should support launching paused with a debugger endpoint.

Debug symbols must be preserved in development builds so GDB (or a later Rust-friendly debugger) can resolve functions and stack traces.

Expected workflows include breakpoints in kernel entry, page-fault handlers, scheduler paths, syscalls, and device initialization.

### Reproducible kernel-entry handoff (M0)

1. Start QEMU with debug-entry mode:

   ```bash
   cargo xtask run-gdb-entry
   ```

2. In another terminal, start GDB with the built image:

   ```bash
   gdb target/x86_64-unknown-uefi/debug/clean-slate-kernel.efi
   ```

3. Attach and continue:

   ```gdb
   target remote :1234
   continue
   ```

4. GDB will stop on a trap once `efi_main` is executing (`SIGTRAP`). From there, single-step or set additional breakpoints.

## Test layers

### Host unit tests

Logic that does not genuinely require privileged execution should be extracted into testable crates and run through ordinary Rust tests.

Examples:

- parsers;
- capability tables;
- object/reference management;
- allocators where possible;
- filesystem data structures;
- scheduling algorithms;
- protocol encoding/decoding;
- policy and repair logic.

These tests should remain fast enough to run constantly.

### QEMU integration tests

Integration tests should boot a real Clean-Slate kernel headlessly and communicate results through serial output or a dedicated test channel.

Representative tests:

- boot;
- physical memory initialization;
- paging;
- exceptions;
- syscall boundary;
- process isolation;
- IPC;
- capability transfer/revocation;
- VirtIO block;
- filesystem persistence;
- service restart;
- driver restart;
- update rollback.

The VM should shut down automatically with a machine-readable pass/fail result.

### Real hardware tests

A dedicated development/sacrificial machine should be used before Clean-Slate is trusted on important hardware.

Initial real-hardware targets should be deliberately boring:

- standard x86-64 UEFI platform;
- integrated graphics or simple framebuffer path;
- NVMe;
- Ethernet before difficult Wi-Fi where possible;
- USB keyboard/mouse;
- dedicated test drive.

Do not initially grant write access to a development machine's important Windows/Linux system disk.

## Machine profiles

QEMU machine configurations should be committed to the repository so regressions can be reproduced.

Examples:

```text
minimal       1 CPU, low RAM
standard      common development target
multicore     high concurrency stress
low-memory    memory pressure
recovery      fault-injection environment
```

Configurations should eventually be invokable by name.

## Fault injection

Because recovery is a defining Clean-Slate feature, fault injection must be part of ordinary testing rather than a late add-on.

The test environment should eventually support deliberately:

- killing a driver/service;
- hanging a service;
- exhausting memory;
- delivering malformed IPC;
- failing block operations;
- simulating unexpected device responses;
- corrupting test state;
- interrupting updates;
- comparing behaviour before/after rollback.

A successful test should prove recovery of the affected service without rebooting where architecture permits.

## Multiprocessor testing

QEMU profiles should cover one CPU and many CPUs early.

Scheduler, allocator, IPC, capability, and locking code must not accidentally rely on single-core execution.

## Graphics progression

Do not start with physical GPU drivers.

Preferred order:

1. serial console;
2. UEFI framebuffer;
3. VirtIO GPU;
4. basic compositor/input;
5. Linux graphics/driver-domain experiments;
6. selected physical GPU support.

## Storage safety

Storage code is destructive when wrong.

Early persistence should use disposable VM disk images. Real hardware storage tests should use a dedicated expendable disk until block and filesystem layers have extensive automated coverage.

## CI target

A major engineering goal is for every commit to be able to run:

```text
host unit tests
       +
headless QEMU kernel tests
```

without a human rebooting a machine.

That testability is part of the architecture, not merely build infrastructure.
