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
4. connects serial output to the host terminal for a normal interactive boot.

For the bounded M1 memory acceptance path:

```bash
cargo xtask test-m1
```

This command builds the kernel with the M1 self-test mode enabled, boots QEMU headlessly, enforces a timeout, and validates the required serial markers including the deliberate page-fault diagnostic and `[M1  ] PASS`.

For the bounded M2 interrupt/timer/scheduler acceptance path:

```bash
cargo xtask test-m2
```

This command runs three bounded headless QEMU boots:

1. a double-fault acceptance path that proves vector 8 runs on its dedicated IST emergency stack;
2. a standalone timer acceptance path that proves the kernel receives a bounded minimum number of monotonic LAPIC ticks;
3. the scheduler/preemption acceptance path that proves reusable interrupt setup, timer-driven preemption, and two kernel tasks making progress before `[M2  ] PASS`.

The shared acceptance runner treats the ordered serial PASS markers as authoritative, terminates QEMU from the host as soon as those markers arrive, and only falls back to `isa-debug-exit` or the timeout path if the expected sequence never completes. This keeps the test reliable on hosts where the guest can print PASS but QEMU does not shut down cleanly on its own.

M2 intentionally treats the LAPIC timer as an uncalibrated periodic tick source for now. The contract is in ticks, not Hertz: the kernel reports the divide configuration and initial count, exposes a monotonic `[TIME] ticks=<n>` counter, and the standalone timer acceptance requires at least the documented minimum number of ticks within the bounded test window.

For the bounded M3.1 userspace-entry acceptance path:

```bash
cargo xtask test-m3-entry
```

This command builds the kernel with the M3.1 userspace-entry self-test enabled, boots QEMU headlessly, and validates the ordered markers for:

1. explicit CPL3 entry with a deliberate user `RIP`, `RSP`, `CS`, `SS`, and `RFLAGS`;
2. a controlled return to the kernel through the dedicated DPL3 rendezvous gate; and
3. a deterministic privileged-instruction (`cli`) denial from ring 3 with useful fault context before `[M3.1] PASS`.

For the bounded M3.2 address-space isolation acceptance path:

```bash
cargo xtask test-m3-address-space
```

This command builds the kernel with the M3.2 address-space self-test enabled, boots QEMU headlessly, and validates the ordered markers for:

1. creation of two distinct per-process address-space roots;
2. a successful switch between those address spaces while the same user virtual address resolves to different private frames;
3. a ring-3 kernel-memory read denial and a cross-process private-memory read denial before `[M3.2] PASS`.

For the bounded M3.3 native-syscall acceptance path:

```bash
cargo xtask test-m3-syscall
```

This command builds the kernel with the M3.3 syscall self-test enabled, boots QEMU headlessly, and validates the ordered markers proving timer-enabled repeated ring-3 `syscall/sysretq` round-trips and `[SYSC] syscall entry/return PASS`.

For the bounded M3.4 process/thread lifecycle acceptance path:

```bash
cargo xtask test-m3-lifecycle
```

This command builds the kernel with the M3 userspace address-space self-test path, boots QEMU headlessly, and validates ownership-aware process/thread lifecycle markers including deterministic creation (`[PROC] created pid=... tid=...`), fault attribution (`[PROC] fault pid=...`), and teardown (`[PROC] pid=... exited status=...`) before `[M3.4] PASS`.

For the bounded M3.5 capability-authorized IPC acceptance path:

```bash
cargo xtask test-m3-ipc
```

This command builds the kernel with the M3.5 IPC self-test enabled, boots QEMU headlessly, and validates ordered capability and IPC markers proving explicit grant (`[CAP ] endpoint capability granted pid=1`), successful bounded send (`[IPC ] send OK bytes=...`), deterministic unauthorized denial (`[CAP ] unauthorized send denied pid=2`), and endpoint lifecycle completion before `[M3.5] PASS`.

For the bounded M3.6 domain resource-accounting and teardown acceptance path:

```bash
cargo xtask test-m3-resources
```

This command builds the kernel with the dedicated M3.6 resource self-test enabled, boots QEMU headlessly, and validates ordered markers proving:

1. baseline resource accounting (`[RES ] baseline pages=...`);
2. live per-domain ownership snapshots (`[RES ] pid=... pages=... handles=... threads=...`);
3. production teardown returning each terminated domain to zero owned scheduler/IPC state (`[PROC] teardown pid=... resources=0`); and
4. repeated create/run/exit plus create/run/fault cycles that exceed the fixed process-table lifetime capacity before `[M3.6] PASS`.

If the M3.6 run fails, start from the last emitted `[RES ]` or `[PROC]` marker to see which phase leaked or failed to reap. For deeper debugging, rerun with `cargo xtask run-gdb` and break in `process::domain::teardown_current_process`, `ipc::IpcEndpointTable::teardown_resources_for_pid`, or `sched::Scheduler::reap_threads_for_process`.

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

## Kernel source layout

`kernel/src/lib.rs` is a thin crate-composition file: crate attributes, the module list, the three `pub` re-exports `main.rs` needs (`serial_write_line`, `serial_write_fmt`, `qemu_exit_failure`) and `pub fn run()`, which forwards to `boot::run`. Everything else lives in subsystem modules inside the same `clean-slate-kernel` crate; there are no extra workspace crates.

```text
kernel/src
├── lib.rs                 crate attrs, mod list, 3 pub re-exports, run()
├── main.rs                UEFI entry; unchanged by the layout
├── arch/x86_64/           CPU mechanism only (no policy)
│   ├── port.rs, msr.rs    port and MSR wrappers
│   ├── cpu.rs             interrupt enable/disable, halt, CR0.WP toggling, bit helpers
│   ├── interrupt_context.rs  InterruptContext, UserspaceEntryFrame, SyscallContext layouts
│   ├── idt.rs, gdt.rs     IDT install, GDT/TSS/IST, userspace selectors, DOUBLE_FAULT_STACK
│   ├── apic.rs            LAPIC/PIC register access and timer programming
│   ├── context_switch.rs  TaskStack, task frames, NEXT_TASK_* hand-off (set_next_task/next_task)
│   └── asm.rs             the single global_asm! block and the extern "C" symbol declarations
├── boot/
│   ├── mod.rs             run/run_inner, boot ordering, feature-gated dispatch into selftest
│   └── uefi.rs            memory-map normalization and reserved-range collection
├── mm/
│   ├── mod.rs             PAGE_SIZE, PHYSICAL_MEMORY_OFFSET
│   ├── region.rs          MemoryRegion, ReservedRange, NormalizedMemoryMap
│   ├── frame_allocator.rs PageAllocator (physical frames)
│   ├── paging.rs          page-table walking, current root frame, zero_page
│   ├── address_space.rs   per-process roots, kernel-root sanitization/validation
│   └── user_mapping.rs    map/unmap of userspace pages and mapping validation
├── process/               Process, ResourceDomain, ProcessRegistry, teardown coordinator; id_allocator.rs, domain.rs
├── sched/                 Thread, Scheduler, TASK_STACKS; dispatch.rs (start/schedule), demo_tasks.rs
├── ipc/                   endpoint table, capabilities, send path
├── syscall/               syscall dispatch (mod.rs) and return-state validation (validation.rs)
├── interrupt/             exception/IRQ dispatch and handlers (mod.rs), timer tick policy (timer.rs)
├── diagnostics/           serial.rs, log.rs, qemu.rs (exit codes, halt_loop, fatal error), gdb.rs
├── sync/global_cell.rs    GlobalCell<T>
└── selftest/              milestone acceptance scaffolding, one file per milestone
    ├── mod.rs             feature-gated mod decls; shared USER_TEST_* address constants
    ├── m1_memory.rs, m2_double_fault.rs, m2_timer.rs
    └── m3_entry.rs, m3_address_space.rs, m3_resources.rs, m3_syscall.rs, m3_ipc.rs
```

Conventions:

- **Visibility.** The crate's `pub` surface is exactly the four items `main.rs` imports. Everything shared across modules is `pub(crate)`; items shared only within a subsystem are `pub(super)`; everything else is private. Adding a new `pub(crate)` is a reviewed decision.
- **Dependency direction.** `arch::x86_64` provides mechanism and must not import `sched`, `process`, `ipc`, `syscall`, `interrupt` or `selftest`. Policy modules depend downward on `arch`, `mm`, `sync` and `diagnostics`. The assembly block calls `clean_slate_interrupt_dispatch`, `clean_slate_syscall_dispatch`, `clean_slate_task_one`/`two` and `clean_slate_timer_self_test_task` by symbol only; those Rust functions live in `interrupt`, `syscall`, `sched::demo_tasks` and `selftest::m2_timer`.
- **State ownership.** Global state lives with the subsystem that owns it; there is no central `state.rs`. Cross-module access goes through narrow owner accessors rather than `pub(crate)` statics: `sched::{with_scheduler, scheduler_mut, task_stacks_mut}`, `process::process_registry_mut`, `process::id_allocator::id_allocator_mut`, `ipc::endpoint_table_mut`, `arch::x86_64::context_switch::{set_next_task, next_task}`, `mm::address_space::{kernel_root_frame, set_kernel_root_frame}`, `interrupt::set_expected_page_fault_address`, `interrupt::timer::{kernel_ticks, reset_kernel_ticks}`. The `*_mut` accessors are `unsafe fn` and preserve the exact `&'static mut` access pattern the call sites already had. Statics that assembly reads or writes directly (`NEXT_TASK_*`, `SYSCALL_KERNEL_STACK_TOP`, `SYSCALL_SCRATCH_USER_RSP`) stay `#[no_mangle]` next to their consumers and are never renamed.
- **Self-test hooks.** Production code reaches `selftest` from exactly three places: `boot::run_inner`, `interrupt` dispatch/exception handling, and the `syscall` handlers. `mod selftest` itself is always compiled because `selftest::m2_timer` owns the `clean_slate_timer_self_test_task` symbol that the assembly trampoline references unconditionally; every other selftest submodule is gated on its milestone feature. Reusable logic is not moved into `selftest` just because only tests use it today.
- **Dead code.** Production modules must build warning-free in every feature configuration; there is no crate-level `allow(dead_code)`. The allowance is scoped to `mod selftest` under the self-test features (milestones exit QEMU before the boot tail, so each build leaves some of its own scaffolding unreferenced). The four boot-tail entry points that self-tests skip (`interrupt::timer::{initialize_timer, report_timer_contract}`, `sched::dispatch::{initialize_scheduler, start_scheduler}`) carry a feature-conditioned `cfg_attr(..., allow(dead_code))` with a comment; because rustc treats allowed items as liveness roots, that also covers what they call. Anything else that goes dead under a feature should have its `cfg` gate narrowed to match its real users rather than be silenced.
- **Tests.** `#[cfg(test)] mod tests` sits beside the implementation it exercises (`boot::uefi`, `mm::frame_allocator`, `mm::paging`, `mm::address_space`, `process`, `process::id_allocator`, `sched`, `ipc`, `syscall::validation`, `arch::x86_64::{gdt, interrupt_context}`). The tests that exercise feature-gated code live in their `selftest/m3_*.rs` under the same feature gate. Run `cargo test -p clean-slate-kernel` for the default set and add `--features <milestone>` to include the gated ones.
- **`unsafe` and assembly.** New `unsafe fn` items carry a `# Safety` section. `global_asm!` is confined to `arch/x86_64/asm.rs`, whose header lists each label the block defines and the Rust symbol or static it consumes. `extern "C"` declarations for assembly labels live next to the block; the Rust side of each contract (`no_mangle` functions) lives with its owning module.
- **File size.** Roughly 800 lines is a soft signal that a module wants splitting, not a rule; `selftest/m3_address_space.rs` is the deliberate exception.

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

M2 intentionally targets one running CPU, but task bookkeeping should stay separable from CPU-local execution state so a later SMP step can move `current task`, timer source, and interrupt-entry scratch state per-CPU without redesigning the runnable task model.

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
