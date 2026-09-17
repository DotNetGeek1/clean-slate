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

For the aggregate M3 milestone gate:

```bash
cargo xtask test-m3
```

This command runs five bounded headless QEMU boots in a fixed order, each with the same 20-second timeout and ordered serial-marker validation as its standalone counterpart:

1. `m3-entry-self-test`, validated against the M3.1 markers (CPL3 entry and privileged-instruction denial);
2. `m3-entry` plus `m3-syscall` self-test, validated against the M3.3 markers (`syscall/sysretq` round-trip);
3. `m3-address-space-self-test` once, validated against a merged M3.2 and M3.4 marker list (kernel-memory read denied, cross-process read denied, faulting `pid=1` terminated while `pid=2` exits cleanly, address-space teardown OK, then `[M3.2] PASS` followed by `[M3.4] PASS`);
4. `m3-ipc-self-test`, validated against the M3.5 markers (granted endpoint send OK, unauthorized send denied);
5. `m3-resources-self-test`, validated against the M3.6 markers (`teardown ... resources=0` and `[M3.6] PASS`).

Step 3 deliberately boots the address-space self-test only once: that single boot already proves both isolation (M3.2) and fault attribution/lifecycle (M3.4), so the gate reuses it rather than booting the same image twice. The host prints `[M3  ] step i/5 <name>` before each boot and `[M3  ] PASS` only after all five succeed. Any build failure, QEMU failure, missing or out-of-order marker, or timeout aborts the run with an error and no `[M3  ] PASS` is printed. Guest-emitted milestone markers remain authoritative for each boot; the host marker is the aggregate result. `cargo xtask run` is unchanged.

The individual M3.1–M3.6 commands below are the per-boundary debugging workflows: use them when the gate reports a failing step or when a specific boundary regresses.

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

This command builds the kernel with the M3.5 IPC self-test enabled, boots QEMU headlessly, and validates ordered capability and IPC markers proving explicit grant (`[CAP ] endpoint capability granted pid=1`), userspace payload delivery through the kernel-owned console sink (`[IPC ] console pid=1: hello from pid 1`), successful bounded send (`[IPC ] send OK bytes=...`), deterministic unauthorized denial (`[CAP ] unauthorized send denied pid=2`), and endpoint lifecycle completion before `[M3.5] PASS`.

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

For the M4.1 service lifecycle protocol (host-tested, no QEMU boot required):

```bash
cargo test -p clean-slate-service-lifecycle
```

This crate is `no_std` outside unit tests and is the shared contract for supervisor, kernel control, and service fixtures in later M4 issues.

For the M6.1 capability contract (host-tested):

```bash
cargo test -p clean-slate-capability
```

For M4.2 kernel lifecycle control (host tests + optional QEMU acceptance):

```bash
cargo test -p clean-slate-kernel service::
cargo test -p clean-slate-kernel --features m4-service-lifecycle-self-test
cargo xtask test-m4-service-lifecycle
```

The `m4-service-lifecycle-self-test` feature boots a bounded launch/terminate/restart path and emits `[M4.2] PASS` when fresh PID/generation invariants hold.

For the M4.3 userspace supervisor runtime (host-tested registry/control + optional QEMU integration):

```bash
cargo test -p clean-slate-supervisor
cargo xtask test-m4-supervisor
```

The `clean-slate-supervisor` crate (`supervisor/`) owns the bounded service registry and supervisor runtime. Lifecycle control is behind the mockable `LifecycleControl` trait so host tests and the CPL3 integration image can run before the kernel syscall 4 lifecycle-control path (#36) is wired end-to-end. The QEMU self-test maps a release `clean-slate-supervisor-userspace` image into pid 1, grants a console IPC capability, and validates `[SUP ]` diagnostics plus `[M4.3] PASS`.

For M5.7 integrated userspace storage path (host transport tests + bounded CPL3 integration):

```bash
cargo test -p clean-slate-service-fixtures block_transport
cargo test -p clean-slate-kernel service::capability::tests
cargo test -p clean-slate-kernel service::control::tests::block_capability
cargo xtask test-m5-storage
```

`test-m5-storage` now resets the M5 data disk to blank media for each run, then requires capability-gated userspace storage handshake plus store format/write/commit/remount/overwrite and malformed-media rejection markers before `[M5.7] PASS`. The storage path keeps the transport-neutral block contract while preserving explicit unauthorized denial for unrelated userspace callers.

M4.4 health/liveness tracking (host-tested, no QEMU) exercises `ServiceHealthTracker` deadline math with explicit tick values — no real-time sleeps:

```bash
cargo test -p clean-slate-service-lifecycle health_tracker
cargo test -p clean-slate-service-lifecycle hlth_lines
```

For M4.5 dependency metadata and start-readiness evaluation (host-tested):

```bash
cargo test -p clean-slate-service-lifecycle dependency_graph
```

The `dependency_graph` module provides `DependencyGraph`, `evaluate_start_readiness`, and `[DEP ]` diagnostic formatters for supervisor integration (#37). `ServiceHealthTracker` and `DependencyHealthSnapshot` compose in `ConvergedSupervisor` (#40).

For M4.6 restart policy and Wave 2 supervisor convergence (host-tested; CPL3 image build):

```bash
cargo test -p clean-slate-supervisor restart_policy
cargo xtask test-m4-restart-policy
```

`ConvergedSupervisor` composes the M4.3 registry/control path with M4.4 health tracking, M4.5 dependency readiness, and bounded userspace restart policy (`RestartPolicy`, crash-loop backoff, `[SUP ] failure/restart/restarted/suppressed` markers). The `#36` lifecycle control path is invoked via `issue_restart_sequence` / `ControlRequestKind::Restart` then `Start`. Stale instance events remain rejected by the shared lifecycle state machine. For the authoritative M4.8 recovery acceptance (CPL3 converged supervisor, real lifecycle syscall transport, crash fixture, production teardown):

```bash
cargo xtask test-m4
```

The aggregate runs `test-m4-recovery` (QEMU) plus M4.6 host restart-policy tests, then prints `[M4  ] PASS`. Constituent `cargo xtask test-m4-recovery` expects ordered markers including `[SUP ]`, `[SVC ]`, `[HLTH]`, `[PROC] teardown pid=… resources=0`, `[TEST] unrelated workload progress=`, and `[M4  ] PASS`. Individual M4 self-test kernel features remain separate debugging boots.

For the M4.7 supervised crash-service fixture (host tests + optional QEMU self-test):

```bash
cargo test -p clean-slate-service-fixtures
cargo xtask test-m4-crash-service
```

The `clean-slate-service-fixtures` crate holds launch metadata encoding, `[TEST]` diagnostics helpers, and a host-side lifecycle harness. The `m4-crash-service-self-test` kernel feature exercises production userspace teardown, authoritative `Faulted` lifecycle events, deterministic fault injection, and unrelated workload progress without rebooting.

For the bounded M5.2 VirtIO block transport acceptance path:

```bash
cargo xtask test-m5-block
```

This command builds the kernel with `m5-block-self-test`, creates a disposable raw disk image under `target/m5-block.img`, boots QEMU with a legacy (`disable-modern=on`) `virtio-blk-pci` device, and validates ordered discovery/write/flush/read markers through `[M5.2] PASS`.

For the host-side M5.6 crash-consistency matrix:

```bash
cargo xtask test-m5-crash-matrix
```

This bounded host prerequisite runs `cargo test -p clean-slate-store crash_consistency` under `xtask` timeout control and exercises the full deterministic write/flush fault matrix from #58 before the QEMU abrupt-stop lane is trusted.

For the two-boot M5 reboot-persistence acceptance:

```bash
cargo xtask test-m5-persistence
```

This command resets `target/m5/m5-data.img` by default, boots the `m5-persistence-self-test` kernel twice with fresh copied OVMF vars, preserves the exact same VirtIO disk image across the reboot, and requires ordered markers proving: fresh mount/format, deterministic writes of `alpha` and `beta`, a durable commit with `[BLK ] flush complete`, reboot on the same image, exact recovery of both objects, and a post-reboot overwrite where `beta` remains intact. Pass `--keep-disk` to preserve `target/m5/m5-data.img` after the run and to reuse that kept image instead of resetting it on the next debugging invocation.

For the four-boot M5 abrupt-stop crash-recovery acceptance:

```bash
cargo xtask test-m5-crash-recovery
```

This command also resets `target/m5/m5-data.img` by default, rebuilds the known committed baseline on the same disk, then reboots into a deterministic crash boot that halts after the first counted store write of the interrupted commit. `xtask` kills QEMU at that crash marker (no clean storage shutdown or extra flush), then reboots the same disk with `m5-crash-recovery-self-test` and accepts only the documented old-or-new coherent recovery states. Pass `--keep-disk` to retain the image and reuse that kept disk on the next debugging invocation instead of recreating it.

For the aggregate M5 milestone gate:

```bash
cargo xtask test-m5
```

The aggregate runs `test-m5-block`, `test-m5-storage`, `test-m5-crash-matrix`, `test-m5-persistence`, and `test-m5-crash-recovery` in order, then prints `[M5  ] PASS`. The host emits `[TEST] rebooting with persistent disk` between QEMU phases; the recovery boot emits `[CRSH] recovery outcome=<previous-commit|new-commit>` once it has validated that no torn object/metadata state was accepted.

For M5.5 persistent block-harness plumbing (QEMU fixture + host sentinel):

```bash
cargo xtask test-m5-disk-harness
```

`test-m5-disk-harness` is intentionally harness-only: it runs two bounded QEMU boots with M1 marker validation, reuses the same raw disk at `target/m5/m5-data.img`, copies fresh OVMF vars per boot (so firmware variable state is not used as a persistence substitute), writes a host-side sentinel after boot 1, and verifies those bytes after boot 2. It emits `[M5.H] PASS` (harness marker), not the milestone marker. Use `--keep-disk` to preserve `target/m5/m5-data.img` after the run for debugging.

For explicit disk lifecycle while debugging:

```bash
cargo xtask m5-disk-inspect
cargo xtask m5-disk-create
cargo xtask m5-disk-reset
```

On Windows, `scripts/run-tests.ps1` wraps the acceptance commands above. With no arguments it runs the default suite `test-m1`, `test-m2`, `test-m3`, `test-m4`, `test-m5`, which covers the milestone gates already wired into the aggregate flows without redundantly rerunning constituents. `-Exhaustive` additionally runs every individual `test-m3-*`, `test-m4-*`, `test-m5-block`, `test-m5-storage`, `test-m5-crash-matrix`, `test-m5-persistence`, `test-m5-crash-recovery`, and `test-m5-disk-harness` constituent. Individual tests remain selectable by name or alias (`m1`, `m2`, `m3`, `m4`/`m4.8`, `m5`, `entry`/`m3.1`, `address-space`/`m3.2`, `syscall`/`m3.3`, `lifecycle`/`m3.4`, `ipc`/`m3.5`, `resources`/`m3.6`, `m4-recovery`, `m4-restart-policy`, `m4-service-lifecycle`, `m4-crash-service`, `m4-supervisor`, `m5-block`/`block-attach`, `m5-storage`/`m5.7`, `m5-crash-matrix`/`crash-matrix`/`m5.6`, `m5-persistence`/`reboot-persistence`, `m5-crash-recovery`/`crash-recovery`, `m5-disk-harness`/`m5-harness`), for example `.\scripts\run-tests.ps1 -Test m5`; `-List` prints the available names.

On Linux and WSL, use `scripts/run-tests.sh` with the same default suite, `--exhaustive`, `--list`, and test aliases (including `m5`, `m5-block`/`block-attach`, `m5-storage`/`m5.7`, `m5-crash-matrix`/`crash-matrix`/`m5.6`, `m5-persistence`/`reboot-persistence`, `m5-crash-recovery`/`crash-recovery`, and `m5-disk-harness`/`m5-harness`). OVMF is discovered by `cargo xtask` from standard distro paths when `OVMF_CODE` / `OVMF_VARS` are unset. Pull request CI on GitHub Actions runs the `check` job (format, clippy, build, host unit tests) and an `acceptance` job that executes `./scripts/run-tests.sh --exhaustive` on `ubuntu-latest`; exhaustive therefore exercises the new M5 crash/persistence constituents with the existing `qemu-system-x86` and `ovmf` package setup from `.github/workflows/pr.yml`.

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

`kernel/src/lib.rs` is a thin crate-composition file: crate attributes, the module list, the three `pub` re-exports `main.rs` needs (`serial_write_line`, `serial_write_fmt`, `qemu_exit_failure`) and `pub fn run()`, which forwards to `boot::run`. Kernel-internal mechanism and policy still live in subsystem modules inside the same `clean-slate-kernel` crate, while transport-independent shared contracts that need host tests can live in separate workspace crates such as `clean-slate-block`.

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

For M5 storage, keep the layering narrow and split:

- `clean-slate-block` for the transport-independent geometry/read-write/flush/error contract and fake host backend;
- `clean-slate-store` for the host-testable versioned object-store format on top of that contract;
- kernel storage/virtio code for hardware transport only;
- userspace storage service code for request/response IPC/syscall boundary and explicit authority checks;
- `clean-slate-block::fault` for the deterministic host fault-injection backend (counted write/flush power-loss and I/O-error triggers) used by crash-model tests;
- `xtask`/`scripts` for persistence harness orchestration.

The host crash-consistency contract is explicit:

- writes become durable only after `flush` succeeds;
- `clean-slate-store` commits by writing object data into the inactive copy-on-write arena, then the next-generation superblock into the inactive superblock slot, then `flush`;
- the exact commit point is the successful return from that final `flush`;
- recovery must choose either the last previously committed generation or the fully committed new generation, never a mixed/torn combination.

Useful fast M5 host commands:

- `cargo test -p clean-slate-block` for the block contract, fake backend, and fault-injection backend;
- `cargo test -p clean-slate-store` for the M5 host-side object-store format, copy-on-write persistence, remount, and crash-consistency tests.

## Test layers

### Host unit tests

Logic that does not genuinely require privileged execution should be extracted into testable crates and run through ordinary Rust tests.

Examples:

- parsers;
- capability tables;
- block and persistence contracts;
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
