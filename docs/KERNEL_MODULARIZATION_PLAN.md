# Kernel `lib.rs` Modularization Plan

## Goal

Break the current ~6.4k-line `kernel/src/lib.rs` into a conventional Rust module tree while preserving behavior exactly.

This is a **structural refactor only**. Phase 1 must not redesign kernel behavior, change ABI contracts, alter feature names, change QEMU acceptance markers, or introduce new workspace crates.

The immediate goals are:

- make the kernel source tree navigable;
- isolate architecture-specific mechanisms from kernel policy;
- keep unit tests beside the code they exercise;
- move milestone/QEMU acceptance scaffolding into a dedicated `selftest/` tree;
- preserve the current public kernel API used by `main.rs`;
- keep the tree buildable and testable throughout the refactor;
- establish module boundaries that can later inform crate boundaries.

---

## Current-state assessment

`kernel/src/lib.rs` currently mixes at least these concerns:

- global constants for ports, MSRs, interrupt vectors, APIC, paging, scheduling, syscall ABI, IPC limits, and self-test markers;
- process/thread lifecycle and the process registry;
- IPC endpoints and capability tables;
- ID allocation;
- UEFI memory-map normalization;
- physical page allocation;
- boot orchestration;
- paging and address-space management;
- scheduler state and dispatch;
- x86-64 GDT, TSS, IDT, interrupt frames, and assembly entry/exit;
- syscall dispatch and validation;
- exception and timer dispatch;
- LAPIC/PIC/MSR/port helpers;
- serial logging and QEMU exit support;
- feature-gated milestone self-tests;
- host unit tests.

A significant portion of the file is feature-gated milestone self-test scaffolding, which causes production code and acceptance-test code to interleave heavily.

The public API consumed by `kernel/src/main.rs` is intentionally small:

- `run`
- `serial_write_line`
- `serial_write_fmt`
- `qemu_exit_failure`

That makes the split comparatively low-risk as long as those interfaces and all link-time symbol contracts remain unchanged.

---

## Phase 1 constraints

Phase 1 is a **pure structural move** inside the existing `clean-slate-kernel` crate.

### Must not change

Do not change:

- runtime behavior;
- boot order;
- syscall ABI;
- interrupt vectors;
- memory layout;
- feature names;
- `xtask` command behavior;
- QEMU acceptance markers;
- serial output relied on by tests;
- `scripts/run-tests.ps1`;
- externally referenced symbol names;
- `#[no_mangle]` symbol names;
- assembly-visible static/function names;
- public API used by `main.rs`;
- algorithmic behavior;
- scheduling policy;
- capability semantics;
- address-space semantics.

### Avoid renames

This phase should be a **move, not a rename-and-cleanup pass**.

Existing type, function, constant, and symbol names should remain unchanged unless a path/import adjustment makes a minimal rename unavoidable.

In particular, do not rename anything referenced by:

- `global_asm!`;
- `extern "C"` declarations;
- `#[no_mangle]`;
- linker-visible symbols;
- QEMU/acceptance-test markers.

If naming cleanup is desirable, do it in a later, isolated change.

### No new workspace crates

Keep all moved code inside `clean-slate-kernel`.

Do not introduce `mm`, `sched`, `ipc`, `process`, or architecture crates in Phase 1.

Crate extraction is a later decision, after module boundaries have proven stable.

---

# Target module tree

```text
kernel/src/
├── lib.rs
├── main.rs
│
├── boot/
│   ├── mod.rs
│   └── uefi.rs
│
├── arch/
│   ├── mod.rs
│   └── x86_64/
│       ├── mod.rs
│       ├── asm.rs
│       ├── cpu.rs
│       ├── port.rs
│       ├── msr.rs
│       ├── idt.rs
│       ├── gdt.rs
│       ├── apic.rs
│       ├── interrupt_context.rs
│       └── context_switch.rs
│
├── mm/
│   ├── mod.rs
│   ├── region.rs
│   ├── frame_allocator.rs
│   ├── paging.rs
│   ├── address_space.rs
│   └── user_mapping.rs
│
├── process/
│   ├── mod.rs
│   └── id_allocator.rs
│
├── sched/
│   ├── mod.rs
│   ├── dispatch.rs
│   └── demo_tasks.rs
│
├── ipc/
│   └── mod.rs
│
├── syscall/
│   ├── mod.rs
│   └── validation.rs
│
├── interrupt/
│   ├── mod.rs
│   └── timer.rs
│
├── diagnostics/
│   ├── mod.rs
│   ├── serial.rs
│   ├── log.rs
│   ├── qemu.rs
│   └── gdb.rs
│
├── sync/
│   ├── mod.rs
│   └── global_cell.rs
│
└── selftest/
    ├── mod.rs
    ├── m1_memory.rs
    ├── m2_double_fault.rs
    ├── m2_timer.rs
    ├── m3_entry.rs
    ├── m3_address_space.rs
    ├── m3_syscall.rs
    └── m3_ipc.rs
```

There should be **no top-level `state.rs` bag of globals**.

Subsystem-owned state remains beside the subsystem that owns it, with narrow `pub(crate)` accessors where cross-module access is required.

---

# Module responsibilities

## `lib.rs`

`lib.rs` should become intentionally boring.

It should contain only:

- crate attributes;
- top-level module declarations;
- the four public exports used by `main.rs`;
- the smallest practical `run()` entry wrapper.

It should not contain subsystem implementation logic.

Target shape:

```rust
#![cfg_attr(not(test), no_std)]

mod arch;
mod boot;
mod diagnostics;
mod interrupt;
mod ipc;
mod mm;
mod process;
mod sched;
mod selftest;
mod sync;
mod syscall;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

pub fn run() -> uefi::Status {
    boot::run()
}
```

Exact declarations may differ as required by `cfg` gates.

---

## `boot/`

### `boot/mod.rs`

Owns boot orchestration:

- `run`;
- `run_inner`;
- initialization ordering;
- subsystem startup;
- feature-gated dispatch into milestone self-tests.

It should orchestrate subsystems rather than implement them.

### `boot/uefi.rs`

Owns UEFI-specific boot memory-map handling:

- `collect_reserved_ranges_from_firmware`;
- `BootReservedRanges`;
- raw descriptor conversion;
- memory-map normalization;
- sort/merge helpers that exist specifically to interpret firmware memory state.

---

## `arch/x86_64/`

This layer owns **CPU/architecture mechanism**, not kernel policy.

### `asm.rs`

Owns the central `global_asm!` block and assembly-visible declarations:

- interrupt entry stubs;
- syscall entry/return assembly;
- task-context restore;
- bootstrap/user-test entry stubs where they are intrinsically architectural;
- `extern "C"` declarations;
- interrupt-entry declaration macros.

Do not rename labels or referenced symbols.

### `interrupt_context.rs`

Owns `repr(C)` architecture boundary frames:

- `InterruptContext`;
- `UserspaceEntryFrame`;
- `SyscallContext`;
- layout/offset unit tests.

### `idt.rs`

Owns:

- IDT entry representation;
- IDT table representation;
- descriptor-table pointer representation;
- IDT static storage;
- interrupt-handler registration;
- architecture exception-name mapping.

### `gdt.rs`

Owns:

- GDT/TSS structures;
- privilege stacks;
- double-fault stack;
- GDT/TSS storage;
- GDT/TSS initialization;
- userspace selector construction;
- privilege-stack setters;
- selector validation helpers.

### `apic.rs`

Owns LAPIC/PIC mechanics:

- legacy PIC masking;
- LAPIC enablement;
- LAPIC timer programming;
- EOI/acknowledgement;
- LAPIC MMIO access helpers.

### `msr.rs`

Owns:

- `read_msr`;
- `write_msr`.

### `cpu.rs`

Owns CPU-local architecture helpers:

- interrupt enable/disable state;
- `without_interrupts`;
- RFLAGS access;
- code-segment reads;
- stack-pointer reads;
- CR0 write-protect control;
- `Cr0RestoreGuard`.

### `port.rs`

Owns raw I/O port access:

- `port_in`;
- `port_out`.

### `context_switch.rs`

Owns architecture-level context switch mechanics:

- task stack representation;
- saved stack-pointer handoff;
- first-task entry;
- restore-context boundary;
- assembly-facing context-switch statics.

Scheduler policy remains under `sched/`.

---

# `mm/`

## `mm/mod.rs`

Owns memory-management-wide constants and exports, such as:

- `PAGE_SIZE`;
- `PHYSICAL_MEMORY_OFFSET`.

Avoid turning `mod.rs` into another implementation dump.

## `region.rs`

Owns:

- `MemoryRegionKind`;
- `MemoryRegion`;
- `ReservedRange`;
- `NormalizedMemoryMap`;
- pure memory-region normalization helpers not specific to UEFI parsing.

## `frame_allocator.rs`

Owns:

- `PageAllocator`;
- `PageAllocatorStats`;
- `FreePageNode`;
- allocator implementation;
- allocator unit tests.

Allocator-owned global/static state, if any, should remain in `mm`, not a shared global state module.

## `paging.rs`

Owns generic kernel paging mechanics:

- current page-table access;
- page-table access by root;
- page-table walkers;
- flag inspection;
- mapping inspection;
- page-table-frame reservation;
- page zeroing;
- frame freeing.

## `address_space.rs`

Owns process address-space construction and teardown:

- `ProcessAddressSpace`;
- `OwnedUserMapping`;
- address-space frame allocation;
- cloning kernel mappings;
- kernel-root validation/sanitization;
- activating an address-space root;
- process-page mapping;
- translation through a supplied root.

Any kernel-root static/state belongs here or elsewhere under `mm`.

## `user_mapping.rs`

Owns userspace mapping policy/helpers:

- userspace map/unmap;
- userspace leaf-flag validation;
- userspace pointer-range validation;
- validation of userspace mappings.

---

# `process/`

## `process/mod.rs`

Owns process/thread ownership and lifecycle:

- `Process`;
- `ProcessState`;
- `ResourceDomain`;
- `ProcessRegistry`;
- process lifecycle helpers;
- exit/fault/reap transitions;
- process registry state and accessors.

Do not expose the registry as a generic global.

Prefer narrow functions such as:

```rust
pub(crate) fn with_process_registry<R>(
    f: impl FnOnce(&mut ProcessRegistry) -> R
) -> R
```

or similarly constrained access patterns if required by the existing design.

## `process/id_allocator.rs`

Owns:

- `IdAllocator`;
- allocator state if logically process-owned;
- its unit tests.

---

# `sched/`

## `sched/mod.rs`

Owns scheduler policy and scheduler-owned state:

- `Thread`;
- `ThreadState`;
- `ThreadKind`;
- `Scheduler`;
- scheduler constants;
- scheduler global/static storage;
- task-stack storage where it belongs to scheduler ownership.

## `dispatch.rs`

Owns scheduling orchestration:

- preparing dispatch;
- selecting the next runnable thread;
- starting scheduler execution;
- scheduler initialization;
- scheduler handoff to architecture context-switch mechanism.

This module may depend on `arch::x86_64::context_switch`, but the architecture layer must not depend on scheduler policy.

## `demo_tasks.rs`

Owns milestone/demo scheduler tasks:

- demo task bodies;
- progress tracking;
- scheduler acceptance markers;
- task-exit helpers that belong specifically to the scheduler demo path.

If code is purely milestone acceptance scaffolding rather than reusable scheduler behavior, prefer placing it under `selftest/` instead.

---

# `ipc/`

## `ipc/mod.rs`

Owns:

- IPC endpoints;
- endpoint lifecycle;
- endpoint state;
- capability handles;
- handle decomposition/validation;
- IPC send errors;
- endpoint table;
- IPC constants;
- endpoint/capability table state;
- IPC unit tests.

The endpoint table should be owned here rather than exposed through a top-level global-state module.

---

# `syscall/`

## `syscall/mod.rs`

Owns syscall semantics and ABI dispatch:

- syscall numbers;
- syscall ABI constants;
- syscall initialization glue;
- Rust syscall dispatcher;
- syscall handlers;
- caller PID resolution;
- pointer-read syscall behavior;
- IPC syscall behavior.

Raw CPU entry/exit assembly stays in `arch/x86_64/asm.rs`.

## `syscall/validation.rs`

Owns syscall-boundary validation that is not raw assembly:

- SYSRET selector validation;
- return RFLAGS matching;
- canonical userspace return-state validation;
- entry-flag validation;
- relevant host unit tests.

---

# `interrupt/`

This layer owns kernel **interrupt/exception policy and dispatch**.

Raw CPU entry mechanics stay under `arch/x86_64`.

## `interrupt/mod.rs`

Owns:

- `clean_slate_interrupt_dispatch`;
- generic exception dispatch;
- page-fault handling;
- double-fault handling;
- expected-fault state used by normal kernel dispatch.

Feature-specific self-test policy should be invoked through small hooks into `selftest`.

## `interrupt/timer.rs`

Owns kernel timer policy/state:

- timer initialization orchestration;
- kernel tick counter;
- timer contract reporting.

Raw LAPIC timer programming remains in `arch/x86_64/apic.rs`.

---

# `diagnostics/`

## `serial.rs`

Owns:

- serial port abstraction;
- serial initialization;
- byte/string/formatted output;
- `COM1`.

## `log.rs`

Owns:

- kernel logging façade;
- test stubs required by host tests.

Keep test and production versions together so host-test linking remains predictable.

## `qemu.rs`

Owns:

- QEMU exit;
- success/failure exit codes;
- fatal kernel halt behavior;
- `halt_loop`;
- `fatal_kernel_error`.

## `gdb.rs`

Owns:

- GDB entry handoff and related diagnostics-only behavior.

---

# `sync/`

## `global_cell.rs`

Owns:

- `GlobalCell<T>`;
- its safety invariants;
- unit tests if applicable.

This is a synchronization primitive, not a home for unrelated global state.

---

# `selftest/`

Milestone/QEMU acceptance scaffolding belongs here.

These are not ordinary unit tests. They are feature-gated boot/runtime acceptance tests.

## `selftest/mod.rs`

Owns:

- feature-gated module declarations;
- self-test dispatch helpers;
- genuinely shared self-test-only helpers.

Do not turn this into a dumping ground for production helpers.

## Milestone files

```text
m1_memory.rs
m2_double_fault.rs
m2_timer.rs
m3_entry.rs
m3_address_space.rs
m3_syscall.rs
m3_ipc.rs
```

Each file owns the scaffolding, payload setup, markers, and validation for that milestone.

Production subsystems should interact with self-tests only through narrow hook points.

Prefer:

```rust
#[cfg(feature = "...")]
selftest::some_hook(...);
```

at a small number of established dispatch locations rather than scattering milestone-specific `cfg` blocks throughout production modules.

---

# State ownership rules

There must not be a new central `state.rs` containing unrelated globals.

State lives with the subsystem that owns the invariant around it.

Examples:

```text
Scheduler / task stacks          -> sched
Process registry / process IDs   -> process
IPC endpoint table               -> ipc
GDT / TSS / privilege stacks     -> arch::x86_64::gdt
IDT                              -> arch::x86_64::idt
Kernel root page-table state      -> mm
Timer tick state                  -> interrupt::timer
```

Cross-subsystem access should use narrow functions or APIs.

Avoid patterns such as:

```rust
crate::state::SCHEDULER
crate::state::PROCESS_REGISTRY
crate::state::IPC_ENDPOINT_TABLE
```

because they create a new dependency hub and weaken ownership boundaries.

---

# Dependency-direction rules

The module tree should reflect a deliberate dependency direction.

## Architecture mechanism vs kernel policy

Architecture code should provide mechanisms.

Kernel subsystems may use those mechanisms.

Architecture code should not know scheduler, process, IPC, or syscall policy.

Good:

```text
sched -> arch::x86_64::context_switch
syscall -> arch::x86_64
interrupt -> arch::x86_64
mm -> arch::x86_64
```

Avoid:

```text
arch::x86_64 -> sched
arch::x86_64 -> process
arch::x86_64 -> ipc
```

Where an assembly symbol must call into Rust policy, keep the symbol/link contract in the architecture boundary while the Rust dispatch implementation remains owned by the appropriate subsystem.

## Suggested high-level dependency direction

```text
boot
 ├─> mm
 ├─> arch
 ├─> sched
 ├─> syscall
 ├─> interrupt
 └─> selftest

interrupt
 ├─> arch
 ├─> sched
 └─> selftest

syscall
 ├─> arch
 ├─> mm
 ├─> process
 └─> ipc

sched
 ├─> arch
 └─> process

process
 └─> mm   (only where ownership/address-space lifecycle requires it)

mm
 └─> arch

selftest
 ├─> mm
 ├─> process
 ├─> sched
 ├─> ipc
 ├─> syscall
 └─> arch
```

Try to avoid circular dependencies.

If a circular dependency appears, stop and inspect the ownership boundary rather than solving it with broad re-exports or a shared global module.

---

# Visibility rules

Default to the narrowest visibility possible.

Preferred order:

1. private;
2. `pub(super)`;
3. `pub(crate)`;
4. `pub`.

Only the API consumed outside the library crate should remain public.

The only intended public kernel functions after this refactor are the existing entry/diagnostic functions used by `main.rs`.

Do not make items `pub(crate)` merely because moving files makes access inconvenient. Prefer introducing a narrow owner-controlled helper when that better preserves the subsystem boundary.

---

# Constants

Constants live with the subsystem that owns their meaning.

Examples:

```text
IPC_*                 -> ipc
SYSCALL_*             -> syscall
interrupt vectors     -> arch::x86_64 / interrupt as appropriate
MSR numbers           -> arch::x86_64
APIC register offsets -> arch::x86_64::apic
task sizing           -> sched
page constants        -> mm
self-test markers     -> selftest
```

Do not recreate a giant global constants block elsewhere.

---

# Unsafe and assembly rules

Unsafe Rust and assembly should remain concentrated at hardware and ABI boundaries.

Each architecture-facing file should have a module-level `//!` comment stating:

- its responsibility;
- why unsafe code is required;
- what invariants callers must uphold;
- what assembly/link-time contracts exist.

`unsafe_op_in_unsafe_fn = "deny"` remains enabled.

For every symbol consumed by assembly, add a short comment at the Rust definition naming the assembly site that consumes it.

Example:

```rust
// Consumed by arch/x86_64/asm.rs syscall entry path.
#[no_mangle]
static mut SYSCALL_KERNEL_STACK_TOP: u64 = 0;
```

Do not rename these symbols during Phase 1.

---

# Unit-test placement

Ordinary host unit tests move beside the implementation they exercise:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    // ...
}
```

Examples:

- allocator tests -> `mm/frame_allocator.rs`;
- memory-region tests -> `mm/region.rs`;
- scheduler tests -> `sched/`;
- process tests -> `process/`;
- IPC tests -> `ipc/`;
- syscall validation tests -> `syscall/validation.rs`;
- selector tests -> `arch/x86_64/gdt.rs`;
- ABI/layout tests -> `arch/x86_64/interrupt_context.rs`.

Milestone/QEMU acceptance tests are different and belong under `selftest/`.

---

# File-size guidance

A file growing beyond roughly **800 lines** should be treated as a signal to inspect whether it contains more than one responsibility.

This is a **soft heuristic, not a hard limit**.

Do not split coherent code merely to satisfy a line count.

A cohesive 1,000-line paging implementation is preferable to several artificial files with unclear ownership.

---

# Execution plan

Perform the split in dependency order.

Each step should be a mechanical move:

1. cut an existing item/block;
2. paste it into its new owner module;
3. add module declarations/imports;
4. fix paths and visibility only as required;
5. run the relevant verification;
6. commit the step where practical.

Do not mix unrelated cleanup into these commits.

Repository-wide formatting cleanup is out of scope.

Running `cargo fmt` on touched code is fine, but avoid creating a giant formatting-only diff around unrelated code.

If a move appears to require a real architectural or behavioral change, **stop and report it instead of silently redesigning the code**.

---

## Step 1 — Leaf modules

Create:

```text
sync/global_cell.rs

diagnostics/
  serial.rs
  log.rs
  qemu.rs
  gdb.rs

arch/x86_64/
  port.rs
  msr.rs
  cpu.rs
```

Move only leaf functionality with minimal internal dependencies.

### Verify

Run:

```text
cargo test -p clean-slate-kernel
```

Compile any self-test features that directly reference the moved symbols.

Commit when green.

---

## Step 2 — Memory-map and allocator core

Create:

```text
mm/
  region.rs
  frame_allocator.rs

boot/
  uefi.rs
```

Move:

- memory-region types;
- normalization helpers;
- page allocator;
- allocator statistics;
- UEFI descriptor conversion;
- reserved-range collection;
- related unit tests.

Keep pure memory logic under `mm`, firmware-facing parsing under `boot::uefi`.

### Verify

Run:

```text
cargo test -p clean-slate-kernel
```

Compile at least the features that exercise M1 memory/paging behavior.

Commit when green.

---

## Step 3 — x86-64 architecture boundary

Create:

```text
arch/x86_64/
  interrupt_context.rs
  idt.rs
  gdt.rs
  apic.rs
  context_switch.rs
  asm.rs
```

Move:

- interrupt/syscall context frame types;
- IDT;
- GDT/TSS;
- privilege-stack state;
- double-fault stack;
- APIC/PIC helpers;
- architecture context-switch support;
- assembly block;
- assembly-visible statics owned by architecture mechanisms.

Preserve exact symbol names and layouts.

### Verify

Run host tests.

Compile **every feature that touches interrupt, syscall, userspace-entry, double-fault, timer, or context-switch paths**, including as applicable:

```text
m2-self-test
m2-double-fault-self-test
m2-timer-self-test
m3-entry-self-test
m3-address-space-self-test
m3-syscall-self-test
m3-ipc-self-test
```

Run a QEMU checkpoint here if the architecture movement is large enough that compilation alone is not confidence-building.

Commit when green.

---

## Step 4 — Process, IPC, and scheduler

Create:

```text
process/
  mod.rs
  id_allocator.rs

ipc/
  mod.rs

sched/
  mod.rs
  dispatch.rs
  demo_tasks.rs
```

Move:

- process/thread lifecycle;
- process registry;
- ID allocation;
- IPC endpoints/capabilities/table;
- scheduler types/state;
- scheduling policy;
- scheduler dispatch;
- demo-task logic that genuinely belongs to scheduler behavior;
- relevant unit tests.

Keep subsystem-owned global/static state inside the owning subsystem.

Do **not** create `state.rs`.

### Verify

Run:

```text
cargo test -p clean-slate-kernel
```

Compile scheduler/process/IPC-related feature combinations, especially:

```text
m2-self-test
m2-timer-self-test
m3-address-space-self-test
m3-entry-self-test
m3-syscall-self-test
m3-ipc-self-test
```

Commit when green.

---

## Step 5 — Paging, address spaces, syscall policy, interrupt policy

Create:

```text
mm/
  paging.rs
  address_space.rs
  user_mapping.rs

syscall/
  mod.rs
  validation.rs

interrupt/
  mod.rs
  timer.rs
```

Move:

- paging helpers;
- process address-space creation/teardown;
- userspace mapping validation;
- syscall ABI constants;
- Rust syscall dispatch/handlers;
- syscall validation;
- Rust interrupt/exception dispatch;
- timer policy/state;
- relevant unit tests.

Keep raw entry/exit mechanics in `arch/x86_64`.

### Verify

Run host tests.

Compile every feature that exercises these paths.

Run a QEMU checkpoint for at least:

```text
m3-address-space-self-test
m3-syscall-self-test
m3-ipc-self-test
```

and timer/double-fault paths where impacted.

Commit when green.

---

## Step 6 — Self-test tree

Create:

```text
selftest/
  mod.rs
  m1_memory.rs
  m2_double_fault.rs
  m2_timer.rs
  m3_entry.rs
  m3_address_space.rs
  m3_syscall.rs
  m3_ipc.rs
```

Move feature-gated milestone acceptance scaffolding one milestone at a time.

Keep production hook points small.

Do not move ordinary subsystem unit tests into `selftest`.

After self-test code is isolated, narrow the crate-level dead-code allowance so production dead code is visible again.

Prefer feature-specific allowances on `selftest` modules rather than a broad crate-level exemption.

### Verify after each milestone move

Compile that milestone feature immediately.

Where practical, run its QEMU acceptance test before moving the next milestone.

This avoids accumulating several feature-gated breakages before detection.

Commit in logical milestone-sized chunks if helpful.

---

## Step 7 — Shrink `lib.rs`

Once implementation code has moved:

- reduce `lib.rs` to crate attributes, module declarations, and public re-exports;
- move boot orchestration into `boot/mod.rs`;
- keep `main.rs` unchanged.

### Verify

Run:

```text
cargo test -p clean-slate-kernel
```

Then run the complete feature compilation matrix.

---

# Verification matrix

Feature-gated code must be compiled explicitly because the default build cannot detect unresolved paths hidden behind disabled `cfg` branches.

Compile the kernel for `x86_64-unknown-uefi` with each relevant feature:

```text
m1-self-test
m2-self-test
m2-double-fault-self-test
m2-timer-self-test
m3-entry-self-test
m3-address-space-self-test
m3-syscall-self-test
m3-ipc-self-test
```

Where features compose, preserve the existing feature relationships exactly.

At the end of Phase 1 run:

```text
cargo test -p clean-slate-kernel
```

Run Clippy for the kernel/target and feature matrix as supported by the existing project tooling.

Run the complete QEMU acceptance suite:

```text
scripts/run-tests.ps1
```

The refactor is complete only when the existing suite passes without changing expected markers or acceptance criteria.

---

# Verification cadence

Do not reserve all feature checking for the end.

Use three levels of verification:

### After every mechanical move

Run the fastest relevant host/unit test or compile check.

### After every subsystem-sized step

Run:

- `cargo test -p clean-slate-kernel`;
- all self-test feature builds that touch that subsystem.

### At architecture-sensitive checkpoints and the end

Run the relevant QEMU acceptance tests.

At final completion, run the entire test suite.

---

# Commit strategy

Where practical, each numbered execution step should be its own commit.

Good examples:

```text
refactor(kernel): extract diagnostics and arch leaf modules
refactor(kernel): extract memory region and frame allocator modules
refactor(kernel): isolate x86_64 descriptor and entry machinery
refactor(kernel): extract process ipc and scheduler modules
refactor(kernel): extract paging syscall and interrupt modules
refactor(kernel): move milestone selftests into selftest tree
refactor(kernel): reduce lib.rs to crate composition
docs(kernel): document source layout and module boundaries
```

Commits should remain reviewable and revertable.

Do not combine:

- behavior changes;
- naming cleanup;
- broad formatting churn;
- optimization;
- feature additions;
- API redesign

with this modularization unless a separate commit is explicitly created after Phase 1 is green.

---

# Documentation changes

Update `docs/DEVELOPMENT.md` with a **Kernel source layout** section containing:

- the final tree;
- module responsibilities;
- visibility convention;
- dependency-direction rules;
- state-ownership rule;
- test placement convention;
- unsafe/assembly convention;
- soft file-size heuristic.

Add a short pointer from `docs/ARCHITECTURE.md` to the development/source-layout documentation rather than duplicating the whole tree there.

---

# Phase 2 — Possible crate extraction

Phase 2 is explicitly **not part of this change**.

Once the module boundaries have been stable for a while, review which modules are genuinely pure logic and host-testable without:

- `uefi`;
- `x86_64`;
- assembly;
- kernel-global hardware state.

Potential extraction candidates may include:

```text
clean-slate-mm-core
  region
  frame allocator
  memory-map normalization

clean-slate-sched-core
  scheduler policy
  thread/task state transitions

clean-slate-ipc-core
  endpoint/capability tables
  ID allocation
  selected process-registry logic
```

These names and boundaries are provisional.

Do not extract a crate merely because a module exists.

Extract only when:

- the dependency direction is clear;
- the public API is small and stable;
- the code is meaningfully reusable/testable in isolation;
- architecture-specific dependencies can be excluded cleanly.

The kernel crate should continue to own architecture, boot, syscall entry glue, interrupt entry glue, and runtime self-tests.

---

# Risks

## Assembly and link-time contracts

`global_asm!` labels, `#[no_mangle]` symbols, and assembly-visible statics are link-time contracts.

Moving them is acceptable.

Renaming them is not part of this phase.

Mitigation:

- preserve exact names;
- keep comments documenting assembly consumers;
- compile all architecture-sensitive feature configurations;
- run QEMU checkpoints.

## Feature-gated compile gaps

A default build will not compile code hidden behind disabled features.

Mitigation:

- compile impacted feature gates after each subsystem move;
- run the full feature matrix at the end.

## Visibility creep

Moving code can tempt broad `pub(crate)` exposure.

Mitigation:

- use the narrowest visibility possible;
- prefer owner-controlled accessors;
- review every visibility increase as an architectural decision.

## Global-state re-centralization

A generic `state.rs` would recreate a cross-subsystem dependency hub.

Mitigation:

- state remains with its owning subsystem;
- cross-module access uses narrow APIs.

## Accidental behavior changes

A structural split can accidentally alter initialization ordering, `cfg` behavior, static initialization, or unsafe assumptions.

Mitigation:

- move in dependency order;
- avoid renames and cleanup;
- preserve boot ordering exactly;
- commit incrementally;
- test after each significant move.

## Test-scaffolding leakage

Self-test helpers can accidentally become production dependencies.

Mitigation:

- self-test modules may depend on production modules;
- production modules should only call self-test through narrow feature-gated hooks;
- do not move reusable production logic into `selftest` merely because it is currently exercised only by tests.

---

# Definition of done

Phase 1 is complete when:

- `kernel/src/lib.rs` is a thin crate-composition file;
- subsystem implementation code lives in coherent modules;
- architecture-specific mechanisms are concentrated under `arch/x86_64`;
- milestone acceptance scaffolding lives under `selftest`;
- ordinary unit tests live beside their implementation;
- subsystem state is owned by the subsystem rather than a central global module;
- no unnecessary new public API has been introduced;
- no new workspace crates have been added;
- existing symbol names and ABI contracts are preserved;
- all host tests pass;
- all feature-gated kernel configurations compile;
- Clippy passes under the existing project expectations;
- the complete QEMU acceptance suite passes unchanged;
- source-layout and module conventions are documented.

Only after this is green should feature development resume or Phase 2 crate extraction be considered.
