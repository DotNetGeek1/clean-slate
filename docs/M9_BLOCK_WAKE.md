# M9 block/wake scheduler substrate (#145)

Native mechanism for sleeping and waking scheduler threads. Linux `wait4`, pipes, poll, and socket receive lanes consume this API, as do the native net service (`NET_SUBOP_WAIT_WORK`), the object-service queue and the virtio-blk completion wait; none of them reimplements wait queues.

## State machine

- `Running` → `Blocked { key, optional deadline }` when `block_current_thread` registers a waiter and yields.
- `Blocked` → `Ready` on `wake_one` / `wake_all`, deadline expiry (`expire_deadlines`), or `cancel_waiters_for_process`.
- Round-robin selection skips `Blocked` threads.

## Lost-wake discipline

Wait registration and the “already woken?” check run with interrupts disabled. `wake_one` / `wake_all` record a **pending wake** when no waiter is registered yet; the next `block_current_thread` on that `WaitKey` consumes it and returns `Woken` without sleeping. The pending-wake table has `MAX_WAITERS` entries and silently drops records once full, and `RestartSyscall` / `RetrySyscall` blocks consume and ignore them.

### Atomic check-then-block (M10 W1)

`block_current_thread_unless(frame, key, deadline, resume, check)` evaluates the readiness predicate `check` inside the same interrupts-disabled section that registers the waiter. On the single CPU a producer (an IRQ or another thread's syscall) therefore runs either wholly before `check`, which then sees its state change and returns `BlockCheck::Ready(rax)` without registering anything, or wholly after registration, and finds the waiter. An interrupt raised inside `check` is delivered only after the thread is registered. It neither consumes nor records pending wakes.

Producers for such waiters call `wake_all_registered(key)`, which wakes registered waiters and **never records a pending wake**. New code must not call `wake_all` / `wake_one` for these keys: a wake of a key with no waiter would spend a slot of the bounded pending-wake table, and a full table silently drops the network service's `NET_SUBOP_WAIT_WORK` wakes.

The network service still checks readiness in one critical section and blocks in another, relying on the pending-wake table to close the gap. It is unchanged by M10; the service port and work sets (#200) use the atomic form.

## Syscall continuation (design a)

Each thread’s `kernel_stack_top` is published to `SYSCALL_KERNEL_STACK_TOP` on dispatch (`prepare_thread_dispatch`). Before blocking, the syscall handler arms `blocked_syscall_frame` with the live `SyscallContext` pointer on that stack. After wake, the scheduler returns `SYSCALL_BLOCKED_RESUME_SENTINEL` and the assembly tail completes the syscall via `sysretq` with updated `RAX`.

`block_current_thread_with_resume` takes a `BlockedResume` that decides how the blocked syscall completes:

- `NativeOutcome`: `RAX` is the encoded #145 outcome (`WOKEN` / `TIMEOUT` / `CANCEL`). `NET_SUBOP_WAIT_WORK` uses it.
- `RestartSyscall { nr, timeout_rax }`: a wake or cancel re-executes the syscall, and a timeout returns `timeout_rax`. Used, for example, by `NET_SUBOP_POLL` and by the storage service's `OBJECT_SUBOP_SERVICE_NEXT`, which blocks on the object-service work key (`0x47 << 56`) with no deadline while the queue is empty.
- `RetrySyscall { nr }`: every outcome, the timeout included, re-executes the syscall, so the handler owns its deadline. The virtio-blk completion wait uses it: the block request syscall blocks on `0x48 << 56` with a 5 s `MonotonicNs` deadline, and the re-executed syscall either harvests the completion or fails the in-flight request closed (see [ARCHITECTURE.md](ARCHITECTURE.md#m5-storage-layering)).

## Capacity

`MAX_WAITERS == TASK_COUNT` (fixed waiter table, no heap). Exhaustion returns an error from `block_current_thread`.

## Time contract

`Deadline::MonotonicNs` is the only deadline: an absolute calibrated TSC value from `time::monotonic_ns()`. There is no IRQ-tick deadline (#180). Under QEMU TCG the LAPIC interrupt delivery rate follows the host timer resolution (about 1010/s on CI Linux, about 670/s on Windows at 1 ms resolution, as low as 64/s at the 15.6 ms Windows default), so a count of delivered ticks is not a clock.

- **Ticks:** `kernel_ticks()` counts delivered LAPIC timer interrupts. Timer IRQs only bound how late a due deadline is noticed (`expire_deadlines` runs on each IRQ and in the idle loop). Tick counts remain valid as evidence that interrupts were delivered (for example "blocked across N timer IRQs"), not as durations.
- **Calibration:** timer init calibrates the LAPIC counter and TSC against the PIT. Builds with `m3-entry-self-test` skip that inside `initialize_timer`, so any self-test that arms a deadline calls `calibrate_apic_tick()` itself. Building a deadline without a calibrated TSC is fatal.
- **#103 (`nanosleep` / `poll`):** Linux lanes turn requested durations into exact TSC deadlines (`kernel/src/time`, `now + request`, no tick rounding; see [M9.md](M9.md), "Timed wait latency").
- **Tick-unit clients:** the net service (`NET_SUBOP_MONOTONIC_TICKS`) and the recovery supervisor bootstrap take a clock in `tick_period_ns` units. Both are fed `time::monotonic_period_ticks()`, TSC time divided by the IRQ period, so their timers run on real time.

## Idle

When no application thread is `Ready`/`Running` but blocked threads or deadlines remain, the scheduler dispatches a dedicated **idle kernel thread** at `IDLE_THREAD_INDEX` (`TASK_COUNT`), using its own `TaskStack`. That thread’s loop is `hlt` with interrupts enabled, then `expire_deadlines` and a runnable pick. While the idle thread is current, timer interrupts update only the idle thread’s `saved_stack_pointer` (never a `Blocked` thread’s), scan deadlines, and either return into the idle loop or hand off to a newly runnable thread. A guard fatal fires if `rsp` leaves the top 1 KiB of the idle stack (detects IRQ nesting / stack growth bugs).

## Interrupt state during syscalls

Every syscall, native and Linux, runs with interrupts disabled from entry to return. `IA32_FMASK` clears `IF` on `syscall` entry (`SYSCALL_ENTRY_RFLAGS_MASK` in `kernel/src/syscall/mod.rs`), the entry trampoline never executes `sti`, and `without_interrupts` only restores `IF` when it was set on entry. Interrupts are taken again only after `sysretq` restores the user `RFLAGS`, or once a block or yield has switched to another thread whose restored frame re-enables them. A timer interrupt therefore never preempts a syscall handler: long syscall paths (Linux relaunch, exec) run to completion or block. The kernel is single-CPU, so every syscall handler is atomic with respect to IRQ handlers and to every other thread.

Lost-wake protection relies on this: registration in `block_current_thread` (including arming `blocked_syscall_frame`) and the whole of `block_current_thread_unless` happen in one interrupts-disabled section.

## Serial logging

`[M9.E] blocked tid=… key=…` is logged on every block only in `m9-block-wake-self-test` builds, whose ordered markers need it. Other builds do not log per block, so a thread that blocks every frame cannot flood the serial console.
