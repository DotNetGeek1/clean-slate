# M9 block/wake scheduler substrate (#145)

Native mechanism for sleeping and waking scheduler threads. Linux `wait4`, pipes, poll, and socket receive lanes consume this API; they do not reimplement wait queues.

## State machine

- `Running` → `Blocked { key, optional deadline }` when `block_current_thread` registers a waiter and yields.
- `Blocked` → `Ready` on `wake_one` / `wake_all`, deadline expiry (`expire_deadlines`), or `cancel_waiters_for_process`.
- Round-robin selection skips `Blocked` threads.

## Lost-wake discipline

Wait registration and the “already woken?” check run with interrupts disabled. `wake_one` records a **pending wake** when no waiter is registered yet; the next `block_current_thread` on that `WaitKey` consumes it and returns `Woken` without sleeping.

## Syscall continuation (design a)

Each thread’s `kernel_stack_top` is published to `SYSCALL_KERNEL_STACK_TOP` on dispatch (`prepare_thread_dispatch`). Before blocking, the syscall handler arms `blocked_syscall_frame` with the live `SyscallContext` pointer on that stack. After wake, the scheduler returns `SYSCALL_BLOCKED_RESUME_SENTINEL` and the assembly tail completes the syscall via `sysretq` with updated `RAX`.

## Capacity

`MAX_WAITERS == TASK_COUNT` (fixed waiter table, no heap). Exhaustion returns an error from `block_current_thread`.

## Tick contract

`Deadline` is an absolute value from `kernel_ticks()` (APIC timer increments in `interrupt::timer`). This is **not** wall-clock nanoseconds.

- **Rate today:** one tick per local APIC timer interrupt (`interrupt::timer::increment_kernel_ticks` on the periodic LAPIC path). The divisor/initial count are fixed at timer init and logged as `tick-rate=uncalibrated` in self-tests.
- **#103 (`nanosleep` / `poll`):** Linux lanes must convert between `kernel_ticks()` and requested durations once a calibrated tick period (or explicit “ticks per second”) is published; until then, native deadlines are expressed only in tick units and documented here.
- **Future calibration:** a single authoritative ticks-per-second (or ns-per-tick) value will live alongside the timer driver (`interrupt::timer`), not in wait-table code.

## Idle

When no application thread is `Ready`/`Running` but blocked threads or deadlines remain, the scheduler dispatches a dedicated **idle kernel thread** at `IDLE_THREAD_INDEX` (`TASK_COUNT`), using its own `TaskStack`. That thread’s loop is `hlt` with interrupts enabled, then `expire_deadlines` and a runnable pick. While the idle thread is current, timer interrupts update only the idle thread’s `saved_stack_pointer` (never a `Blocked` thread’s), scan deadlines, and either return into the idle loop or hand off to a newly runnable thread. A guard fatal fires if `rsp` leaves the top 1 KiB of the idle stack (detects IRQ nesting / stack growth bugs).

## Timer preemption

Timer preemption is **not** suppressed for arbitrary syscall handlers. Lost-wake protection uses interrupts-disabled registration in `block_current_thread` (including arming `blocked_syscall_frame` under the same critical section). Linux relaunch and other long syscall paths rely on ordinary timer preemption.
