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

`Deadline` is an absolute value from `kernel_ticks()` (APIC timer increments in `interrupt::timer`). Not nanoseconds.

## Idle

When no thread is `Ready` but blocked threads or deadlines remain, the kernel executes `hlt` with interrupts enabled until the next timer interrupt or wake.
