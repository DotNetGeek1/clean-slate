//! Capacities shared by every boot. Self-test features do not select these.
//!
//! The task stacks are the expensive part: seventeen guarded stacks
//! (sixteen application slots, plus idle) at 128 KiB plus a 4 KiB guard
//! are 2,244 KiB of `.bss`. The mapping-table pool is the next largest
//! static table, at 144 KiB. Everything else below is a few kilobytes.

/// Application and userspace scheduler slots. Idle is extra
/// ([`SCHEDULER_THREAD_SLOTS`]).
///
/// Consumed by the scheduler table, the task-stack array, FPU images,
/// the wait table, and the Linux per-process memory and signal tables.
/// Cost: each of the seventeen slots owns a 128 KiB stack and a 4 KiB guard.
pub(crate) const TASK_COUNT: usize = 16;

/// `TASK_COUNT` application slots plus the idle thread.
pub(crate) const SCHEDULER_THREAD_SLOTS: usize = TASK_COUNT + 1;

/// Unused guarded-stack table entries for IST stacks that are not armed yet.
/// Issue #217 adds one for NMI.
pub(crate) const GUARDED_STACK_FUTURE_IST_RESERVE: usize = 1;

/// Records the boot can arm: every scheduler slot (including idle), the boot
/// stack, the double-fault IST stack, and [`GUARDED_STACK_FUTURE_IST_RESERVE`].
///
/// The record table itself is a few hundred bytes. The stacks it describes
/// are the `TASK_COUNT` cost above.
pub(crate) const MAX_GUARDED_STACKS: usize =
    SCHEDULER_THREAD_SLOTS + 2 + GUARDED_STACK_FUTURE_IST_RESERVE;

/// Process registry slots. The Linux fd-table registry uses the same count.
///
/// Each `Process` carries an inline page-table frame list
/// ([`BASE_ADDRESS_SPACE_PAGE_TABLE_FRAMES`] plus the carve-out tables).
/// Sixteen of those lists are a few kilobytes. The user-mapping tables are
/// not inline; they live in the pool sized from this capacity.
pub(crate) const PROCESS_REGISTRY_CAPACITY: usize = 16;

/// User pages one address space can track.
///
/// The pool holds `PROCESS_REGISTRY_CAPACITY + 8` tables (spaces in flight
/// during exec, fork and spawn). Each entry is two `u64`s, so the pool is
/// 24 × 384 × 16 = 144 KiB.
pub(crate) const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 384;

/// Page-table frames tracked inside `ProcessAddressSpace`, before the fixed
/// carve-out tables are added.
///
/// The list is inline and the address space is moved by value on kernel
/// stacks. Twenty-nine `u64`s is 232 bytes per address space.
pub(crate) const BASE_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 29;

/// Declared services. The planned system set is six (storage, network, the Linux shell,
/// compositor, desktop shell and one application); eight leaves two spare.
/// A `ServiceRecord` is a few dozen bytes, so the table is under a kilobyte.
pub(crate) const SERVICE_REGISTRY_CAPACITY: usize = 8;
