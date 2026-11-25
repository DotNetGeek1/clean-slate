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

/// IST stacks: double fault, NMI and machine check (16 KiB each plus a guard).
pub(crate) const IST_STACK_COUNT: usize = 3;

/// Records the boot arms: every scheduler slot (including idle), the boot
/// stack and the [`IST_STACK_COUNT`] IST stacks.
///
/// The record table itself is a few hundred bytes. The stacks it describes
/// are the `TASK_COUNT` cost above.
pub(crate) const MAX_GUARDED_STACKS: usize = SCHEDULER_THREAD_SLOTS + 1 + IST_STACK_COUNT;

/// Process registry slots. The Linux fd-table registry uses the same count.
///
/// Each `Process` carries an inline page-table frame list
/// ([`BASE_ADDRESS_SPACE_PAGE_TABLE_FRAMES`] plus the carve-out tables).
/// Sixteen of those lists are a few kilobytes. The user-mapping tables are
/// not inline; they live in the pool sized from this capacity.
pub(crate) const PROCESS_REGISTRY_CAPACITY: usize = 16;

/// User pages every address space can track in its pooled mapping table.
///
/// The pool holds `PROCESS_REGISTRY_CAPACITY + 8` tables (spaces in flight
/// during exec, fork and spawn). Each entry is two `u64`s, so the pool is
/// 24 × 384 × 16 = 144 KiB.
pub(crate) const SMALL_ADDRESS_SPACE_USER_MAPPINGS: usize = 384;

/// User pages one address space can track at most (64 MiB of 4 KiB pages):
/// the ceiling for a Linux process's image, stack, brk and mmap together.
///
/// A space that outgrows its small table moves to one of
/// [`LARGE_USER_MAPPING_TABLES`] large tables, so only big processes pay
/// for the capacity. Each large table is 16,384 × 16 = 256 KiB.
pub(crate) const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 16 * 1024;

/// Large mapping tables, shared by every address space (1.25 MiB of `.bss`).
///
/// Four cover two large Linux processes, each with an exec replacement
/// in flight; the fifth is the object storage service's, whose heap is
/// 2048 pages (#304). Beyond that a growing space fails with `ENOMEM` once
/// its small table is full.
pub(crate) const LARGE_USER_MAPPING_TABLES: usize = 5;

/// Page-table frames tracked inside `ProcessAddressSpace`, before the fixed
/// carve-out tables are added.
///
/// One page table maps 2 MiB, so a 64 MiB process needs 32 of them plus
/// its directories. The list is inline and the address space is moved by
/// value on kernel stacks: 61 `u64`s is 488 bytes per address space.
pub(crate) const BASE_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 61;

/// Declared services. The planned system set is six (storage, network, the Linux shell,
/// compositor, desktop shell and one application); eight leaves two spare.
/// A `ServiceRecord` is a few dozen bytes, so the table is under a kilobyte.
pub(crate) const SERVICE_REGISTRY_CAPACITY: usize = 8;
