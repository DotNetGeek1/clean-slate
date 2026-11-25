//! Shared zombie publication for Linux `exit(2)` and `exit_group(2)` (#102).
//!
//! M9 Linux processes are single-threaded: one live thread per address space, so
//! `exit` and `exit_group` observe the same teardown contract for proc-table state.

use super::pipe::wait_key_for_parent;
use super::table::{exit_status_word, table_mut, ProcId};
use crate::sched::wait::wake_all_registered;

/// Publish exit status, retire the proc-table slot, and wake the parent wait queue.
///
/// The caller must already hold a proc-table slot for `id` (registered at launch or fork).
pub(crate) fn publish_linux_exit(id: ProcId, status: u32, finalize_children: bool) {
    let table = table_mut();
    // The caller is exiting either way and its teardown runs next, so a missing slot only
    // means there is no zombie to publish; it must not take the kernel down with it (#215).
    if table.require_proc_slot(id).is_err() {
        crate::diagnostics::log::kernel_log_fmt(format_args!(
            "[LNX ] exit pid={} gen={} without proc-table slot; tearing down without a zombie\n",
            id.pid, id.generation.0
        ));
        return;
    }
    let parent_pid = table.parent_of(id).map_or(id.pid, |p| p.pid);
    // Children first: `publish_exit` retires the slot of a process whose parent is pid 0,
    // and finalizing needs the exiting parent's slot to find them.
    if finalize_children {
        table.finalize_children_on_parent_exit(id);
    }
    table.publish_exit(id, exit_status_word(status, None));
    table.retire_slot(id);
    wake_all_registered(wait_key_for_parent(parent_pid));
}

/// Publish a signalled zombie (e.g. page fault) and wake a blocked parent `wait4`.
pub(crate) fn publish_linux_signalled_exit(id: ProcId, signal: u32) {
    let table = table_mut();
    if table.require_proc_slot(id).is_err() {
        return;
    }
    let parent_pid = table.parent_of(id).map_or(id.pid, |p| p.pid);
    table.publish_exit(id, exit_status_word(0, Some(signal)));
    table.retire_slot(id);
    wake_all_registered(wait_key_for_parent(parent_pid));
}
