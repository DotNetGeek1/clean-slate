//! Shared zombie publication for Linux `exit(2)` and `exit_group(2)` (#102).
//!
//! M9 Linux processes are single-threaded: one live thread per address space, so
//! `exit` and `exit_group` observe the same teardown contract for proc-table state.

use super::pipe::wait_key_for_parent;
use super::table::{exit_status_word, table_mut, ProcId};
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::sched::wait::wake_all;

/// Publish exit status, retire the proc-table slot, and wake the parent wait queue.
///
/// The caller must already hold a proc-table slot for `id` (registered at launch or fork).
pub(crate) fn publish_linux_exit(id: ProcId, status: u32, finalize_children: bool) {
    let table = table_mut();
    if table.require_proc_slot(id).is_err() {
        fatal_kernel_error("linux exit without proc-table slot");
    }
    let parent_pid = table.parent_of(id).map_or(id.pid, |p| p.pid);
    table.publish_exit(id, exit_status_word(status, None));
    if finalize_children {
        table.finalize_children_on_parent_exit(id);
    }
    table.retire_slot(id);
    wake_all(wait_key_for_parent(parent_pid));
}
