//! Linux fault → waitable status (#102).

use super::pipe::wait_key_for_parent;
use super::table::{exit_status_word, table_mut, ProcId};
use crate::process::live_instance_generation;
use crate::process::personality::{execution_personality_for_pid, ExecutionPersonality};
use crate::sched::wait::wake_all;

/// Publish a signalled zombie before production fault teardown runs.
pub(crate) fn publish_linux_fault_exit(pid: u64, vector: u64) {
    let Ok(personality) = execution_personality_for_pid(pid) else {
        return;
    };
    if personality != ExecutionPersonality::LinuxX86_64 {
        return;
    }
    let Some(generation) = live_instance_generation(pid) else {
        return;
    };
    let signal = fault_vector_to_signal(vector);
    let id = ProcId { pid, generation };
    let parent_pid = table_mut().parent_of(id).map_or(pid, |p| p.pid);
    table_mut().publish_exit(id, exit_status_word(0, Some(signal)));
    wake_all(wait_key_for_parent(parent_pid));
}

const PAGE_FAULT_VECTOR: u64 = 14;
const INVALID_OPCODE_VECTOR: u64 = 6;
const GENERAL_PROTECTION_VECTOR: u64 = 13;

fn fault_vector_to_signal(vector: u64) -> u32 {
    match vector {
        INVALID_OPCODE_VECTOR => 4,                          // SIGILL
        PAGE_FAULT_VECTOR | GENERAL_PROTECTION_VECTOR => 11, // SIGSEGV
        _ => 11,
    }
}
