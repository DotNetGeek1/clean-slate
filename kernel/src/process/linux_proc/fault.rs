//! Linux fault → waitable status (#102).

use super::exit_publish::publish_linux_signalled_exit;
use super::table::ProcId;
use crate::process::live_instance_generation;
use crate::process::personality::{execution_personality_for_pid, ExecutionPersonality};

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
    publish_linux_signalled_exit(id, signal);
}

const PAGE_FAULT_VECTOR: u64 = 14;
const INVALID_OPCODE_VECTOR: u64 = 6;
const GENERAL_PROTECTION_VECTOR: u64 = 13;

pub(crate) fn fault_vector_to_signal(vector: u64) -> u32 {
    match vector {
        INVALID_OPCODE_VECTOR => 4,                          // SIGILL
        PAGE_FAULT_VECTOR | GENERAL_PROTECTION_VECTOR => 11, // SIGSEGV
        _ => 11,
    }
}
