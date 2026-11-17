//! `system-test-hooks` (#218 S7b): the one test-only difference between the kernel that
//! `cargo xtask test-system` boots and the default image. Nothing else enables the feature.
//!
//! Receiving byte `0x1C` (Ctrl-\) on COM1 asks for the live network service instance to fault.
//! The default line discipline drops that byte as an unhandled control byte in every build,
//! so the hooks build changes nothing about how the shell's input is processed; it only also
//! notices the byte.
//!
//! The fault is a genuine CPU exception, not a simulated death: the hook points the saved
//! syscall frame of the network thread parked in a syscall at address 0, which is unmapped
//! in every address space, and cancels its waits. The thread leaves the syscall, fetches its
//! next instruction from page 0 and takes a user-mode page fault. From there everything
//! (fault report, init's restart policy, socket loss, capability revoke and re-issue) is the
//! production path the default image runs.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::capability::network::NETWORK_SERVICE_ID;
use crate::diagnostics::log::kernel_log_fmt;

use super::control::service_lifecycle_controller_mut;

/// COM1 byte that requests the network fault (ASCII FS, typed as Ctrl-\).
const FAULT_NETWORK_BYTE: u8 = 0x1c;
/// Where the redirected thread resumes: page 0 is never mapped, so the fetch faults.
const FAULT_USER_RIP: u64 = 0;

/// Set by the receive path, cleared once the fault is armed or there is nothing to fault.
static NETWORK_FAULT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Printed once COM1 receive is on, so every transcript says which build produced it.
pub(crate) fn announce() {
    kernel_log_fmt(format_args!(
        "[HOOK] system-test-hooks build: Ctrl-\\ on COM1 faults the network service\n"
    ));
}

/// COM1 receive path: records a fault request when `byte` is the fault byte.
pub(crate) fn observe_received_byte(byte: u8) {
    if byte == FAULT_NETWORK_BYTE {
        NETWORK_FAULT_REQUESTED.store(true, Ordering::Relaxed);
    }
}

/// Arms a requested fault. Called after every COM1 receive interrupt and on every timer
/// tick: the network thread can only be redirected while it is parked in a syscall, so a
/// request that arrives while it is running waits for the next tick that finds it parked.
pub(crate) fn run_pending() {
    if !NETWORK_FAULT_REQUESTED.load(Ordering::Relaxed) {
        return;
    }
    let controller = unsafe { service_lifecycle_controller_mut() };
    let Some(instance) = controller.live_service_instance_id(NETWORK_SERVICE_ID) else {
        NETWORK_FAULT_REQUESTED.store(false, Ordering::Relaxed);
        kernel_log_fmt(format_args!(
            "[HOOK] network fault requested but no network instance is live; ignored\n"
        ));
        return;
    };
    let Some(pid) = controller.live_pid(NETWORK_SERVICE_ID) else {
        return;
    };
    let Some(process_generation) = crate::process::live_instance_generation(pid) else {
        return;
    };
    if !crate::sched::wait::redirect_parked_native_syscall(pid, FAULT_USER_RIP) {
        return;
    }
    NETWORK_FAULT_REQUESTED.store(false, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[HOOK] network fault armed pid={} gen={} user_rip={:#x}\n",
        pid, instance.generation.0, FAULT_USER_RIP
    ));
    crate::sched::wait::cancel_waiters_for_process(pid, process_generation);
}
