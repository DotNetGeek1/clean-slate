#![cfg_attr(not(test), no_std)]

mod arch;
mod boot;
mod diagnostics;
mod interrupt;
mod ipc;
mod mm;
mod process;
mod sched;
mod service;
// Milestone self-tests exit QEMU before the normal boot tail runs, so each
// feature build leaves parts of its own scaffolding unreferenced. The
// allowance is scoped to this module only; production modules must stay
// warning-clean in every configuration.
#[cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test",
        feature = "m4-service-lifecycle-self-test"
    ),
    allow(dead_code)
)]
mod selftest;
mod sync;
mod syscall;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

pub fn run() -> uefi::Status {
    boot::run()
}
