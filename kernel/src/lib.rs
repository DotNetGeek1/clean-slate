#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]

mod arch;
mod boot;
mod diagnostics;
mod interrupt;
mod ipc;
mod mm;
mod process;
mod sched;
mod selftest;
mod sync;
mod syscall;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

pub fn run() -> uefi::Status {
    boot::run()
}
