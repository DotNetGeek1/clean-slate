use core::arch::asm;

use crate::diagnostics::serial::{serial_drain, serial_write_fmt};

const QEMU_EXIT_PORT: u16 = 0xf4;
pub(crate) const QEMU_EXIT_SUCCESS: u32 = 0x10;
pub(crate) const QEMU_EXIT_FAILURE: u32 = 0x11;

/// The only way the kernel ends a QEMU run: every fault, panic, fatal init error and self-test
/// verdict comes through here, so the serial drain before the exit write covers all of them.
pub(crate) fn qemu_exit(value: u32) -> ! {
    serial_drain();
    unsafe {
        asm!("out dx, eax", in("dx") QEMU_EXIT_PORT, in("eax") value, options(nostack, nomem, preserves_flags));
    }
    halt_loop()
}

pub fn qemu_exit_failure() -> ! {
    qemu_exit(QEMU_EXIT_FAILURE)
}

pub(crate) fn halt_loop() -> ! {
    loop {
        unsafe {
            asm!("cli", options(nomem, nostack, preserves_flags));
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

/// Stops the machine. For kernel invariants only (#215): a value derived from a user
/// register or user memory, or any outcome a user process can cause, must fail that
/// process (an errno, or the CPL3 fault teardown), never reach this. A call site on a
/// syscall or user-fault path says in a comment why user mode cannot reach it.
pub(crate) fn fatal_kernel_error(message: &'static str) -> ! {
    serial_write_fmt(format_args!("[FAIL] {message}\n"));
    qemu_exit_failure()
}
