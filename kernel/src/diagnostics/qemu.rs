use core::arch::asm;

use crate::diagnostics::serial::serial_write_fmt;

const QEMU_EXIT_PORT: u16 = 0xf4;
pub(crate) const QEMU_EXIT_SUCCESS: u32 = 0x10;
pub(crate) const QEMU_EXIT_FAILURE: u32 = 0x11;

pub(crate) fn qemu_exit(value: u32) -> ! {
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

pub(crate) fn fatal_kernel_error(message: &'static str) -> ! {
    serial_write_fmt(format_args!("[FAIL] {message}\n"));
    qemu_exit_failure()
}
