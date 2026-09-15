//! Legacy I/O port access.
//!
//! Why unsafe: `in`/`out` touch hardware directly. Callers must only use port
//! numbers that are known to belong to the intended device (COM1, PIC, QEMU
//! debug-exit); there is no link contract.

use core::arch::asm;

pub(crate) fn port_out(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem, preserves_flags));
    }
}

pub(crate) fn port_in(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, nomem, preserves_flags));
    }
    value
}
