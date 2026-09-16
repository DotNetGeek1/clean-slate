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

pub(crate) fn port_out_u16(port: u16, value: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nostack, nomem, preserves_flags));
    }
}

pub(crate) fn port_in_u16(port: u16) -> u16 {
    let value: u16;
    unsafe {
        asm!("in ax, dx", in("dx") port, out("ax") value, options(nostack, nomem, preserves_flags));
    }
    value
}

pub(crate) fn port_out_u32(port: u16, value: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nostack, nomem, preserves_flags));
    }
}

pub(crate) fn port_in_u32(port: u16) -> u32 {
    let value: u32;
    unsafe {
        asm!("in eax, dx", in("dx") port, out("eax") value, options(nostack, nomem, preserves_flags));
    }
    value
}
