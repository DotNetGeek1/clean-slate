use core::fmt::{self, Write};

use crate::arch::x86_64::port::{port_in, port_out};

const COM1: u16 = 0x3F8;

pub(crate) fn serial_init() {
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x80);
    port_out(COM1, 0x03);
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x03);
    port_out(COM1 + 2, 0xc7);
    port_out(COM1 + 4, 0x0b);
}

pub fn serial_write_line(message: &str) {
    serial_write_fmt(format_args!("{message}\n"));
}

/// One call emits one contiguous record: interrupts are masked (and the prior
/// IF restored) so preemption cannot splice another task's line into it.
pub fn serial_write_fmt(arguments: fmt::Arguments<'_>) {
    #[cfg(not(test))]
    x86_64::instructions::interrupts::without_interrupts(|| {
        let _ = SerialPort.write_fmt(arguments);
    });
    #[cfg(test)]
    let _ = SerialPort.write_fmt(arguments);
}

/// Write raw bytes to COM1 without UTF-8 interpretation or formatting.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn serial_write_bytes(bytes: &[u8]) {
    for byte in bytes {
        serial_write_byte(*byte);
    }
}

struct SerialPort;

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            serial_write_byte(byte);
        }
        Ok(())
    }
}

fn serial_write_byte(byte: u8) {
    while (port_in(COM1 + 5) & 0x20) == 0 {}
    port_out(COM1, byte);
}
