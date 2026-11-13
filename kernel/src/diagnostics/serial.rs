use core::fmt::{self, Write};

use crate::arch::x86_64::port::{port_in, port_out};

pub(crate) const COM1: u16 = 0x3F8;
const LSR_TRANSMIT_EMPTY: u8 = 0x20;

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

/// Write raw bytes to COM1 without UTF-8 interpretation or formatting, as one record like
/// [`serial_write_fmt`], so serial console echo can never land inside it.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn serial_write_bytes(bytes: &[u8]) {
    #[cfg(not(test))]
    x86_64::instructions::interrupts::without_interrupts(|| {
        bytes.iter().for_each(|byte| serial_write_byte(*byte));
    });
    #[cfg(test)]
    bytes.iter().for_each(|byte| serial_write_byte(*byte));
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
    while (line_status() & LSR_TRANSMIT_EMPTY) == 0 {}
    port_out(COM1, byte);
}

/// Reading the line status clears its receive error bits; with receive compiled in, they are
/// handed to the receive interrupt so a flagged byte is still discarded there.
fn line_status() -> u8 {
    let lsr = port_in(COM1 + 5);
    #[cfg(clean_slate_serial_console)]
    crate::device::serial_console::note_transmit_line_status(lsr);
    lsr
}
