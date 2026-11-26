use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(any(test, clean_slate_system_init))]
use clean_slate_native_abi::console::CONSOLE_LINE_TAG;

use crate::arch::x86_64::port::{port_in, port_out};

pub(crate) const COM1: u16 = 0x3F8;
const LSR_TRANSMIT_EMPTY: u8 = 0x20;
/// Holding register and shift register both empty: every byte written so far has left the UART.
const LSR_TRANSMITTER_IDLE: u8 = 0x40;
/// Upper bound on line-status reads while draining, so a wedged UART cannot hang an exit path.
const DRAIN_POLL_LIMIT: u32 = 50_000_000;

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
        end_console_line();
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
        end_console_line();
        bytes.iter().for_each(|byte| serial_write_byte(*byte));
    });
    #[cfg(test)]
    bytes.iter().for_each(|byte| serial_write_byte(*byte));
}

/// Whether the last byte on COM1 ended a line (true before the first byte).
static AT_LINE_START: AtomicBool = AtomicBool::new(true);
/// Whether the line COM1 is on was started by the console device and not yet ended.
static CONSOLE_LINE_OPEN: AtomicBool = AtomicBool::new(false);

/// Where the serial line stands, as the console device's tagging sees it.
#[cfg(any(test, clean_slate_system_init))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SerialLineState {
    pub(crate) at_line_start: bool,
    pub(crate) console_line_open: bool,
}

/// Renders a console-device write (#310) for a line in `state`, through `emit`. Every line the
/// device starts begins with [`CONSOLE_LINE_TAG`]. A write that finds someone else's line open
/// ends it first, and a write that finds the device's own line open continues it, so the tag is
/// always at the start of a line and nothing the device writes can start a line without it.
#[cfg(any(test, clean_slate_system_init))]
pub(crate) fn render_console_device_bytes(
    state: &mut SerialLineState,
    bytes: &[u8],
    mut emit: impl FnMut(u8),
) {
    let mut at_start = if state.console_line_open && !state.at_line_start {
        false
    } else {
        if !state.at_line_start {
            emit(b'\n');
        }
        true
    };
    for &byte in bytes {
        if at_start {
            CONSOLE_LINE_TAG.bytes().for_each(&mut emit);
        }
        emit(byte);
        at_start = byte == b'\n';
    }
    state.at_line_start = at_start;
    state.console_line_open = !at_start;
}

/// Writes `bytes` from the console device (syscall 25) as one record, tagged per line by
/// [`render_console_device_bytes`].
#[cfg(any(test, clean_slate_system_init))]
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn serial_write_console_device(bytes: &[u8]) {
    let write = || {
        let mut state = SerialLineState {
            at_line_start: AT_LINE_START.load(Ordering::Relaxed),
            console_line_open: CONSOLE_LINE_OPEN.load(Ordering::Relaxed),
        };
        render_console_device_bytes(&mut state, bytes, serial_write_byte);
        CONSOLE_LINE_OPEN.store(state.console_line_open, Ordering::Relaxed);
    };
    #[cfg(not(test))]
    x86_64::instructions::interrupts::without_interrupts(write);
    #[cfg(test)]
    write();
}

/// Ends a line the console device left open, so a kernel record always starts a line of its
/// own. Runs with interrupts masked, inside the caller's record.
#[cfg(not(test))]
fn end_console_line() {
    if CONSOLE_LINE_OPEN.swap(false, Ordering::Relaxed) && !AT_LINE_START.load(Ordering::Relaxed) {
        serial_write_byte(b'\n');
    }
}

/// Waits until COM1 has shifted out every byte written so far. `serial_write_byte` only waits for
/// room in the FIFO, so the last bytes of a report can still be inside the UART. QEMU keeps a byte
/// in the shift register, with TEMT clear, until its chardev accepts it, and the debug-exit port
/// ends QEMU without flushing that byte. Bounded by [`DRAIN_POLL_LIMIT`]; a port with no UART
/// behind it reads all ones and returns at once.
pub(crate) fn serial_drain() {
    for _ in 0..DRAIN_POLL_LIMIT {
        if line_status() & LSR_TRANSMITTER_IDLE != 0 {
            return;
        }
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
    while (line_status() & LSR_TRANSMIT_EMPTY) == 0 {}
    port_out(COM1, byte);
    AT_LINE_START.store(byte == b'\n', Ordering::Relaxed);
}

/// Reading the line status clears its receive error bits; with receive compiled in, they are
/// handed to the receive interrupt so a flagged byte is still discarded there.
fn line_status() -> u8 {
    let lsr = port_in(COM1 + 5);
    #[cfg(clean_slate_serial_console)]
    crate::device::serial_console::note_transmit_line_status(lsr);
    lsr
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn render(state: &mut SerialLineState, bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        render_console_device_bytes(state, bytes, |byte| out.push(byte));
        out
    }

    const FRESH: SerialLineState = SerialLineState {
        at_line_start: true,
        console_line_open: false,
    };

    #[test]
    fn every_console_line_starts_with_the_tag() {
        let mut state = FRESH;
        assert_eq!(
            render(&mut state, b"pid=7: a\npid=7: [M4  ] PASS\n"),
            b"[CON ] pid=7: a\n[CON ] pid=7: [M4  ] PASS\n"
        );
        assert_eq!(state, FRESH);
    }

    #[test]
    fn a_line_someone_else_left_open_is_ended_first() {
        let mut state = SerialLineState {
            at_line_start: false,
            console_line_open: false,
        };
        assert_eq!(render(&mut state, b"x\n"), b"\n[CON ] x\n");
    }

    #[test]
    fn the_devices_own_open_line_is_continued() {
        let mut state = FRESH;
        assert_eq!(render(&mut state, b"# "), b"[CON ] # ");
        assert_eq!(
            state,
            SerialLineState {
                at_line_start: false,
                console_line_open: true,
            }
        );
        assert_eq!(render(&mut state, b"ls\n[M4  ]"), b"ls\n[CON ] [M4  ]");
        assert!(state.console_line_open);
    }
}
