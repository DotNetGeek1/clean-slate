//! COM1 behind [`UartIo`], the IRQ 4 route and handler, and [`enable`]. Compiled with
//! `clean_slate_serial_console`, which `kernel/build.rs` emits only together with
//! `clean_slate_isa_irq`.

use core::sync::atomic::{AtomicU8, Ordering};

use super::console_mut;
use super::line_discipline::EchoSink;
use super::uart::{self, UartIo, IER_RECEIVE, LSR_ABSENT, LSR_CLEARED_ON_READ};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::port::{port_in, port_out};
use crate::diagnostics::serial::{serial_write_bytes, COM1};
use crate::interrupt::irq::{allocate_device_vector, release_device_vector, route_isa_irq};

const RBR: u16 = COM1;
const IER: u16 = COM1 + 1;
const IIR: u16 = COM1 + 2;
const LSR: u16 = COM1 + 5;
const MSR: u16 = COM1 + 6;

const COM1_IRQ: u8 = 4;
/// Bytes discarded at enable: anything typed before receive was on is not input.
const STALE_FLUSH_LIMIT: u32 = 64;

/// Receive error bits that a transmit-side line-status read cleared before the receive
/// interrupt read them. They describe the byte at the top of the receive FIFO, which only the
/// interrupt removes, so handing them over keeps them attached to the right byte.
static TRANSMIT_SEEN_ERRORS: AtomicU8 = AtomicU8::new(0);

/// Called by the transmit path with every line status it reads.
pub(crate) fn note_transmit_line_status(lsr: u8) {
    if lsr != LSR_ABSENT && lsr & LSR_CLEARED_ON_READ != 0 {
        TRANSMIT_SEEN_ERRORS.fetch_or(lsr & LSR_CLEARED_ON_READ, Ordering::Relaxed);
    }
}

struct Com1;

impl EchoSink for Com1 {
    fn echo(&mut self, bytes: &[u8]) {
        serial_write_bytes(bytes);
    }
}

impl UartIo for Com1 {
    fn read_iir(&mut self) -> u8 {
        port_in(IIR)
    }

    fn read_lsr(&mut self) -> u8 {
        let lsr = port_in(LSR);
        if lsr == LSR_ABSENT {
            return lsr;
        }
        lsr | TRANSMIT_SEEN_ERRORS.swap(0, Ordering::Relaxed)
    }

    fn read_rbr(&mut self) -> u8 {
        port_in(RBR)
    }

    fn read_msr(&mut self) -> u8 {
        port_in(MSR)
    }

    fn write_ier(&mut self, value: u8) {
        port_out(IER, value);
    }
}

fn com1_interrupt() {
    let state = console_mut();
    if uart::drain(&mut Com1, &mut state.discipline, &mut state.uart).wake {
        state.wake_readers();
    }
}

/// Turns COM1 receive on: discards stale input, routes ISA IRQ 4 and sets the receive bits of
/// the interrupt-enable register. Returns the device vector. Idempotent; call with the IDT
/// and the local APIC up. Nothing is changed when it fails.
pub(crate) fn enable() -> Result<u8, &'static str> {
    without_interrupts(|| {
        let state = console_mut();
        if let Some(vector) = state.vector {
            return Ok(vector);
        }
        if port_in(LSR) == LSR_ABSENT {
            return Err("serial console: COM1 is absent");
        }
        let vector = allocate_device_vector(com1_interrupt)?;
        if let Err(message) = route_isa_irq(COM1_IRQ, vector) {
            release_device_vector(vector);
            return Err(message);
        }
        state.uart.stale = uart::flush_stale(&mut Com1, STALE_FLUSH_LIMIT);
        TRANSMIT_SEEN_ERRORS.store(0, Ordering::Relaxed);
        port_out(IER, IER_RECEIVE);
        state.vector = Some(vector);
        Ok(vector)
    })
}
