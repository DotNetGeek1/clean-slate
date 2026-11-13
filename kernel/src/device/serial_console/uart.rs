//! 16550 receive-interrupt drain, written against [`UartIo`] so host tests can drive it with a
//! scripted UART.

use super::line_discipline::{EchoSink, LineDiscipline};

const IIR_NO_INTERRUPT: u8 = 1 << 0;
const IIR_ID_MASK: u8 = 0x0E;
const IIR_MODEM_STATUS: u8 = 0x00;

const LSR_DATA_READY: u8 = 1 << 0;
const LSR_OVERRUN: u8 = 1 << 1;
const LSR_PARITY: u8 = 1 << 2;
const LSR_FRAMING: u8 = 1 << 3;
const LSR_BREAK: u8 = 1 << 4;
/// Bits that describe the byte at the top of the receive FIFO, which is then not data.
pub(super) const LSR_BYTE_ERRORS: u8 = LSR_PARITY | LSR_FRAMING | LSR_BREAK;
/// Sticky error bits a line-status read clears; the transmit path hands back the ones it saw.
#[cfg(clean_slate_serial_console)]
pub(super) const LSR_CLEARED_ON_READ: u8 = LSR_OVERRUN | LSR_BYTE_ERRORS;
/// A missing UART floats the bus; every bit reads set.
pub(super) const LSR_ABSENT: u8 = 0xFF;

/// Received-data-available and receiver-line-status interrupts.
pub(super) const IER_RECEIVE: u8 = 0b0000_0101;

/// Bytes read per interrupt: one receive FIFO's worth. Echo is at most three bytes per byte
/// read, except that one Ctrl-U erases the whole edit line (up to 768 bytes of echo).
pub(super) const DRAIN_BUDGET: u32 = 16;
/// Interrupt-identification passes per interrupt. Each pass clears one condition; a UART that
/// keeps reporting one is left for the re-armed edge.
const MAX_IIR_PASSES: u32 = 4;

pub(super) trait UartIo: EchoSink {
    fn read_iir(&mut self) -> u8;
    /// Line status, including any error bits the transmit path consumed since the last call.
    fn read_lsr(&mut self) -> u8;
    fn read_rbr(&mut self) -> u8;
    fn read_msr(&mut self) -> u8;
    fn write_ier(&mut self, value: u8);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct UartStats {
    pub(crate) irqs: u32,
    /// Interrupts with nothing pending in the interrupt-identification register.
    pub(crate) spurious: u32,
    /// Bytes read from the receive buffer, refused ones included.
    pub(crate) bytes: u32,
    /// Most bytes one interrupt read; never more than [`DRAIN_BUDGET`].
    pub(crate) max_drained: u32,
    /// Line-status reads reporting that the receiver lost bytes before the drain reached them.
    pub(crate) overruns: u32,
    /// Bytes discarded because the line status flagged them (parity, framing, break).
    pub(crate) line_errors: u32,
    /// Interrupts left with a condition still pending, re-armed by toggling the enable register.
    pub(crate) rearms: u32,
    /// Stale bytes discarded when receive was enabled.
    pub(crate) stale: u32,
}

/// What one interrupt did that the caller acts on.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DrainOutcome {
    /// A line was committed or an end-of-file recorded: wake console readers.
    pub(super) wake: bool,
}

/// One receive interrupt. Reads the interrupt-identification register until it reports nothing
/// pending, at most [`MAX_IIR_PASSES`] times, draining at most [`DRAIN_BUDGET`] bytes in total.
/// With an edge-triggered route a condition left pending would hold the line high forever, so
/// if one remains the receive interrupts are disabled and re-enabled, which drops and raises
/// the line and gives the I/O APIC a fresh edge after EOI.
pub(super) fn drain(
    io: &mut impl UartIo,
    discipline: &mut LineDiscipline,
    stats: &mut UartStats,
) -> DrainOutcome {
    bump(&mut stats.irqs);
    let bytes_before = stats.bytes;
    let mut budget = DRAIN_BUDGET;
    let mut iir = io.read_iir();
    if iir & IIR_NO_INTERRUPT != 0 {
        bump(&mut stats.spurious);
    }
    let mut passes = 0;
    while iir & IIR_NO_INTERRUPT == 0 && passes < MAX_IIR_PASSES {
        passes += 1;
        if iir & IIR_ID_MASK == IIR_MODEM_STATUS {
            let _ = io.read_msr();
        }
        // Line status, received data and character timeout are all cleared by reading the
        // line status and draining the receive buffer; a transmit-empty condition (never
        // enabled) is cleared by the identification read itself.
        drain_receive(io, discipline, stats, &mut budget);
        iir = io.read_iir();
        if budget == 0 {
            break;
        }
    }
    stats.max_drained = stats.max_drained.max(stats.bytes - bytes_before);
    if iir & IIR_NO_INTERRUPT == 0 {
        io.write_ier(0);
        io.write_ier(IER_RECEIVE);
        bump(&mut stats.rearms);
    }
    DrainOutcome {
        wake: discipline.take_wake(),
    }
}

fn drain_receive(
    io: &mut impl UartIo,
    discipline: &mut LineDiscipline,
    stats: &mut UartStats,
    budget: &mut u32,
) {
    while *budget > 0 {
        let lsr = io.read_lsr();
        if lsr == LSR_ABSENT || lsr & LSR_DATA_READY == 0 {
            if lsr != LSR_ABSENT && lsr & LSR_OVERRUN != 0 {
                bump(&mut stats.overruns);
            }
            return;
        }
        if lsr & LSR_OVERRUN != 0 {
            bump(&mut stats.overruns);
        }
        let byte = io.read_rbr();
        *budget -= 1;
        bump(&mut stats.bytes);
        if lsr & LSR_BYTE_ERRORS != 0 {
            bump(&mut stats.line_errors);
            continue;
        }
        discipline.feed(byte, io);
    }
}

/// Discards bytes received before the interrupt was enabled; returns how many.
pub(super) fn flush_stale(io: &mut impl UartIo, limit: u32) -> u32 {
    let mut flushed = 0;
    while flushed < limit {
        let lsr = io.read_lsr();
        if lsr == LSR_ABSENT || lsr & LSR_DATA_READY == 0 {
            break;
        }
        let _ = io.read_rbr();
        flushed += 1;
    }
    flushed
}

fn bump(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

#[cfg(test)]
mod tests;
