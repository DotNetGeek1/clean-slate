use std::collections::VecDeque;
use std::vec::Vec;

use super::*;

/// A 16550 receiver: a FIFO of bytes, each with the line-status error bits it arrives with,
/// a sticky overrun flag, and an interrupt identification derived from that state.
#[derive(Default)]
struct FakeUart {
    fifo: VecDeque<(u8, u8)>,
    overrun: bool,
    modem_status_pending: bool,
    /// Reports this identification forever, whatever the state (a wedged or absent UART).
    stuck_iir: Option<u8>,
    absent: bool,
    ier_writes: Vec<u8>,
    echo: Vec<u8>,
    rbr_reads: u32,
}

impl FakeUart {
    fn receive(&mut self, bytes: &[u8]) {
        self.fifo.extend(bytes.iter().map(|byte| (*byte, 0)));
    }
}

impl EchoSink for FakeUart {
    fn echo(&mut self, bytes: &[u8]) {
        self.echo.extend_from_slice(bytes);
    }
}

impl UartIo for FakeUart {
    fn read_iir(&mut self) -> u8 {
        if let Some(iir) = self.stuck_iir {
            return iir;
        }
        if self.absent {
            return 0xFF;
        }
        let top_error = self.fifo.front().is_some_and(|(_, errors)| *errors != 0);
        if self.overrun || top_error {
            0x06
        } else if !self.fifo.is_empty() {
            0x04
        } else if self.modem_status_pending {
            0x00
        } else {
            0x01
        }
    }

    fn read_lsr(&mut self) -> u8 {
        if self.absent {
            return LSR_ABSENT;
        }
        let mut lsr = 0x60;
        if let Some((_, errors)) = self.fifo.front() {
            lsr |= LSR_DATA_READY | errors;
        }
        if core::mem::take(&mut self.overrun) {
            lsr |= LSR_OVERRUN;
        }
        lsr
    }

    fn read_rbr(&mut self) -> u8 {
        self.rbr_reads += 1;
        self.fifo.pop_front().map_or(0, |(byte, _)| byte)
    }

    fn read_msr(&mut self) -> u8 {
        self.modem_status_pending = false;
        0
    }

    fn write_ier(&mut self, value: u8) {
        self.ier_writes.push(value);
    }
}

struct Rig {
    uart: FakeUart,
    discipline: std::boxed::Box<LineDiscipline>,
    stats: UartStats,
}

impl Rig {
    fn new() -> Self {
        Self {
            uart: FakeUart::default(),
            discipline: std::boxed::Box::new(LineDiscipline::new()),
            stats: UartStats::default(),
        }
    }

    fn interrupt(&mut self) -> DrainOutcome {
        drain(&mut self.uart, &mut self.discipline, &mut self.stats)
    }

    fn read_line(&mut self) -> Vec<u8> {
        let mut buffer = [0u8; 256];
        let copied = self.discipline.read(&mut buffer);
        buffer[..copied].to_vec()
    }
}

#[test]
fn an_interrupt_drains_the_fifo_into_the_discipline_and_echoes() {
    let mut rig = Rig::new();
    rig.uart.receive(b"ls\r");
    assert!(rig.interrupt().wake, "a committed line wakes readers");
    assert_eq!(rig.uart.echo, b"ls\r\n");
    assert_eq!(rig.read_line(), b"ls\n");
    assert_eq!(rig.stats.bytes, 3);
    assert_eq!(rig.stats.rearms, 0);
    assert!(rig.uart.ier_writes.is_empty());
}

#[test]
fn only_a_finished_line_wakes() {
    let mut rig = Rig::new();
    rig.uart.receive(b"l");
    assert!(!rig.interrupt().wake, "an edit line is not readable");
    rig.uart.receive(b"\x04");
    assert!(
        rig.interrupt().wake,
        "Ctrl-D on a non-empty line commits it"
    );
    assert_eq!(rig.read_line(), b"l");
}

#[test]
fn ctrl_d_on_an_empty_line_wakes_readers() {
    let mut rig = Rig::new();
    rig.uart.receive(b"\x04");
    assert!(rig.interrupt().wake);
    assert!(rig.discipline.take_eof());
}

#[test]
fn a_byte_with_a_framing_or_parity_error_is_discarded_and_counted() {
    let mut rig = Rig::new();
    rig.uart.fifo.push_back((b'a', 0));
    rig.uart.fifo.push_back((b'?', LSR_FRAMING));
    rig.uart.fifo.push_back((b'!', LSR_PARITY));
    rig.uart.fifo.push_back((0, LSR_BREAK));
    rig.uart.receive(b"b\r");
    rig.interrupt();
    assert_eq!(rig.read_line(), b"ab\n");
    assert_eq!(rig.stats.line_errors, 3);
    assert_eq!(
        rig.stats.bytes, 6,
        "flagged bytes are still read out of the FIFO"
    );
    assert!(rig.uart.fifo.is_empty());
}

#[test]
fn an_overrun_is_counted_and_the_bytes_that_did_arrive_are_kept() {
    let mut rig = Rig::new();
    rig.uart.receive(b"ok\r");
    rig.uart.overrun = true;
    rig.interrupt();
    assert_eq!(rig.stats.overruns, 1);
    assert_eq!(rig.read_line(), b"ok\n");
}

#[test]
fn an_overrun_reported_with_an_empty_fifo_is_counted_and_cleared() {
    let mut rig = Rig::new();
    rig.uart.overrun = true;
    rig.interrupt();
    assert_eq!(rig.stats.overruns, 1);
    assert_eq!(rig.uart.read_iir(), 0x01, "the line-status read cleared it");
    assert_eq!(rig.stats.rearms, 0);
}

#[test]
fn the_drain_is_bounded_and_rearms_the_edge_when_bytes_remain() {
    let mut rig = Rig::new();
    rig.uart.receive(&[b'x'; 40]);
    rig.interrupt();
    assert_eq!(rig.stats.bytes, DRAIN_BUDGET);
    assert_eq!(rig.stats.max_drained, DRAIN_BUDGET);
    assert_eq!(rig.uart.fifo.len(), 40 - DRAIN_BUDGET as usize);
    assert_eq!(
        rig.uart.ier_writes,
        [0, IER_RECEIVE],
        "disable then enable re-raises the line"
    );
    assert_eq!(rig.stats.rearms, 1);
    rig.interrupt();
    rig.interrupt();
    assert!(rig.uart.fifo.is_empty());
    assert_eq!(rig.stats.bytes, 40);
    assert_eq!(
        rig.stats.rearms, 2,
        "the interrupt that empties the FIFO does not re-arm"
    );
    assert_eq!(rig.uart.echo, std::vec![b'x'; 40]);
}

#[test]
fn a_spurious_interrupt_reads_no_data() {
    let mut rig = Rig::new();
    assert!(!rig.interrupt().wake);
    assert_eq!(rig.stats.spurious, 1);
    assert_eq!(rig.uart.rbr_reads, 0);
    assert_eq!(rig.stats.max_drained, 0);
}

#[test]
fn a_modem_status_interrupt_is_cleared_by_reading_the_modem_status() {
    let mut rig = Rig::new();
    rig.uart.modem_status_pending = true;
    rig.uart.receive(b"a");
    rig.interrupt();
    assert!(!rig.uart.modem_status_pending);
    assert_eq!(rig.uart.read_iir(), 0x01);
    assert_eq!(rig.stats.rearms, 0);
}

#[test]
fn a_uart_that_never_clears_its_interrupt_cannot_wedge_the_handler() {
    let mut rig = Rig::new();
    rig.uart.stuck_iir = Some(0x06);
    rig.interrupt();
    assert_eq!(rig.stats.rearms, 1);
    assert_eq!(rig.uart.rbr_reads, 0, "line status said no data");
}

#[test]
fn an_absent_uart_reads_as_spurious_and_drains_nothing() {
    let mut rig = Rig::new();
    rig.uart.absent = true;
    rig.interrupt();
    assert_eq!(rig.stats.spurious, 1);
    assert_eq!(rig.uart.rbr_reads, 0);
    assert_eq!(flush_stale(&mut rig.uart, 32), 0);
}

#[test]
fn flush_stale_discards_queued_bytes_up_to_its_limit() {
    let mut rig = Rig::new();
    rig.uart.receive(&[b'z'; 40]);
    assert_eq!(flush_stale(&mut rig.uart, 32), 32);
    assert_eq!(flush_stale(&mut rig.uart, 32), 8);
    assert!(rig.uart.echo.is_empty(), "stale bytes are never echoed");
}

#[test]
fn burst_lines_across_interrupts_all_arrive_in_order() {
    let mut rig = Rig::new();
    rig.uart.receive(b"one\rtwo\rthree\rfour\rfive\rsix\r");
    let mut wakes = 0;
    while !rig.uart.fifo.is_empty() {
        wakes += u32::from(rig.interrupt().wake);
    }
    assert!(wakes >= 2, "a 28-byte burst spans at least two interrupts");
    assert_eq!(rig.stats.max_drained, DRAIN_BUDGET);
    for line in [
        &b"one\n"[..],
        b"two\n",
        b"three\n",
        b"four\n",
        b"five\n",
        b"six\n",
    ] {
        assert_eq!(rig.read_line(), line);
    }
    assert_eq!(
        rig.uart.echo,
        b"one\r\ntwo\r\nthree\r\nfour\r\nfive\r\nsix\r\n"
    );
}
