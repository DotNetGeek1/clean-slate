//! Serial console input (#218 S4): the COM1 receive interrupt feeds a canonical-mode line
//! discipline, and console readers take finished lines from it.
//!
//! Receive is compiled only with `clean_slate_serial_console` (emitted by `kernel/build.rs`) and
//! is off until something calls [`enable`]; until then COM1 keeps its interrupt-enable register
//! at 0 and nothing reads the receive buffer, so input on the line is never echoed.
//!
//! Readers (the S5 console descriptor) use [`read`], [`would_block`] and [`take_eof`], and block
//! on [`CONSOLE_INPUT_KEY`] with `block_current_thread_unless`; the interrupt wakes that key with
//! `wake_all_registered` whenever a line is committed or an end-of-file recorded, and then runs
//! the notifier from [`set_input_notifier`] (for `poll` readiness).
//!
//! Single CPU: the state is mutated only in the IRQ 4 handler (interrupts masked) or under
//! `without_interrupts`.

#[cfg(clean_slate_serial_console)]
mod hardware;
mod line_discipline;
mod uart;

use crate::arch::x86_64::cpu::without_interrupts;
use crate::sched::wait::{wake_all_registered, WaitKey};
use crate::sync::global_cell::GlobalCell;

#[cfg(clean_slate_serial_console)]
pub(crate) use hardware::{enable, note_transmit_line_status};
pub(crate) use line_discipline::LineStats;
pub(crate) use uart::UartStats;

/// Console readers block on this key; the receive interrupt wakes it.
pub(crate) const CONSOLE_INPUT_KEY: WaitKey = WaitKey(0x43 << 56);

/// Line discipline, UART and wake counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ConsoleStats {
    pub(crate) line: LineStats,
    pub(crate) uart: UartStats,
    /// Wakes issued on [`CONSOLE_INPUT_KEY`] (several commits in one interrupt issue one).
    pub(crate) wakes: u32,
    /// Waiters those wakes made runnable.
    pub(crate) woken: u32,
    /// Bytes committed and waiting for a reader.
    pub(crate) committed: u32,
    /// A finished line is waiting for committed space.
    pub(crate) deferred_line: bool,
}

struct ConsoleState {
    discipline: line_discipline::LineDiscipline,
    uart: UartStats,
    wakes: u32,
    woken: u32,
    notifier: Option<fn()>,
    #[cfg(clean_slate_serial_console)]
    vector: Option<u8>,
}

impl ConsoleState {
    const fn new() -> Self {
        Self {
            discipline: line_discipline::LineDiscipline::new(),
            uart: UartStats {
                irqs: 0,
                spurious: 0,
                bytes: 0,
                max_drained: 0,
                overruns: 0,
                line_errors: 0,
                rearms: 0,
                stale: 0,
            },
            wakes: 0,
            woken: 0,
            notifier: None,
            #[cfg(clean_slate_serial_console)]
            vector: None,
        }
    }

    /// Harmless with no waiter: `wake_all_registered` records no pending wake.
    fn wake_readers(&mut self) {
        self.wakes = self.wakes.saturating_add(1);
        let woken = wake_all_registered(CONSOLE_INPUT_KEY);
        self.woken = self
            .woken
            .saturating_add(u32::try_from(woken).unwrap_or(u32::MAX));
        if let Some(notifier) = self.notifier {
            notifier();
        }
    }
}

static CONSOLE: GlobalCell<ConsoleState> = GlobalCell::new(ConsoleState::new());

fn console_mut() -> &'static mut ConsoleState {
    // SAFETY: single CPU; the state is borrowed only in the IRQ 4 handler (interrupts masked)
    // or under `without_interrupts`, so no two borrows overlap.
    unsafe { &mut *CONSOLE.get() }
}

/// Copies committed input into `out`, stopping after a `\n`, at the end of a line committed by
/// Ctrl-D, and before an unread end-of-file. Returns the byte count; 0 means nothing to read
/// (check [`take_eof`], then block). A read that makes room for a waiting line commits it and
/// wakes the other readers.
pub(crate) fn read(out: &mut [u8]) -> usize {
    without_interrupts(|| {
        let state = console_mut();
        let copied = state.discipline.read(out);
        if state.discipline.take_wake() {
            state.wake_readers();
        }
        copied
    })
}

/// Whether [`read`] would return 0 and [`take_eof`] false.
pub(crate) fn would_block() -> bool {
    without_interrupts(|| console_mut().discipline.would_block())
}

/// Consumes the pending end-of-file if no committed input is ahead of it.
pub(crate) fn take_eof() -> bool {
    without_interrupts(|| console_mut().discipline.take_eof())
}

/// Runs `notifier` after each wake of [`CONSOLE_INPUT_KEY`], in interrupt context or in the
/// reader's syscall. It must not block.
pub(crate) fn set_input_notifier(notifier: Option<fn()>) {
    without_interrupts(|| console_mut().notifier = notifier);
}

pub(crate) fn stats() -> ConsoleStats {
    without_interrupts(|| {
        let state = console_mut();
        ConsoleStats {
            line: state.discipline.stats(),
            uart: state.uart,
            wakes: state.wakes,
            woken: state.woken,
            committed: state.discipline.committed_len() as u32,
            deferred_line: state.discipline.has_deferred_line(),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::line_discipline::EchoSink;
    use super::*;
    use core::sync::atomic::{AtomicU32, Ordering};

    struct NoEcho;

    impl EchoSink for NoEcho {
        fn echo(&mut self, _bytes: &[u8]) {}
    }

    /// The IRQ path in miniature: feed, then wake if the discipline asks.
    fn receive(bytes: &[u8]) {
        let state = console_mut();
        for byte in bytes {
            state.discipline.feed(*byte, &mut NoEcho);
        }
        if state.discipline.take_wake() {
            state.wake_readers();
        }
    }

    #[test]
    fn readers_see_committed_lines_then_the_end_of_file() {
        assert!(would_block());
        receive(b"echo hi\r\x04");
        assert!(!would_block());
        let mut buffer = [0u8; 32];
        assert_eq!(read(&mut buffer), 8);
        assert_eq!(&buffer[..8], b"echo hi\n");
        assert!(!would_block());
        assert_eq!(read(&mut buffer), 0);
        assert!(take_eof());
        assert!(would_block());
    }

    #[test]
    fn a_wake_with_no_waiter_is_counted_and_harmless() {
        receive(b"a\r");
        let stats = stats();
        assert_eq!((stats.wakes, stats.woken), (1, 0));
        assert_eq!(stats.committed, 2);
        assert_eq!(stats.line.lines, 1);
    }

    static NOTIFIED: AtomicU32 = AtomicU32::new(0);

    fn count_notification() {
        NOTIFIED.fetch_add(1, Ordering::Relaxed);
    }

    #[test]
    fn the_notifier_runs_after_each_wake_including_a_deferred_commit() {
        set_input_notifier(Some(count_notification));
        let before = NOTIFIED.load(Ordering::Relaxed);
        for _ in 0..8 {
            let mut line = [b'n'; 128];
            line[127] = b'\r';
            receive(&line);
        }
        receive(b"late\r");
        assert!(stats().deferred_line);
        let mut buffer = [0u8; 256];
        assert_eq!(read(&mut buffer), 128);
        assert!(!stats().deferred_line);
        assert_eq!(
            stats().wakes,
            9,
            "eight commits, then the deferred one from the read"
        );
        assert_eq!(NOTIFIED.load(Ordering::Relaxed) - before, 9);
        set_input_notifier(None);
    }
}
