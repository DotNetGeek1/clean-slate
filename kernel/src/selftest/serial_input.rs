//! `test-serial-input` (#218 S4): COM1 receive in boot context. The kernel turns receive on,
//! prints `[TTY ] ready`, and reports every console read as a `[TTY ] read` line carrying the
//! bytes in hex, so the host can check the echo and the committed lines byte for byte. No
//! scheduler thread exists: between reads the boot CPU halts with interrupts enabled, the
//! local APIC timer is masked, and only IRQ 4 wakes it. Ctrl-D on an empty line ends the lane.

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::arch::x86_64::apic::{enable_local_apic, mask_legacy_pic, mask_local_apic_timer};
use crate::arch::x86_64::cpu::{disable_interrupts, enable_interrupts_and_halt};
use crate::device::serial_console;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};

/// Smaller than a full line, so the host sees a 256-byte line split across two reads.
const READ_BUFFER_BYTES: usize = 128;
/// After a committed `hold\n` the lane stops reading until this many bytes have been refused
/// while a finished line waited for committed space. The host's next burst fills the committed
/// buffer, finishes one more line, then sends exactly this many bytes.
const HOLD_LINE: &[u8] = b"hold\n";
const HOLD_REFUSED_BYTES: u32 = 4;

static NOTIFICATIONS: AtomicU32 = AtomicU32::new(0);

fn count_notification() {
    NOTIFICATIONS.fetch_add(1, Ordering::Relaxed);
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

pub(crate) fn run_serial_input_self_test() -> ! {
    mask_legacy_pic();
    enable_local_apic();
    mask_local_apic_timer();
    serial_console::set_input_notifier(Some(count_notification));
    let vector = serial_console::enable().unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[TTY ] receive enabled irq=4 vector={vector:#04x} stale={}\n",
        serial_console::stats().uart.stale
    ));
    kernel_log_fmt(format_args!("[TTY ] ready\n"));

    let mut held_since: Option<u32> = None;
    loop {
        if let Some(refused_at_hold) = held_since {
            let stats = serial_console::stats();
            if stats.line.dropped_while_deferred - refused_at_hold >= HOLD_REFUSED_BYTES {
                kernel_log_fmt(format_args!(
                    "[TTY ] resume committed={} deferred_line={} refused={}\n",
                    stats.committed,
                    u8::from(stats.deferred_line),
                    stats.line.dropped_while_deferred - refused_at_hold
                ));
                held_since = None;
            }
        }
        while held_since.is_none() && !serial_console::would_block() {
            if serial_console::take_eof() {
                finish();
            }
            let mut buffer = [0u8; READ_BUFFER_BYTES];
            let copied = serial_console::read(&mut buffer);
            if copied == 0 {
                fatal_kernel_error("serial input: read found nothing though would_block was false");
            }
            let bytes = &buffer[..copied];
            kernel_log_fmt(format_args!(
                "[TTY ] read len={copied} hex={}\n",
                Hex(bytes)
            ));
            if bytes == HOLD_LINE {
                held_since = Some(serial_console::stats().line.dropped_while_deferred);
                kernel_log_fmt(format_args!("[TTY ] hold\n"));
            }
        }
        // `sti; hlt`: an IRQ raised since the reads above is taken by the halt, not lost.
        enable_interrupts_and_halt();
        disable_interrupts();
    }
}

fn finish() -> ! {
    let stats = serial_console::stats();
    let line = stats.line;
    let uart = stats.uart;
    kernel_log_fmt(format_args!("[TTY ] eof\n"));
    kernel_log_fmt(format_args!(
        "[TTY ] stats lines={} eofs={} deferred={} edit_overflow={} refused={} eof_dropped={} \
         control_dropped={} bytes={} line_errors={} overruns={} stale={} woken={}\n",
        line.lines,
        line.eofs,
        line.deferred,
        line.edit_overflow,
        line.dropped_while_deferred,
        line.eof_dropped,
        line.control_dropped,
        uart.bytes,
        uart.line_errors,
        uart.overruns,
        uart.stale,
        stats.woken
    ));
    kernel_log_fmt(format_args!(
        "[TTY ] irq irqs={} spurious={} rearms={} max_drained={} wakes={} notified={}\n",
        uart.irqs,
        uart.spurious,
        uart.rearms,
        uart.max_drained,
        stats.wakes,
        NOTIFICATIONS.load(Ordering::Relaxed)
    ));
    kernel_log_fmt(format_args!("[TTY ] done\n"));
    // QEMU may reset the socket when it exits, and a reset discards whatever the host has not
    // read yet. The host acknowledges `done` with one byte the discipline drops unechoed.
    while serial_console::stats().uart.bytes == uart.bytes {
        enable_interrupts_and_halt();
        disable_interrupts();
    }
    qemu_exit(QEMU_EXIT_SUCCESS)
}
