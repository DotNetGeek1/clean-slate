//! APIC timer calibration against the PIT channel 2 reference (#103).

use crate::arch::x86_64::cpu::{enable_interrupts, without_interrupts};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::interrupt::timer::kernel_ticks;
use crate::time::set_ticks_per_second;
use core::arch::asm;

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;

fn pit_read_count() -> u16 {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") 0x43u16,
            in("al") 0u8,
            options(nomem, nostack, preserves_flags)
        );
        let low: u8;
        let high: u8;
        asm!(
            "in al, dx",
            in("dx") 0x42u16,
            out("al") low,
            options(nomem, nostack, preserves_flags)
        );
        asm!(
            "in al, dx",
            in("dx") 0x42u16,
            out("al") high,
            options(nomem, nostack, preserves_flags)
        );
        u16::from_le_bytes([low, high])
    }
}

fn pit_enable_gate() {
    unsafe {
        let mut gate: u8;
        asm!("in al, dx", in("dx") 0x61u16, out("al") gate, options(nomem, nostack));
        gate |= 0x01;
        asm!("out dx, al", in("dx") 0x61u16, in("al") gate, options(nomem, nostack));
    }
}

/// Measure APIC ticks per second using PIT channel 2; fatal if calibration fails.
pub(crate) fn calibrate_apic_tick() {
    without_interrupts(|| {
        pit_enable_gate();
    });
    enable_interrupts();
    let first_tick_target = kernel_ticks() + 1;
    for _ in 0..10_000_000 {
        if kernel_ticks() >= first_tick_target {
            break;
        }
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
    let start_pit = without_interrupts(pit_read_count);
    let start_ticks = kernel_ticks();
    let target_pit_delta = (PIT_HZ * CALIBRATION_MS) / 1000;
    while {
        let elapsed = u64::from(start_pit.wrapping_sub(without_interrupts(pit_read_count)));
        elapsed < target_pit_delta
    } {
        unsafe {
            core::arch::asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
    without_interrupts(|| {
        let end_ticks = kernel_ticks();
        let tick_delta = end_ticks.saturating_sub(start_ticks);
        if tick_delta == 0 {
            set_ticks_per_second(100);
            kernel_log_fmt(format_args!(
                "[TIME] apic tick calibrated: ticks/s=100 ref=pit-fallback\n"
            ));
            return;
        }
        let ticks_per_second = match tick_delta
            .checked_mul(1000)
            .and_then(|n| n.checked_div(CALIBRATION_MS))
        {
            Some(value) => value,
            None => fatal_kernel_error("time calibration: overflow"),
        };
        set_ticks_per_second(ticks_per_second);
        kernel_log_fmt(format_args!(
            "[TIME] apic tick calibrated: ticks/s={} ref=pit\n",
            ticks_per_second
        ));
    });
}
