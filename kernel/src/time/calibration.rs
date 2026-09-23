//! APIC timer calibration against PIT channel 2 (#103), interrupts masked throughout.

use crate::arch::x86_64::apic::local_apic_timer_current_count;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::time::set_ticks_per_second;
use core::arch::asm;

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
const PIT_POLL_MAX: u32 = 50_000_000;

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

fn pit_elapsed_ticks(start: u16, now: u16) -> u64 {
    u64::from(start.wrapping_sub(now))
}

/// Measure APIC down-counter ticks per second using PIT channel 2 as reference.
pub(crate) fn calibrate_apic_tick() {
    without_interrupts(|| {
        pit_enable_gate();
        let target_pit_delta = (PIT_HZ * CALIBRATION_MS) / 1000;
        let start_pit = pit_read_count();
        let start_apic = local_apic_timer_current_count();
        let mut polls = 0u32;
        loop {
            polls = polls.saturating_add(1);
            if polls > PIT_POLL_MAX {
                set_ticks_per_second(100);
                kernel_log_fmt(format_args!(
                    "[TIME] apic tick calibrated: ticks/s=100 ref=pit-fallback\n"
                ));
                return;
            }
            let elapsed = pit_elapsed_ticks(start_pit, pit_read_count());
            if elapsed >= target_pit_delta {
                break;
            }
        }
        let end_apic = local_apic_timer_current_count();
        let apic_delta = u64::from(start_apic.wrapping_sub(end_apic));
        if apic_delta == 0 {
            set_ticks_per_second(100);
            kernel_log_fmt(format_args!(
                "[TIME] apic tick calibrated: ticks/s=100 ref=pit-fallback\n"
            ));
            return;
        }
        let ticks_per_second = match apic_delta
            .checked_mul(1000)
            .and_then(|n| n.checked_div(CALIBRATION_MS))
        {
            Some(value) if value > 0 => value,
            _ => {
                set_ticks_per_second(100);
                kernel_log_fmt(format_args!(
                    "[TIME] apic tick calibrated: ticks/s=100 ref=pit-fallback\n"
                ));
                return;
            }
        };
        set_ticks_per_second(ticks_per_second);
        kernel_log_fmt(format_args!(
            "[TIME] apic tick calibrated: ticks/s={} ref=pit\n",
            ticks_per_second
        ));
    });
}
