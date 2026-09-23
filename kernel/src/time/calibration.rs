//! APIC timer calibration against PIT channel 2 (#163), interrupts masked throughout.

use crate::arch::x86_64::apic::{
    local_apic_timer_current_count, prepare_local_apic_timer_for_calibration,
    program_local_apic_timer,
};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::time::{
    set_apic_counter_hz, set_apic_timer_initial_count, APIC_TIMER_FALLBACK_INITIAL_COUNT,
    QEMU_APIC_COUNTER_HZ_FALLBACK,
};
use core::arch::asm;

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
const PIT_POLL_MAX: u32 = 50_000_000;
const APIC_COUNTER_HZ_MIN: u64 = 10_000_000;
const APIC_COUNTER_HZ_MAX: u64 = 500_000_000;

fn pit_write_control(value: u8) {
    unsafe {
        asm!(
            "out dx, al",
            in("dx") 0x43u16,
            in("al") value,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn pit_write_reload(value: u16) {
    let bytes = value.to_le_bytes();
    unsafe {
        asm!(
            "out dx, al",
            in("dx") 0x42u16,
            in("al") bytes[0],
            options(nomem, nostack, preserves_flags)
        );
        asm!(
            "out dx, al",
            in("dx") 0x42u16,
            in("al") bytes[1],
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Latch channel 2 count (control byte `0x80`), then read data port 0x42.
fn pit_read_count() -> u16 {
    unsafe {
        pit_write_control(0x80);
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

/// Enable PIT channel 2 gate (port 0x61 bit 0), speaker off (bit 1 clear).
fn pit_enable_gate() {
    unsafe {
        let mut gate: u8;
        asm!("in al, dx", in("dx") 0x61u16, out("al") gate, options(nomem, nostack));
        gate = (gate | 0x01) & !0x02;
        asm!("out dx, al", in("dx") 0x61u16, in("al") gate, options(nomem, nostack));
    }
}

/// Program channel 2: mode 2 rate generator, reload `0xFFFF` (down-count only).
fn pit_program_channel2() {
    pit_write_control(0xB4);
    pit_write_reload(0xFFFF);
    pit_enable_gate();
}

fn pit_elapsed_ticks(start: u16, now: u16) -> u64 {
    u64::from(start.wrapping_sub(now))
}

fn derive_initial_count(counter_hz: u64) -> u32 {
    let ic = counter_hz / 1000;
    u32::try_from(ic.max(1)).unwrap_or(APIC_TIMER_FALLBACK_INITIAL_COUNT)
}

fn log_apic_time(counter_hz: u64, initial_count: u32) {
    let tick_ns = crate::time::irq_period_ns_from(counter_hz, initial_count).unwrap_or(0);
    kernel_log_fmt(format_args!(
        "[TIME] apic counter_hz={} initial_count={} tick_ns={}\n",
        counter_hz, initial_count, tick_ns
    ));
}

fn apply_apic_timer_config(counter_hz: u64) {
    let (hz, initial_count) = if (APIC_COUNTER_HZ_MIN..=APIC_COUNTER_HZ_MAX).contains(&counter_hz) {
        (counter_hz, derive_initial_count(counter_hz))
    } else {
        kernel_log_fmt(format_args!(
            "[TIME] apic calibration implausible measured={} fallback={}\n",
            counter_hz, QEMU_APIC_COUNTER_HZ_FALLBACK
        ));
        (
            QEMU_APIC_COUNTER_HZ_FALLBACK,
            APIC_TIMER_FALLBACK_INITIAL_COUNT,
        )
    };
    set_apic_counter_hz(hz);
    set_apic_timer_initial_count(initial_count);
    log_apic_time(hz, initial_count);
}

/// Apply the QEMU fallback rate and ~1 ms reload without PIT measurement.
#[cfg_attr(
    not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    )),
    allow(dead_code)
)]
pub(crate) fn apply_fallback_apic_timer_config() {
    apply_apic_timer_config(QEMU_APIC_COUNTER_HZ_FALLBACK);
}

/// Measure APIC down-counter rate (Hz) using PIT channel 2 as reference.
pub(crate) fn calibrate_apic_tick() {
    without_interrupts(|| {
        prepare_local_apic_timer_for_calibration();
        pit_program_channel2();
        let target_pit_delta = (PIT_HZ * CALIBRATION_MS) / 1000;
        let start_pit = pit_read_count();
        let start_apic = local_apic_timer_current_count();
        let mut polls = 0u32;
        loop {
            polls = polls.saturating_add(1);
            if polls > PIT_POLL_MAX {
                kernel_log_fmt(format_args!("[TIME] apic calibration pit-timeout\n"));
                apply_apic_timer_config(QEMU_APIC_COUNTER_HZ_FALLBACK);
                program_local_apic_timer();
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
            kernel_log_fmt(format_args!("[TIME] apic calibration zero-delta\n"));
            apply_apic_timer_config(QEMU_APIC_COUNTER_HZ_FALLBACK);
            program_local_apic_timer();
            return;
        }
        let counter_hz = match apic_delta
            .checked_mul(1000)
            .and_then(|n| n.checked_div(CALIBRATION_MS))
        {
            Some(value) if value > 0 => value,
            _ => {
                apply_apic_timer_config(QEMU_APIC_COUNTER_HZ_FALLBACK);
                program_local_apic_timer();
                return;
            }
        };
        apply_apic_timer_config(counter_hz);
        program_local_apic_timer();
    });
}
