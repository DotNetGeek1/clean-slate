//! APIC timer calibration against PIT channel 2 (#103), interrupts masked throughout.

#![cfg_attr(not(feature = "m9-linux-runtime-self-test"), allow(dead_code))]

use crate::arch::x86_64::apic::local_apic_timer_current_count;
use crate::arch::x86_64::apic::APIC_TIMER_INITIAL_COUNT;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
#[cfg(feature = "m9-linux-runtime-self-test")]
use crate::diagnostics::qemu::fatal_kernel_error;
#[cfg(feature = "m9-linux-runtime-self-test")]
use crate::interrupt::timer::kernel_ticks;
use crate::time::set_apic_counter_hz;
use core::arch::asm;
const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
const PIT_POLL_MAX: u32 = 50_000_000;

pub(crate) fn pit_read_count() -> u16 {
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

fn log_apic_time(counter_hz: u64) {
    let ic = u64::from(APIC_TIMER_INITIAL_COUNT);
    let irq_tick_ms = (1000u128 * ic as u128).div_ceil(counter_hz as u128);
    kernel_log_fmt(format_args!(
        "[TIME] apic counter_hz={} initial_count={} irq_tick_ms={}\n",
        counter_hz, ic, irq_tick_ms
    ));
}

/// Measure APIC down-counter rate (Hz) using PIT channel 2 as reference.
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
                let fallback = 100u64 * u64::from(APIC_TIMER_INITIAL_COUNT);
                set_apic_counter_hz(fallback);
                log_apic_time(fallback);
                kernel_log_fmt(format_args!("[TIME] apic calibration pit-fallback\n"));
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
            let fallback = 100u64 * u64::from(APIC_TIMER_INITIAL_COUNT);
            set_apic_counter_hz(fallback);
            log_apic_time(fallback);
            kernel_log_fmt(format_args!("[TIME] apic calibration pit-fallback\n"));
            return;
        }
        let counter_hz = match apic_delta
            .checked_mul(1000)
            .and_then(|n| n.checked_div(CALIBRATION_MS))
        {
            Some(value) if value > 0 => value,
            _ => {
                let fallback = 100u64 * u64::from(APIC_TIMER_INITIAL_COUNT);
                set_apic_counter_hz(fallback);
                log_apic_time(fallback);
                kernel_log_fmt(format_args!("[TIME] apic calibration pit-fallback\n"));
                return;
            }
        };
        set_apic_counter_hz(counter_hz);
        log_apic_time(counter_hz);
    });
}

/// Compare IRQ ticks elapsed since `block_start_tick` to PIT (scheduler already running).
#[cfg(feature = "m9-linux-runtime-self-test")]
pub(crate) fn crosscheck_irq_ticks_for_elapsed(block_start_tick: u64, pit_at_block: u16) {
    let irq_elapsed = kernel_ticks().saturating_sub(block_start_tick);
    let pit_elapsed = pit_elapsed_ticks(pit_at_block, pit_read_count());
    let counter_hz = crate::time::apic_counter_hz().unwrap_or(0);
    let ic = u64::from(APIC_TIMER_INITIAL_COUNT);
    let expected_irq = if counter_hz == 0 {
        0
    } else {
        (pit_elapsed * counter_hz) / (PIT_HZ * ic)
    };
    kernel_log_fmt(format_args!(
        "[TIME] irq crosscheck irq_ticks={} pit_expect={} pit_raw={}\n",
        irq_elapsed, expected_irq, pit_elapsed
    ));
    let diff = irq_elapsed.abs_diff(expected_irq);
    if irq_elapsed == 0 || diff > 1 {
        fatal_kernel_error("irq tick crosscheck vs PIT failed");
    }
}
