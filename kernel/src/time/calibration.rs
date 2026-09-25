//! APIC and TSC calibration against PIT channel 2 (#163 / #103), IF masked throughout.

#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]

use crate::arch::x86_64::apic::{
    local_apic_timer_current_count, prepare_local_apic_timer_for_calibration,
    program_local_apic_timer,
};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::time::{
    set_apic_counter_hz, set_apic_timer_initial_count, set_tsc_hz, set_tsc_origin,
    APIC_TIMER_FALLBACK_INITIAL_COUNT, QEMU_APIC_COUNTER_HZ_FALLBACK,
};
use core::arch::asm;
use core::arch::x86_64::__cpuid;

const PIT_HZ: u64 = 1_193_182;
const CALIBRATION_MS: u64 = 50;
const PIT_POLL_MAX: u32 = 50_000_000;
const APIC_COUNTER_HZ_MIN: u64 = 10_000_000;
const APIC_COUNTER_HZ_MAX: u64 = 500_000_000;
const TSC_HZ_MIN: u64 = 500_000_000;
const TSC_HZ_MAX: u64 = 10_000_000_000;

pub(crate) fn read_tsc() -> u64 {
    unsafe { core::arch::x86_64::_rdtsc() }
}

fn log_tsc_cpuid() {
    let leaf0 = unsafe { __cpuid(0) };
    let max_leaf = leaf0.eax;
    let leaf1 = unsafe { __cpuid(1) };
    let tsc_present = (leaf1.edx & (1 << 4)) != 0;
    let mut invariant = false;
    if max_leaf >= 0x8000_0007 {
        let leaf7 = unsafe { __cpuid(0x8000_0007) };
        invariant = (leaf7.edx & (1 << 8)) != 0;
    }
    kernel_log_fmt(format_args!(
        "[TIME] tsc cpuid present={} invariant={}\n",
        tsc_present, invariant
    ));
    if !tsc_present {
        kernel_log_fmt(format_args!("[FAIL] tsc not reported by cpuid\n"));
        fatal_kernel_error("tsc calibration: CPUID reports no TSC");
    }
}

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

fn pit_enable_gate() {
    unsafe {
        let mut gate: u8;
        asm!("in al, dx", in("dx") 0x61u16, out("al") gate, options(nomem, nostack));
        gate = (gate | 0x01) & !0x02;
        asm!("out dx, al", in("dx") 0x61u16, in("al") gate, options(nomem, nostack));
    }
}

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

fn apply_tsc_config(tsc_hz: u64, origin: u64) {
    if !(TSC_HZ_MIN..=TSC_HZ_MAX).contains(&tsc_hz) {
        kernel_log_fmt(format_args!(
            "[FAIL] tsc calibration implausible hz={}\n",
            tsc_hz
        ));
        fatal_kernel_error("tsc calibration implausible frequency");
    }
    set_tsc_hz(tsc_hz);
    set_tsc_origin(origin);
    kernel_log_fmt(format_args!("[TIME] tsc hz={} origin={}\n", tsc_hz, origin));
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

/// Measure APIC down-counter and TSC rates (Hz) using PIT channel 2 as reference.
pub(crate) fn calibrate_apic_tick() {
    without_interrupts(|| {
        log_tsc_cpuid();
        prepare_local_apic_timer_for_calibration();
        pit_program_channel2();
        let target_pit_delta = (PIT_HZ * CALIBRATION_MS) / 1000;
        let start_pit = pit_read_count();
        let start_apic = local_apic_timer_current_count();
        let start_tsc = read_tsc();
        let mut polls = 0u32;
        loop {
            polls = polls.saturating_add(1);
            if polls > PIT_POLL_MAX {
                kernel_log_fmt(format_args!("[FAIL] apic calibration pit-timeout\n"));
                fatal_kernel_error("apic/tsc calibration pit timeout");
            }
            let elapsed = pit_elapsed_ticks(start_pit, pit_read_count());
            if elapsed >= target_pit_delta {
                break;
            }
        }
        let pit_delta = pit_elapsed_ticks(start_pit, pit_read_count());
        let end_apic = local_apic_timer_current_count();
        let end_tsc = read_tsc();
        let apic_delta = u64::from(start_apic.wrapping_sub(end_apic));
        if apic_delta == 0 || pit_delta == 0 {
            kernel_log_fmt(format_args!("[FAIL] apic/tsc calibration zero-delta\n"));
            fatal_kernel_error("apic/tsc calibration zero delta");
        }
        let counter_hz = match apic_delta
            .checked_mul(1000)
            .and_then(|n| n.checked_div(CALIBRATION_MS))
        {
            Some(value) if value > 0 => value,
            _ => {
                kernel_log_fmt(format_args!("[FAIL] apic calibration overflow\n"));
                fatal_kernel_error("apic calibration overflow");
            }
        };
        let tsc_delta = end_tsc.wrapping_sub(start_tsc);
        if tsc_delta == 0 {
            kernel_log_fmt(format_args!("[FAIL] tsc calibration zero-delta\n"));
            fatal_kernel_error("tsc calibration zero delta");
        }
        let Some(tsc_hz) = tsc_delta
            .checked_mul(PIT_HZ)
            .and_then(|n| n.checked_div(pit_delta))
            .filter(|&hz| hz > 0)
        else {
            kernel_log_fmt(format_args!("[FAIL] tsc calibration overflow\n"));
            fatal_kernel_error("tsc calibration overflow");
        };
        apply_apic_timer_config(counter_hz);
        apply_tsc_config(tsc_hz, end_tsc);
        program_local_apic_timer();
    });
}
