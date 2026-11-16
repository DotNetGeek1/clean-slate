//! Local APIC timer/EOI programming and legacy PIC masking.
//!
//! The register page is reached only through the uncached alias that
//! `mm::identity_holes::arm_identity_holes` maps at the page's direct-map
//! address, in the PML4 slot every root shares. The identity window around the
//! APIC is unmapped (#253), so a register access before the alias is installed
//! is a kernel bug and stops the boot rather than falling back to the identity
//! address.
//!
//! Why unsafe: MMIO writes to the APIC register page and MSR writes to
//! IA32_APIC_BASE. Callers must only acknowledge interrupts that were actually
//! delivered to this CPU. No link contracts.

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::msr::{read_msr, write_msr};
use crate::arch::x86_64::port::port_out;
use crate::arch::x86_64::{SPURIOUS_VECTOR, TIMER_VECTOR};
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::time::apic_timer_initial_count;

const APIC_BASE_MSR: u32 = 0x1b;

const APIC_BASE_ADDRESS_MASK: u64 = 0xffff_f000;
const APIC_ENABLE: u64 = 1 << 11;
const APIC_SPURIOUS_INTERRUPT_VECTOR: u32 = 0x100 | (SPURIOUS_VECTOR as u32);
const APIC_REGISTER_ID: usize = 0x20;
#[cfg(not(test))]
const APIC_REGISTER_VERSION: usize = 0x30;
/// Integrated (xAPIC) local APICs report a version in `0x10..=0x1f`; a missing
/// or disabled register page reads as all ones.
#[cfg(not(test))]
const APIC_INTEGRATED_VERSIONS: core::ops::RangeInclusive<u32> = 0x10..=0x1f;
const APIC_REGISTER_TPR: usize = 0x80;
const APIC_REGISTER_EOI: usize = 0xb0;
const APIC_REGISTER_SVR: usize = 0xf0;
#[cfg(feature = "m10-port-self-test")]
const APIC_REGISTER_ICR_LOW: usize = 0x300;
#[cfg(feature = "m10-port-self-test")]
const APIC_ICR_LEVEL_ASSERT: u32 = 1 << 14;
#[cfg(feature = "m10-port-self-test")]
const APIC_ICR_SHORTHAND_SELF: u32 = 1 << 18;
const APIC_REGISTER_LVT_TIMER: usize = 0x320;
const APIC_REGISTER_INITIAL_COUNT: usize = 0x380;
#[cfg_attr(
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
const APIC_REGISTER_CURRENT_COUNT: usize = 0x390;
const APIC_REGISTER_DIVIDE_CONFIGURATION: usize = 0x3e0;
const APIC_TIMER_PERIODIC: u32 = 1 << 17;
const APIC_TIMER_DIVIDE_BY_16: u32 = 0x03;

const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_DATA: u16 = 0xa1;

pub(crate) fn mask_legacy_pic() {
    port_out(PIC_MASTER_DATA, 0xff);
    port_out(PIC_SLAVE_DATA, 0xff);
}

pub(crate) fn enable_local_apic() {
    if local_apic_physical_base() != LOCAL_APIC_PHYS.load(Ordering::Relaxed) {
        fatal_kernel_error("IA32_APIC_BASE moved away from the aliased local APIC page");
    }
    let apic_base = read_msr(APIC_BASE_MSR) | APIC_ENABLE;
    write_msr(APIC_BASE_MSR, apic_base);
    local_apic_write(APIC_REGISTER_TPR, 0);
    local_apic_write(APIC_REGISTER_SVR, APIC_SPURIOUS_INTERRUPT_VECTOR);
}

fn write_apic_timer_lvt_and_divide() {
    local_apic_write(APIC_REGISTER_DIVIDE_CONFIGURATION, APIC_TIMER_DIVIDE_BY_16);
    local_apic_write(
        APIC_REGISTER_LVT_TIMER,
        APIC_TIMER_PERIODIC | (TIMER_VECTOR as u32),
    );
}

/// Arm periodic mode with maximum count so calibration can observe the down-counter.
#[cfg_attr(
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
pub(crate) fn prepare_local_apic_timer_for_calibration() {
    write_apic_timer_lvt_and_divide();
    local_apic_write(APIC_REGISTER_INITIAL_COUNT, u32::MAX);
}

/// Stops and masks the local APIC timer, for boot-context code that takes device interrupts
/// with no timer handler behind them.
#[cfg(feature = "serial-input-self-test")]
pub(crate) fn mask_local_apic_timer() {
    const APIC_LVT_MASKED: u32 = 1 << 16;
    local_apic_write(APIC_REGISTER_INITIAL_COUNT, 0);
    local_apic_write(
        APIC_REGISTER_LVT_TIMER,
        APIC_LVT_MASKED | (TIMER_VECTOR as u32),
    );
}

pub(crate) fn program_local_apic_timer() {
    write_apic_timer_lvt_and_divide();
    local_apic_write(APIC_REGISTER_INITIAL_COUNT, apic_timer_initial_count());
}

#[allow(dead_code)] // retained for diagnostics; self-tests no longer reprogram manually (#163).
pub(crate) fn reprogram_local_apic_timer(initial_count: u32) {
    local_apic_write(APIC_REGISTER_INITIAL_COUNT, initial_count);
}

pub(crate) fn acknowledge_timer_interrupt() {
    acknowledge_interrupt();
}

/// End-of-interrupt for the in-service vector; for level-triggered I/O APIC
/// sources the EOI broadcast also clears the redirection entry's remote IRR.
pub(crate) fn acknowledge_interrupt() {
    local_apic_write(APIC_REGISTER_EOI, 0);
}

/// Fixed, edge-triggered IPI to this CPU. With interrupts masked it stays pending in the IRR
/// until the next `sti` or `iretq` to an interrupts-enabled context.
#[cfg(feature = "m10-port-self-test")]
pub(crate) fn send_self_ipi(vector: u8) {
    local_apic_write(
        APIC_REGISTER_ICR_LOW,
        APIC_ICR_SHORTHAND_SELF | APIC_ICR_LEVEL_ASSERT | u32::from(vector),
    );
}

/// This CPU's local APIC ID: the physical destination for MSI and I/O APIC routes.
pub(crate) fn local_apic_id() -> u8 {
    (local_apic_read(APIC_REGISTER_ID) >> 24) as u8
}

/// Current APIC timer count (down-counter); for calibration with interrupts masked.
#[cfg_attr(
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
pub(crate) fn local_apic_timer_current_count() -> u32 {
    local_apic_read(APIC_REGISTER_CURRENT_COUNT)
}

#[cfg_attr(
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
fn local_apic_read(offset: usize) -> u32 {
    let register = (local_apic_base() + offset as u64) as *const u32;
    unsafe { ptr::read_volatile(register) }
}

fn local_apic_write(offset: usize, value: u32) {
    let register = (local_apic_base() + offset as u64) as *mut u32;
    unsafe {
        ptr::write_volatile(register, value);
        ptr::read_volatile(register);
    }
}

/// Virtual address of the register page alias; zero until it is installed.
static LOCAL_APIC_ALIAS: AtomicU64 = AtomicU64::new(0);
/// Physical page the alias maps.
static LOCAL_APIC_PHYS: AtomicU64 = AtomicU64::new(0);

/// The register page IA32_APIC_BASE points at, for mapping the alias at boot.
pub(crate) fn local_apic_physical_base() -> u64 {
    read_msr(APIC_BASE_MSR) & APIC_BASE_ADDRESS_MASK
}

/// Points every register access at `alias`, which maps `phys` uncached, after
/// checking that a local APIC answers there.
#[cfg(not(test))]
pub(crate) fn install_local_apic_alias(phys: u64, alias: u64) -> Result<(), &'static str> {
    if phys == 0 || phys != local_apic_physical_base() {
        return Err("local APIC alias does not map the IA32_APIC_BASE page");
    }
    let version =
        unsafe { ptr::read_volatile((alias + APIC_REGISTER_VERSION as u64) as *const u32) };
    if !APIC_INTEGRATED_VERSIONS.contains(&(version & 0xff)) {
        return Err("local APIC alias did not read an integrated APIC version");
    }
    LOCAL_APIC_PHYS.store(phys, Ordering::Relaxed);
    LOCAL_APIC_ALIAS.store(alias, Ordering::Relaxed);
    Ok(())
}

fn local_apic_base() -> u64 {
    match LOCAL_APIC_ALIAS.load(Ordering::Relaxed) {
        0 => fatal_kernel_error("local APIC accessed before its alias was mapped"),
        alias => alias,
    }
}
