#![cfg_attr(
    not(any(feature = "m2-timer-self-test", feature = "m4-recovery-self-test")),
    allow(dead_code)
)]

//! Local APIC timer/EOI programming and legacy PIC masking.
//!
//! Why unsafe: MMIO writes to the APIC register page and MSR writes to
//! IA32_APIC_BASE. Callers must have the APIC page identity-mapped (true under
//! the UEFI-provided page tables) and must only acknowledge interrupts that
//! were actually delivered to this CPU. No link contracts.

use core::ptr;

use crate::arch::x86_64::msr::{read_msr, write_msr};
use crate::arch::x86_64::port::port_out;
use crate::arch::x86_64::{SPURIOUS_VECTOR, TIMER_VECTOR};

const APIC_BASE_MSR: u32 = 0x1b;

const APIC_BASE_ADDRESS_MASK: u64 = 0xffff_f000;
const APIC_ENABLE: u64 = 1 << 11;
const APIC_SPURIOUS_INTERRUPT_VECTOR: u32 = 0x100 | (SPURIOUS_VECTOR as u32);
const APIC_REGISTER_TPR: usize = 0x80;
const APIC_REGISTER_EOI: usize = 0xb0;
const APIC_REGISTER_SVR: usize = 0xf0;
const APIC_REGISTER_LVT_TIMER: usize = 0x320;
const APIC_REGISTER_INITIAL_COUNT: usize = 0x380;
const APIC_REGISTER_DIVIDE_CONFIGURATION: usize = 0x3e0;
const APIC_TIMER_PERIODIC: u32 = 1 << 17;
const APIC_TIMER_DIVIDE_BY_16: u32 = 0x03;
pub(crate) const APIC_TIMER_INITIAL_COUNT: u32 = 10_000_000;

const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_DATA: u16 = 0xa1;

pub(crate) fn mask_legacy_pic() {
    port_out(PIC_MASTER_DATA, 0xff);
    port_out(PIC_SLAVE_DATA, 0xff);
}

pub(crate) fn enable_local_apic() {
    let apic_base = read_msr(APIC_BASE_MSR) | APIC_ENABLE;
    write_msr(APIC_BASE_MSR, apic_base);
    local_apic_write(APIC_REGISTER_TPR, 0);
    local_apic_write(APIC_REGISTER_SVR, APIC_SPURIOUS_INTERRUPT_VECTOR);
}

pub(crate) fn program_local_apic_timer() {
    local_apic_write(APIC_REGISTER_DIVIDE_CONFIGURATION, APIC_TIMER_DIVIDE_BY_16);
    local_apic_write(
        APIC_REGISTER_LVT_TIMER,
        APIC_TIMER_PERIODIC | (TIMER_VECTOR as u32),
    );
    local_apic_write(APIC_REGISTER_INITIAL_COUNT, APIC_TIMER_INITIAL_COUNT);
}

pub(crate) fn acknowledge_timer_interrupt() {
    local_apic_write(APIC_REGISTER_EOI, 0);
}

fn local_apic_write(offset: usize, value: u32) {
    let register = (local_apic_base() + offset as u64) as *mut u32;
    unsafe {
        ptr::write_volatile(register, value);
        ptr::read_volatile(register);
    }
}

fn local_apic_base() -> u64 {
    read_msr(APIC_BASE_MSR) & APIC_BASE_ADDRESS_MASK
}
