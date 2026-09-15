//! Interrupt descriptor table construction and loading.
//!
//! Why unsafe: `lidt` redirects every exception and interrupt to the entry
//! stubs declared in `asm.rs`; the IDT is a `static mut` written once during
//! boot before interrupts are enabled. Callers must call
//! `install_interrupt_handlers` exactly once, on the boot CPU, before enabling
//! interrupts or entering userspace. Link contract: every handler stored in
//! `INTERRUPT_HANDLERS` is a `clean_slate_interrupt_<n>` label from `asm.rs`.

use core::arch::asm;
use core::mem::size_of;

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
use crate::arch::x86_64::asm::clean_slate_interrupt_128;
use crate::arch::x86_64::asm::{
    clean_slate_interrupt_0, clean_slate_interrupt_1, clean_slate_interrupt_10,
    clean_slate_interrupt_11, clean_slate_interrupt_12, clean_slate_interrupt_13,
    clean_slate_interrupt_14, clean_slate_interrupt_15, clean_slate_interrupt_16,
    clean_slate_interrupt_17, clean_slate_interrupt_18, clean_slate_interrupt_19,
    clean_slate_interrupt_2, clean_slate_interrupt_20, clean_slate_interrupt_21,
    clean_slate_interrupt_22, clean_slate_interrupt_23, clean_slate_interrupt_24,
    clean_slate_interrupt_25, clean_slate_interrupt_26, clean_slate_interrupt_27,
    clean_slate_interrupt_28, clean_slate_interrupt_29, clean_slate_interrupt_3,
    clean_slate_interrupt_30, clean_slate_interrupt_31, clean_slate_interrupt_32,
    clean_slate_interrupt_33, clean_slate_interrupt_4, clean_slate_interrupt_5,
    clean_slate_interrupt_6, clean_slate_interrupt_7, clean_slate_interrupt_8,
    clean_slate_interrupt_9,
};
use crate::arch::x86_64::cpu::read_code_segment;
use crate::arch::x86_64::gdt::initialize_gdt_and_tss;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
use crate::arch::x86_64::USER_TEST_VECTOR;
use crate::arch::x86_64::{DOUBLE_FAULT_VECTOR, SPURIOUS_VECTOR};

pub(super) const DOUBLE_FAULT_IST_INDEX: u16 = 1;

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    options: u16,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        options: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn set_handler(&mut self, handler: unsafe extern "C" fn()) {
        self.set_handler_with_privilege(handler, 0, 0);
    }

    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m3-entry-self-test"
    ))]
    fn set_user_handler(&mut self, handler: unsafe extern "C" fn()) {
        self.set_handler_with_privilege(handler, 0, 3);
    }

    fn set_handler_with_ist(&mut self, handler: unsafe extern "C" fn(), ist_index: u16) {
        self.set_handler_with_privilege(handler, ist_index, 0);
    }

    fn set_handler_with_privilege(
        &mut self,
        handler: unsafe extern "C" fn(),
        ist_index: u16,
        privilege_level: u16,
    ) {
        let address = handler as usize as u64;
        self.offset_low = address as u16;
        self.selector = read_code_segment();
        self.options = 0x8e00 | ((privilege_level & 0x3) << 13) | (ist_index & 0x7);
        self.offset_middle = (address >> 16) as u16;
        self.offset_high = (address >> 32) as u32;
        self.reserved = 0;
    }
}

#[repr(C, align(16))]
struct InterruptDescriptorTable {
    entries: [IdtEntry; 256],
}

static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable {
    entries: [IdtEntry::MISSING; 256],
};

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

static INTERRUPT_HANDLERS: [unsafe extern "C" fn(); SPURIOUS_VECTOR + 1] = [
    clean_slate_interrupt_0,
    clean_slate_interrupt_1,
    clean_slate_interrupt_2,
    clean_slate_interrupt_3,
    clean_slate_interrupt_4,
    clean_slate_interrupt_5,
    clean_slate_interrupt_6,
    clean_slate_interrupt_7,
    clean_slate_interrupt_8,
    clean_slate_interrupt_9,
    clean_slate_interrupt_10,
    clean_slate_interrupt_11,
    clean_slate_interrupt_12,
    clean_slate_interrupt_13,
    clean_slate_interrupt_14,
    clean_slate_interrupt_15,
    clean_slate_interrupt_16,
    clean_slate_interrupt_17,
    clean_slate_interrupt_18,
    clean_slate_interrupt_19,
    clean_slate_interrupt_20,
    clean_slate_interrupt_21,
    clean_slate_interrupt_22,
    clean_slate_interrupt_23,
    clean_slate_interrupt_24,
    clean_slate_interrupt_25,
    clean_slate_interrupt_26,
    clean_slate_interrupt_27,
    clean_slate_interrupt_28,
    clean_slate_interrupt_29,
    clean_slate_interrupt_30,
    clean_slate_interrupt_31,
    clean_slate_interrupt_32,
    clean_slate_interrupt_33,
];

pub(crate) fn install_interrupt_handlers() {
    initialize_gdt_and_tss();
    unsafe {
        for (vector, handler) in INTERRUPT_HANDLERS.iter().enumerate() {
            IDT.entries[vector].set_handler(*handler);
        }
        IDT.entries[DOUBLE_FAULT_VECTOR]
            .set_handler_with_ist(clean_slate_interrupt_8, DOUBLE_FAULT_IST_INDEX);
        #[cfg(any(
            feature = "m3-address-space-self-test",
            feature = "m3-resources-self-test",
            feature = "m3-entry-self-test"
        ))]
        IDT.entries[USER_TEST_VECTOR].set_user_handler(clean_slate_interrupt_128);
        let pointer = DescriptorTablePointer {
            limit: (size_of::<InterruptDescriptorTable>() - 1) as u16,
            base: (&raw const IDT) as *const _ as u64,
        };
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
}

pub(crate) fn exception_name(vector: usize) -> &'static str {
    match vector {
        0 => "divide error",
        1 => "debug",
        2 => "nmi",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range exceeded",
        6 => "invalid opcode",
        7 => "device not available",
        8 => "double fault",
        9 => "coprocessor segment overrun",
        10 => "invalid tss",
        11 => "segment not present",
        12 => "stack segment fault",
        13 => "general protection fault",
        14 => "page fault",
        16 => "x87 floating point",
        17 => "alignment check",
        18 => "machine check",
        19 => "simd floating point",
        20 => "virtualization",
        21 => "control protection",
        28 => "hypervisor injection",
        29 => "vmm communication",
        30 => "security exception",
        32 => "timer interrupt",
        _ => "reserved",
    }
}
