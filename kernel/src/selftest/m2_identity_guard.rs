//! #253 identity-guard self-test: once paging is initialized, boot context makes one deliberate
//! 32-bit store to the local APIC's identity address and one to the null page. Each must take the
//! production page-fault report (`interrupt::report_identity_hole_fault`), whose
//! `[FAIL] kernel page fault in identity hole=<hole> cr2=<address>` line the lane requires.
//!
//! The APIC report's hook makes the null store from inside that #PF handler: a #PF raised while a
//! #PF handler runs is delivered normally, not as a double fault. The null report's hook exits
//! QEMU with success. If a store does not fault, the hole is missing and the probe reports
//! `[FAIL] identity guard absent`, which no lane expects.
//!
//! The stores go through inline assembly because Rust treats a store through a null pointer as
//! undefined behavior. Each stores 0: with the guard missing, QEMU takes the APIC store as an MSI
//! for vector 0 with interrupts masked, and the null store lands in the unused real-mode IVT.

use crate::arch::x86_64::apic::{local_apic_id, local_apic_physical_base};
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_FAILURE, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::{serial_write_fmt, serial_write_line};
use crate::mm::identity_holes::IdentityHole;
use core::sync::atomic::{AtomicU8, Ordering};

const STAGE_IDLE: u8 = 0;
const STAGE_LOCAL_APIC_STORE: u8 = 1;
const STAGE_NULL_STORE: u8 = 2;

static STAGE: AtomicU8 = AtomicU8::new(STAGE_IDLE);

/// Runs the APIC probe, whose fault hook runs the null probe. Never returns.
pub(crate) fn run_identity_guard_self_test() -> ! {
    serial_write_fmt(format_args!(
        "[IDG ] local APIC reached through its alias id={}\n",
        local_apic_id()
    ));
    store_and_expect_fault(
        STAGE_LOCAL_APIC_STORE,
        IdentityHole::LocalApicWindow,
        local_apic_physical_base(),
    )
}

fn store_and_expect_fault(stage: u8, hole: IdentityHole, address: u64) -> ! {
    STAGE.store(stage, Ordering::SeqCst);
    serial_write_fmt(format_args!(
        "[IDG ] probe store hole={} addr={address:#018x}\n",
        hole.label()
    ));
    unsafe {
        core::arch::asm!(
            "mov dword ptr [{address}], {value:e}",
            address = in(reg) address,
            value = in(reg) 0u32,
            options(nostack, preserves_flags)
        );
    }
    STAGE.store(STAGE_IDLE, Ordering::SeqCst);
    serial_write_fmt(format_args!(
        "[FAIL] identity guard absent: store to hole={} addr={address:#018x} did not fault\n",
        hole.label()
    ));
    qemu_exit(QEMU_EXIT_FAILURE)
}

/// Called from the production identity-hole report; exits QEMU or starts the next probe.
pub(crate) fn on_identity_hole_fault(hole: IdentityHole, fault_address: u64, write: bool) -> ! {
    let stage = STAGE.load(Ordering::SeqCst);
    match (stage, hole) {
        (STAGE_LOCAL_APIC_STORE, IdentityHole::LocalApicWindow)
            if write && fault_address == local_apic_physical_base() =>
        {
            serial_write_line("[IDG ] local-apic-window store faulted");
            store_and_expect_fault(STAGE_NULL_STORE, IdentityHole::NullPage, 0)
        }
        (STAGE_NULL_STORE, IdentityHole::NullPage) if write && fault_address == 0 => {
            serial_write_line("[IDG ] null-page store faulted");
            serial_write_line("[IDG ] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        _ => {
            serial_write_fmt(format_args!(
                "[IDG ] fault did not match the probe stage={stage} hole={} cr2={fault_address:#018x} write={write}\n",
                hole.label()
            ));
            qemu_exit(QEMU_EXIT_FAILURE)
        }
    }
}
