//! Milestone 2 double-fault self-test: deliberately faults on an unmapped
//! address twice so the dedicated IST stack and the nested-fault path in
//! `interrupt::handle_exception` can be exercised end to end.

#[cfg(feature = "m2-double-fault-self-test")]
use crate::arch::x86_64::gdt::DOUBLE_FAULT_STACK;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::diagnostics::qemu::QEMU_EXIT_FAILURE;
#[cfg(feature = "m2-double-fault-self-test")]
use core::ptr;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use core::sync::atomic::AtomicBool;
#[cfg(feature = "m2-double-fault-self-test")]
use core::sync::atomic::Ordering;

#[cfg(feature = "m2-double-fault-self-test")]
#[cfg(feature = "m2-double-fault-self-test")]
use crate::mm::layout::KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE;

#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_PRIMARY_ADDRESS: u64 = KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE;
#[cfg(feature = "m2-double-fault-self-test")]
pub(crate) const DOUBLE_FAULT_TEST_SECONDARY_ADDRESS: u64 =
    KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE + 0x1000;

#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
pub(crate) static DOUBLE_FAULT_TEST_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "m2-double-fault-self-test")]
pub(crate) fn trigger_double_fault_self_test() -> ! {
    DOUBLE_FAULT_TEST_ACTIVE.store(true, Ordering::Relaxed);
    unsafe { ptr::read_volatile(DOUBLE_FAULT_TEST_PRIMARY_ADDRESS as *const u64) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
pub(crate) fn trigger_nested_double_fault() -> ! {
    unsafe {
        ptr::read_volatile(DOUBLE_FAULT_TEST_SECONDARY_ADDRESS as *const u64);
    }
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
pub(crate) fn double_fault_stack_contains(address: u64) -> bool {
    let stack = unsafe { &*DOUBLE_FAULT_STACK.get() };
    let start = stack.0.as_ptr() as u64;
    let end = start + stack.0.len() as u64;
    address >= start && address < end
}
