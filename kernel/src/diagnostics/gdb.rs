#[cfg(feature = "gdb-entry")]
use core::arch::asm;

#[cfg(feature = "gdb-entry")]
pub(crate) fn gdb_entry_handoff() {
    unsafe {
        asm!("int3", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(not(feature = "gdb-entry"))]
pub(crate) fn gdb_entry_handoff() {}
