//! Trusted bootstrap grant hand-off (`SYSCALL_NR_CAP_GRANT`).
//!
//! When the kernel (or a kernel-side self-test acting as launch policy) grants a
//! capability to a process it is about to run, the process has no channel yet to
//! receive the handle value. The kernel therefore parks `(holder, handle)` pairs in
//! a bounded table and the process claims them one at a time via
//! `SYSCALL_NR_CAP_GRANT` with `rdi = GRANT_SUBOP_CLAIM`.
//!
//! Claiming is bound to the trusted current process identity: a process can only
//! claim handles registered for its own PID, and the handle value itself is
//! useless to any other holder because the capability record is holder-bound.
//! Nothing here grants authority; it only publishes handles already installed by
//! `crate::capability::grant_root` (or delegation) for that holder.

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::sync::global_cell::GlobalCell;
use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC};
use clean_slate_capability::{CapabilityHandle, HolderId};

/// `rdi` sub-operation: return the next unclaimed handle registered for the
/// current holder, or `0` when none remain.
pub(crate) const GRANT_SUBOP_CLAIM: u64 = 1;

const PENDING_BOOTSTRAP_GRANTS: usize = 16;

#[derive(Clone, Copy)]
struct PendingGrant {
    holder: HolderId,
    handle: CapabilityHandle,
}

/// Bounded, host-testable table of handles awaiting claim by their holder.
pub(crate) struct BootstrapGrantTable {
    entries: [Option<PendingGrant>; PENDING_BOOTSTRAP_GRANTS],
}

impl BootstrapGrantTable {
    pub(crate) const fn new() -> Self {
        Self {
            entries: [None; PENDING_BOOTSTRAP_GRANTS],
        }
    }

    /// Parks `handle` for `holder`. Fails deterministically when the table is full.
    pub(crate) fn register(
        &mut self,
        holder: HolderId,
        handle: CapabilityHandle,
    ) -> Result<(), &'static str> {
        if holder == HolderId::KERNEL {
            return Err("bootstrap grants cannot target the kernel holder");
        }
        match self.entries.iter_mut().find(|entry| entry.is_none()) {
            Some(slot) => {
                *slot = Some(PendingGrant { holder, handle });
                Ok(())
            }
            None => Err("bootstrap grant table is full"),
        }
    }

    /// Removes and returns the oldest pending handle for `holder`, in registration order.
    pub(crate) fn claim(&mut self, holder: HolderId) -> Option<CapabilityHandle> {
        let slot = self
            .entries
            .iter_mut()
            .find(|entry| matches!(entry, Some(grant) if grant.holder == holder))?;
        slot.take().map(|grant| grant.handle)
    }

    /// Drops every pending grant for `holder` (used when the holder exits before claiming).
    pub(crate) fn discard_for_holder(&mut self, holder: HolderId) -> usize {
        let mut discarded = 0;
        for entry in &mut self.entries {
            if matches!(entry, Some(grant) if grant.holder == holder) {
                *entry = None;
                discarded += 1;
            }
        }
        discarded
    }
}

static BOOTSTRAP_GRANTS: GlobalCell<BootstrapGrantTable> =
    GlobalCell::new(BootstrapGrantTable::new());

/// Registers an already-installed capability handle for later claim by `holder`.
///
/// Callers must have installed the capability for the same holder first (for
/// example via `crate::capability::grant_root`); this function publishes, it does
/// not authorize.
#[allow(dead_code)] // Used by M6 self-tests and launch policy.
pub(crate) fn register_bootstrap_grant(
    holder: HolderId,
    handle: CapabilityHandle,
) -> Result<(), &'static str> {
    unsafe { &mut *BOOTSTRAP_GRANTS.get() }.register(holder, handle)
}

pub(crate) fn claim_bootstrap_grant(holder: HolderId) -> Option<CapabilityHandle> {
    unsafe { &mut *BOOTSTRAP_GRANTS.get() }.claim(holder)
}

/// Drops unclaimed grants for an exiting holder so a later PID cannot inherit them.
/// (PIDs are never reused, so this is defensive tidiness rather than a security boundary.)
pub(crate) fn discard_bootstrap_grants_for_holder(holder: HolderId) -> usize {
    unsafe { &mut *BOOTSTRAP_GRANTS.get() }.discard_for_holder(holder)
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    if frame.rdi != GRANT_SUBOP_CLAIM {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match super::current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let table = unsafe { &mut *BOOTSTRAP_GRANTS.get() };
    frame.rax = match table.claim(holder) {
        Some(handle) => handle.encode(),
        None => 0,
    };
}

/// Exposed so callers can map a full table into the documented syscall status.
#[allow(dead_code)]
pub(crate) const BOOTSTRAP_GRANT_FULL_STATUS: u64 = SYSCALL_ENOSPC;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_are_holder_bound_and_ordered() {
        let mut table = BootstrapGrantTable::new();
        let a = HolderId(10);
        let b = HolderId(11);
        table.register(a, CapabilityHandle::new(1, 1)).unwrap();
        table.register(b, CapabilityHandle::new(2, 1)).unwrap();
        table.register(a, CapabilityHandle::new(3, 1)).unwrap();

        assert_eq!(table.claim(b), Some(CapabilityHandle::new(2, 1)));
        assert_eq!(table.claim(b), None);
        assert_eq!(table.claim(a), Some(CapabilityHandle::new(1, 1)));
        assert_eq!(table.claim(a), Some(CapabilityHandle::new(3, 1)));
        assert_eq!(table.claim(a), None);
    }

    #[test]
    fn table_is_bounded_and_rejects_kernel_holder() {
        let mut table = BootstrapGrantTable::new();
        assert!(table
            .register(HolderId::KERNEL, CapabilityHandle::new(0, 1))
            .is_err());
        for slot in 0..PENDING_BOOTSTRAP_GRANTS {
            table
                .register(HolderId(1), CapabilityHandle::new(slot as u16, 1))
                .unwrap();
        }
        assert!(table
            .register(HolderId(1), CapabilityHandle::new(0, 2))
            .is_err());
        assert_eq!(
            table.discard_for_holder(HolderId(1)),
            PENDING_BOOTSTRAP_GRANTS
        );
        assert!(table
            .register(HolderId(1), CapabilityHandle::new(0, 2))
            .is_ok());
    }
}
