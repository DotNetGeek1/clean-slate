//! M6.6 capability revocation syscall surface (SYSCALL_NR_CAP_REVOKE).

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use clean_slate_capability::syscall_abi::{
    CAP_REVOKE_OP_DROP, CAP_REVOKE_OP_PROBE, CAP_REVOKE_OP_REVOKE, SYSCALL_EINVAL,
};
use clean_slate_capability::{
    authorize_revoke, drop_own, revoke_subtree, CapabilityError, CapabilityHandle, DropRefusal,
    HolderId, ResourceClass, Rights,
};
use clean_slate_native_abi::STATUS_EAGAIN;

use super::{authorize_current_class, capability_space_mut, current_holder, with_capability_space};
use crate::mm::shared_buffer::{
    capability_backs_live_row, drain_pending_in_syscall, reconcile_resource,
};

pub(crate) const REVOKE_OP_REVOKE: u64 = CAP_REVOKE_OP_REVOKE;
pub(crate) const REVOKE_OP_PROBE: u64 = CAP_REVOKE_OP_PROBE;
pub(crate) const REVOKE_OP_DROP: u64 = CAP_REVOKE_OP_DROP;
/// M6.6 self-test only: returns 1 once both reader fixtures probed, else 0.
#[cfg(feature = "m6-revocation-self-test")]
pub(crate) const REVOKE_OP_WAIT_READERS: u64 = 3;
/// M6.6 self-test only: blocks a reader fixture until the owner finished its revocations.
#[cfg(feature = "m6-revocation-self-test")]
pub(crate) const REVOKE_OP_WAIT_OWNER: u64 = 4;

#[cfg(feature = "m6-revocation-self-test")]
const _: () =
    assert!(REVOKE_OP_DROP != REVOKE_OP_WAIT_READERS && REVOKE_OP_DROP != REVOKE_OP_WAIT_OWNER);

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    match frame.rdi {
        REVOKE_OP_REVOKE => handle_revoke(frame),
        REVOKE_OP_PROBE => handle_probe(frame),
        REVOKE_OP_DROP => handle_drop(frame),
        #[cfg(feature = "m6-revocation-self-test")]
        REVOKE_OP_WAIT_READERS => {
            crate::selftest::m6_revocation::handle_wait_for_readers(frame);
        }
        #[cfg(feature = "m6-revocation-self-test")]
        REVOKE_OP_WAIT_OWNER => {
            crate::selftest::m6_revocation::handle_wait_for_owner_finished(frame);
        }
        _ => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_revoke(frame: &mut SyscallContext) {
    let actor = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = CapabilityError::UnauthorizedHolder.syscall_status();
            return;
        }
    };
    let handle = match CapabilityHandle::decode(frame.rsi) {
        Ok(handle) => handle,
        Err(error) => {
            frame.rax = error.syscall_status();
            return;
        }
    };
    let auth = with_capability_space(|table| authorize_revoke(table, actor, handle));
    if let Err(error) = auth {
        kernel_log_fmt(format_args!(
            "[CAP ] revoke denied actor={} reason={}\n",
            actor.0,
            error.error_name(),
        ));
        frame.rax = error.syscall_status();
        return;
    }
    let resource =
        with_capability_space(|table| table.record(handle)).map(|record| record.resource);
    let result = revoke_subtree(unsafe { capability_space_mut() }, handle);
    if let Ok(resource) = resource {
        reconcile_resource(resource);
        drain_pending_in_syscall();
    }
    match result {
        Ok(count) => {
            kernel_log_fmt(format_args!(
                "[CAP ] revoke branch={}:{} actor={} count={}\n",
                handle.slot, handle.generation, actor.0, count,
            ));
            frame.rax = count as u64;
        }
        Err(error) => {
            frame.rax = error.syscall_status();
        }
    }
}

fn handle_drop(frame: &mut SyscallContext) {
    let actor = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = CapabilityError::UnauthorizedHolder.syscall_status();
            return;
        }
    };
    frame.rax = match drop_for(actor, frame.rsi) {
        Ok(()) => 0,
        Err(status) => status,
    };
}

/// `REVOKE_OP_DROP`: `actor` gives up its own capability `raw_handle`.
///
/// Statuses: `EINVAL` (malformed or never-issued handle), `ESTALE` (already dropped or
/// released), `EACCES` (`actor` is not the holder, ancestors included), `EAGAIN` (a live child
/// was delegated from it, or it is the authority of a live shared-window row of `actor`; `UNMAP`
/// first). Holder checks run before the busy checks, so a non-holder learns nothing about
/// another holder's mappings or delegations.
pub(crate) fn drop_for(actor: HolderId, raw_handle: u64) -> Result<(), u64> {
    let handle = CapabilityHandle::decode(raw_handle).map_err(|error| error.syscall_status())?;
    let record = with_capability_space(|table| table.record(handle))
        .map_err(|error| error.syscall_status())?;
    if record.holder != actor {
        return Err(CapabilityError::UnauthorizedHolder.syscall_status());
    }
    if record.resource.class == ResourceClass::SharedBuffer
        && capability_backs_live_row(actor.0, handle)
    {
        return Err(STATUS_EAGAIN);
    }
    let resource = drop_own(unsafe { capability_space_mut() }, actor, handle).map_err(
        |refusal| match refusal {
            DropRefusal::Capability(error) => error.syscall_status(),
            DropRefusal::Delegated => STATUS_EAGAIN,
        },
    )?;
    reconcile_resource(resource);
    drain_pending_in_syscall();
    kernel_log_fmt(format_args!(
        "[CAP ] drop handle={}:{} holder={}\n",
        handle.slot, handle.generation, actor.0,
    ));
    Ok(())
}

fn handle_probe(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = CapabilityError::UnauthorizedHolder.syscall_status();
            return;
        }
    };
    let raw_handle = frame.rsi;
    let required = Rights::from_bits(frame.rdx as u32).unwrap_or(Rights::empty());
    let handle = match CapabilityHandle::decode(raw_handle) {
        Ok(handle) => handle,
        Err(error) => {
            frame.rax = error.syscall_status();
            return;
        }
    };
    let class = match with_capability_space(|table| table.record(handle)) {
        Ok(record) => record.resource.class,
        Err(error) => {
            frame.rax = error.syscall_status();
            return;
        }
    };
    match authorize_current_class(raw_handle, class, required) {
        Ok(_) => {
            kernel_log_fmt(format_args!("[CAP ] probe allowed holder={}\n", holder.0));
            #[cfg(feature = "m6-revocation-self-test")]
            crate::selftest::m6_revocation::note_reader_probe(holder);
            frame.rax = 0;
        }
        Err(error) => {
            if matches!(
                error,
                CapabilityError::Revoked | CapabilityError::StaleHandle
            ) {
                kernel_log_fmt(format_args!(
                    "[CAP ] stale denied holder={} reason={}\n",
                    holder.0,
                    error.error_name(),
                ));
            }
            frame.rax = error.syscall_status();
        }
    }
}
