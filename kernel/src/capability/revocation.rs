//! M6.6 capability revocation syscall surface (SYSCALL_NR_CAP_REVOKE).

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use clean_slate_capability::syscall_abi::SYSCALL_EINVAL;
use clean_slate_capability::{
    authorize_revoke, revoke_subtree, CapabilityError, CapabilityHandle, Rights,
};

use super::{authorize_current_class, capability_space_mut, current_holder, with_capability_space};

pub(crate) const REVOKE_OP_REVOKE: u64 = 1;
pub(crate) const REVOKE_OP_PROBE: u64 = 2;
/// M6.6 self-test only: returns 1 once both reader fixtures probed, else 0.
#[cfg(feature = "m6-revocation-self-test")]
pub(crate) const REVOKE_OP_WAIT_READERS: u64 = 3;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    match frame.rdi {
        REVOKE_OP_REVOKE => handle_revoke(frame),
        REVOKE_OP_PROBE => handle_probe(frame),
        #[cfg(feature = "m6-revocation-self-test")]
        REVOKE_OP_WAIT_READERS => {
            crate::selftest::m6_revocation::handle_wait_for_readers(frame);
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
    let result = revoke_subtree(unsafe { capability_space_mut() }, handle);
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
