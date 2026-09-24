//! M6.5 capability delegation/attenuation syscall surface (SYSCALL_NR_CAP_DELEGATE).

use core::fmt::{self, Write};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::process::process_registry_mut;
use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC};
use clean_slate_capability::{
    delegate, delegation_depth, list_holder, CapabilityError, CapabilityHandle, HolderId, Rights,
};

use super::bootstrap_grant::register_bootstrap_grant;
use super::{capability_space_mut, current_holder};

pub(crate) const DELEGATE_OP_DELEGATE: u64 = 1;
pub(crate) const DELEGATE_OP_LIST: u64 = 2;
/// M6.5 self-test only: returns encoded child handle or 0 until owner delegation completes.
#[cfg(feature = "m6-delegation-self-test")]
pub(crate) const DELEGATE_OP_POLL_CHILD: u64 = 3;

const LISTING_BYTES: u64 = 32;

#[repr(C)]
struct CapabilityListing {
    handle: u64,
    class: u64,
    rights: u64,
    depth: u64,
}

struct RightsNameBuf {
    bytes: [u8; 64],
    len: usize,
}

impl Write for RightsNameBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

pub(crate) fn log_delegate_denied(from: HolderId, to: HolderId, error: CapabilityError) {
    kernel_log_fmt(format_args!(
        "[CAP ] delegate denied from={} to={} reason={}\n",
        from.0,
        to.0,
        error.error_name(),
    ));
}

fn log_delegate_success(from: HolderId, to: HolderId, rights: Rights, depth: u8) {
    let mut names = RightsNameBuf {
        bytes: [0; 64],
        len: 0,
    };
    let _ = rights.write_names(&mut names);
    let rights_text = core::str::from_utf8(&names.bytes[..names.len]).unwrap_or("?");
    kernel_log_fmt(format_args!(
        "[CAP ] delegate from={} to={} rights={} depth={}\n",
        from.0, to.0, rights_text, depth,
    ));
}

fn is_live_userspace_process(pid: u64) -> bool {
    if pid == HolderId::KERNEL.0 {
        return false;
    }
    unsafe {
        process_registry_mut()
            .get(pid)
            .is_some_and(|process| process.exit_status.is_none())
    }
}

fn rollback_installed_child(child: CapabilityHandle) {
    let table = unsafe { capability_space_mut() };
    let slot = usize::from(child.slot);
    if table.revoke(child).is_ok() {
        table.release_slot(slot);
    }
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    match frame.rdi {
        DELEGATE_OP_DELEGATE => handle_delegate(frame),
        DELEGATE_OP_LIST => handle_list(frame),
        #[cfg(feature = "m6-delegation-self-test")]
        DELEGATE_OP_POLL_CHILD => {
            crate::selftest::m6_delegation::handle_poll_delegated_child(frame);
        }
        _ => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_delegate(frame: &mut SyscallContext) {
    let source = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let parent = match CapabilityHandle::decode(frame.rsi) {
        Ok(handle) => handle,
        Err(error) => {
            frame.rax = error.syscall_status();
            return;
        }
    };
    let target_pid = frame.rdx;
    let target = HolderId(target_pid);
    if !is_live_userspace_process(target_pid) {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let rights = match Rights::from_bits(frame.r10 as u32) {
        Some(rights) => rights,
        None => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    let child = match delegate(
        unsafe { capability_space_mut() },
        source,
        parent,
        target,
        rights,
    ) {
        Ok(handle) => handle,
        Err(error) => {
            log_delegate_denied(source, target, error);
            frame.rax = error.syscall_status();
            return;
        }
    };
    let depth = match delegation_depth(unsafe { &*capability_space_mut() }, child) {
        Ok(depth) => depth,
        Err(error) => {
            rollback_installed_child(child);
            log_delegate_denied(source, target, error);
            frame.rax = error.syscall_status();
            return;
        }
    };
    if register_bootstrap_grant(target, child).is_err() {
        rollback_installed_child(child);
        frame.rax = SYSCALL_ENOSPC;
        return;
    }
    log_delegate_success(source, target, rights, depth);
    #[cfg(feature = "m6-delegation-self-test")]
    crate::selftest::m6_delegation::record_delegated_child_for_self_test(child);
    frame.rax = child.encode();
}

fn handle_list(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    if validate_user_writable_pointer_range(frame.rdx, LISTING_BYTES).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let cursor = match usize::try_from(frame.rsi) {
        Ok(cursor) => cursor,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    let table = unsafe { &*capability_space_mut() };
    match list_holder(table, holder, cursor) {
        Some((next_cursor, handle, record)) => {
            let listing = CapabilityListing {
                handle: handle.encode(),
                class: u64::from(record.resource.class.as_u8()),
                rights: u64::from(record.rights.bits()),
                depth: u64::from(record.provenance.depth),
            };
            unsafe {
                core::ptr::write(frame.rdx as *mut CapabilityListing, listing);
            }
            frame.rax = next_cursor as u64;
        }
        None => frame.rax = 0,
    }
}
