//! `wait4` helpers (#102).

use super::pipe::wait_key_for_parent;
use super::table::{table_mut, ProcId};
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, ECHILD, EFAULT, EINVAL};

const WNOHANG: u64 = 1;
const WUNTRACED: u64 = 2;
const WCONTINUED: u64 = 8;
const WNOTHREAD: u64 = 0x2000_0000;
const WALL: u64 = 0x4000_0000;
const WCLONE: u64 = 0x8000_0000;
const WAIT_OPTIONS_ALLOWED: u64 = WNOHANG | WUNTRACED | WCONTINUED | WNOTHREAD | WALL | WCLONE;
pub(crate) fn linux_wait4(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let wait_pid = request.args[0] as i64;
    let wstatus_ptr = request.args[1];
    let options = request.args[2];
    let rusage = request.args[3];
    if options & !WAIT_OPTIONS_ALLOWED != 0 {
        return Err(EINVAL);
    }
    let nohang = options & WNOHANG != 0;
    // WUNTRACED / WCONTINUED: M9 has no stopped/continued children; flags are accepted no-ops.

    let parent = ProcId {
        pid: ctx.pid,
        generation: ctx.instance_generation,
    };
    let table = table_mut();
    table.require_proc_slot(parent)?;
    let parent_pgid = table.pgid_of(parent).ok_or(ECHILD)?;

    if wait_pid < -1 && (-wait_pid) as u64 != parent_pgid {
        return Err(ECHILD);
    }

    if rusage != 0 {
        validate_user_writable_pointer_range(rusage, 144).map_err(|_| EFAULT)?;
        unsafe {
            core::ptr::write_bytes(rusage as *mut u8, 0, 144);
        }
    }

    if let Some((child, status)) = table.find_zombie_child(parent, wait_pid) {
        if wstatus_ptr != 0 {
            let bytes = (status as u32).to_le_bytes();
            validate_user_writable_pointer_range(wstatus_ptr, bytes.len() as u64)
                .map_err(|_| EFAULT)?;
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), wstatus_ptr as *mut u8, bytes.len());
            }
        }
        table.reap_zombie(child);
        return Ok(child.pid);
    }
    if !table.has_child_in_wait_set(parent, wait_pid) {
        return Err(ECHILD);
    }
    if nohang {
        return Ok(0);
    }
    if !table.has_waitable_children(parent, wait_pid) {
        return Err(ECHILD);
    }
    block_linux_syscall(
        request,
        ctx,
        wait_key_for_parent(ctx.pid),
        None,
        LinuxTimeoutResult::Zero,
    )
}
