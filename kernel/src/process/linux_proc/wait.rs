//! `wait4` helpers (#102).

use super::pipe::wait_key_for_parent;
use super::table::{table_mut, ProcId};
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, ECHILD, EFAULT};

pub(crate) fn linux_wait4(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let wait_pid = request.args[0] as i64;
    let wstatus_ptr = request.args[1];
    let options = request.args[2];
    let rusage = request.args[3];
    const WNOHANG: u64 = 1;
    let nohang = options & WNOHANG != 0;
    // BusyBox/glibc may set `__WALL` and other bits we do not implement yet; ignore them.
    if rusage != 0 {
        // Documented: non-NULL rusage ignored in M9 traces (always NULL).
    }
    // Linux: `0` = any child in pgid; `<-1` = any child in pgid `-pid`. M9 has no
    // separate pgid tracking yet, so collapse those to "any child of parent".
    let wait_filter = match wait_pid {
        -1 | 0 => -1,
        pid if pid < -1 => -1,
        pid => pid,
    };
    let table = table_mut();
    let parent = table.resolve_proc_id(ProcId {
        pid: ctx.pid,
        generation: ctx.instance_generation,
    });
    if !table.has_any_child(parent) {
        return Err(ECHILD);
    }
    if let Some((child, status)) = table.find_zombie_child(parent, wait_filter) {
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
    if nohang {
        return Ok(0);
    }
    if !table.has_waitable_children(parent, wait_filter) {
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
