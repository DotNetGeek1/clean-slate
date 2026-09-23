//! Linux fd syscalls: `close`, `dup2`, `fcntl`, `writev` (#147).

use super::table::LinuxSyscallContext;
use super::user_copy::copy_user_bytes;
use super::write::{ensure_fd_open, write_chunked};
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::process::linux_fd::{
    self, apply_linux_fl_to_status, ensure_open_fd, open_description::DescriptorKind,
    open_status_to_linux_fl, projection_for,
};
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, EBADF, EFAULT, EINVAL};

/// Matches frozen pipe `read(0, …, 1024)` traces.
pub(crate) const LINUX_READ_SCRATCH_BYTES: usize = 1024;

/// Bounded `writev` iov count (self-test uses 2–3; keep small and fixed).
pub(crate) const LINUX_IOV_MAX: usize = 8;

const F_DUPFD_CLOEXEC: u64 = 1030;
const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const F_GETFL: u64 = 3;
const F_SETFL: u64 = 4;
const FD_CLOEXEC: u64 = 1;

#[derive(Copy, Clone)]
#[repr(C)]
struct IoVec {
    base: u64,
    len: u64,
}

pub(crate) fn handle_sys_read(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let buf_ptr = request.args[1];
    let count = request.args[2];
    let pid = ctx.pid;
    let generation = ctx.instance_generation;

    ensure_open_fd(pid, generation, fd)?;
    if count == 0 {
        return Ok(0);
    }
    let want = usize::try_from(count)
        .map_err(|_| EINVAL)?
        .min(LINUX_READ_SCRATCH_BYTES);
    validate_user_writable_pointer_range(buf_ptr, want as u64).map_err(|_| EFAULT)?;

    let mut scratch = [0u8; LINUX_READ_SCRATCH_BYTES];
    let result = match linux_fd::open_description_kind(pid, generation, fd)? {
        DescriptorKind::Console(_) => Ok(0u64),
        DescriptorKind::PipeRead(_) => crate::process::linux_proc::pipe::read_fd(
            request,
            ctx,
            pid,
            generation,
            fd,
            &mut scratch[..want],
        ),
        DescriptorKind::File(_) | DescriptorKind::Socket(_) => Err(EBADF),
        DescriptorKind::PipeWrite(_) | DescriptorKind::Dir(_) => Err(EBADF),
    };
    if let Ok(n) = result {
        if n > 0 {
            unsafe {
                core::ptr::copy_nonoverlapping(scratch.as_ptr(), buf_ptr as *mut u8, n as usize);
            }
        }
    }
    result
}

pub(crate) fn handle_sys_close(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    linux_fd::close_fd(ctx.pid, ctx.instance_generation, fd).map(|()| 0)
}

pub(crate) fn handle_sys_dup2(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let old_fd = request.args[0];
    let new_fd = request.args[1];
    linux_fd::dup2(ctx.pid, ctx.instance_generation, old_fd, new_fd).map(|()| new_fd)
}

pub(crate) fn handle_sys_fcntl(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let cmd = request.args[1];
    let arg = request.args[2];
    let pid = ctx.pid;
    let generation = ctx.instance_generation;

    match cmd {
        F_GETFD => {
            ensure_open_fd(pid, generation, fd)?;
            let cloexec = linux_fd::get_fd_cloexec(pid, generation, fd)?;
            Ok(if cloexec { FD_CLOEXEC } else { 0 })
        }
        F_SETFD => {
            ensure_open_fd(pid, generation, fd)?;
            let cloexec = (arg & FD_CLOEXEC) != 0;
            linux_fd::set_fd_cloexec(pid, generation, fd, cloexec).map(|()| 0)
        }
        F_GETFL => {
            ensure_open_fd(pid, generation, fd)?;
            let status = linux_fd::open_description_status(pid, generation, fd)?;
            Ok(open_status_to_linux_fl(&status) as u64)
        }
        F_SETFL => {
            ensure_open_fd(pid, generation, fd)?;
            let mut status = linux_fd::open_description_status(pid, generation, fd)?;
            apply_linux_fl_to_status(arg as u32, &mut status)?;
            linux_fd::set_open_description_status(pid, generation, fd, status)?;
            Ok(0)
        }
        F_DUPFD_CLOEXEC => {
            ensure_open_fd(pid, generation, fd)?;
            linux_fd::dup_to_lowest_at_or_above(pid, generation, fd, arg)
                .map(|new_fd| new_fd as u64)
        }
        _ => Err(EINVAL),
    }
}

pub(crate) fn handle_sys_writev(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let iov_ptr = request.args[1];
    let iovcnt = request.args[2];
    let pid = ctx.pid;
    let generation = ctx.instance_generation;

    ensure_fd_open(projection_for(pid, generation, fd))?;

    if iovcnt == 0 {
        return Ok(0);
    }
    let iovcnt = usize::try_from(iovcnt).map_err(|_| EINVAL)?;
    if iovcnt > LINUX_IOV_MAX {
        return Err(EINVAL);
    }
    let iovec_bytes = (core::mem::size_of::<IoVec>() as u64)
        .checked_mul(iovcnt as u64)
        .ok_or(EINVAL)?;
    if validate_user_pointer_range(iov_ptr, iovec_bytes).is_err() {
        return Err(EFAULT);
    }

    let mut iovecs = [IoVec { base: 0, len: 0 }; LINUX_IOV_MAX];
    let src = iov_ptr as *const u8;
    let dst = iovecs.as_mut_ptr() as *mut u8;
    let bytes = iovec_bytes as usize;
    unsafe {
        core::ptr::copy_nonoverlapping(src, dst, bytes);
    }

    let mut total_len = 0u64;
    for iov in &iovecs[..iovcnt] {
        total_len = total_len.checked_add(iov.len).ok_or(EINVAL)?;
        if iov.len > 0 && validate_user_pointer_range(iov.base, iov.len).is_err() {
            return Err(EFAULT);
        }
    }

    write_chunked(
        total_len,
        |offset, len, dst| {
            let mut copied = 0usize;
            let mut pos = offset;
            for iov in &iovecs[..iovcnt] {
                if pos >= iov.len {
                    pos -= iov.len;
                    continue;
                }
                let take = (iov.len - pos).min((len - copied) as u64) as usize;
                let mut chunk = [0u8; super::user_copy::LINUX_USER_COPY_MAX_BYTES];
                copy_user_bytes(iov.base + pos, take as u64, &mut chunk)?;
                dst[copied..copied + take].copy_from_slice(&chunk[..take]);
                copied += take;
                pos = 0;
                if copied >= len {
                    break;
                }
            }
            Ok(copied)
        },
        |chunk| {
            let sent = linux_fd::write_fd(pid, generation, fd, chunk)?;
            Ok(sent)
        },
    )
}
