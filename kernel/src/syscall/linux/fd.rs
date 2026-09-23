//! Linux fd syscalls: `close`, `dup2`, `fcntl`, `writev` (#147).

use super::table::LinuxSyscallContext;
use super::user_copy::copy_user_bytes;
use super::write::{ensure_fd_open, write_chunked, LINUX_WRITE_CHUNK_BYTES};
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::process::linux_fd::{
    self, apply_linux_fl_to_status, ensure_open_fd, open_status_to_linux_fl, projection_for,
};
use clean_slate_linux_abi::{LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EFAULT, EINVAL};

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

    if total_len == 0 {
        return Ok(0);
    }

    write_chunked(
        total_len,
        |offset, len, dst| {
            copy_from_iovecs(&iovecs[..iovcnt], offset, len, dst)?;
            Ok(len)
        },
        |chunk| linux_fd::write_fd(pid, generation, fd, chunk),
    )
}

fn copy_from_iovecs(
    iovecs: &[IoVec],
    offset: u64,
    len: usize,
    dst: &mut [u8; LINUX_WRITE_CHUNK_BYTES],
) -> Result<(), LinuxErrno> {
    let mut filled = 0usize;
    let mut cursor = offset;
    while filled < len {
        let (index, skip) = locate_iov_index(iovecs, cursor)?;
        let iov = &iovecs[index];
        let remaining_in_iov = iov.len - skip;
        let want = (len - filled).min(remaining_in_iov as usize);
        let chunk_ptr = iov.base.checked_add(skip).ok_or(EFAULT)?;
        let mut scratch = [0u8; LINUX_WRITE_CHUNK_BYTES];
        copy_user_bytes(chunk_ptr, want as u64, &mut scratch)?;
        dst[filled..filled + want].copy_from_slice(&scratch[..want]);
        filled += want;
        cursor += want as u64;
    }
    Ok(())
}

fn locate_iov_index(iovecs: &[IoVec], offset: u64) -> Result<(usize, u64), LinuxErrno> {
    let mut walked = 0u64;
    for (index, iov) in iovecs.iter().enumerate() {
        if iov.len == 0 {
            continue;
        }
        let end = walked.checked_add(iov.len).ok_or(EINVAL)?;
        if offset < end {
            return Ok((index, offset - walked));
        }
        walked = end;
    }
    Err(EFAULT)
}

#[cfg(feature = "m9-rootfs")]
pub(crate) fn handle_sys_read(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    use crate::mm::user_mapping::validate_user_writable_pointer_range;
    use clean_slate_linux_abi::EFAULT;
    let fd = request.args[0];
    let buf_ptr = request.args[1];
    let count = request.args[2];
    if count == 0 {
        return Ok(0);
    }
    ensure_open_fd(ctx.pid, ctx.instance_generation, fd)?;
    if validate_user_writable_pointer_range(buf_ptr, count).is_err() {
        return Err(EFAULT);
    }
    let mut scratch = [0u8; 64];
    let want = count.min(scratch.len() as u64) as usize;
    let read = super::fs_io::read_file_fd(ctx.pid, ctx.instance_generation, fd, &mut scratch[..want])?;
    if read == 0 {
        return Ok(0);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(scratch.as_ptr(), buf_ptr as *mut u8, read);
    }
    Ok(read as u64)
}

#[cfg(feature = "m9-rootfs")]
pub(crate) fn handle_sys_lseek(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let offset = request.args[1] as i64;
    let whence = request.args[2] as u32;
    ensure_open_fd(ctx.pid, ctx.instance_generation, fd)?;
    super::fs_io::lseek_file_fd(ctx.pid, ctx.instance_generation, fd, offset, whence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::interrupt_context::SyscallContext;
    use crate::ipc::IpcEndpointTable;
    use crate::process::linux_fd::{LinuxFdRegistry, LINUX_STDOUT_FD};
    use clean_slate_linux_abi::{EBADF, SYS_DUP2, SYS_FCNTL, SYS_WRITEV};
    use clean_slate_service_lifecycle::InstanceGeneration;

    fn empty_frame() -> SyscallContext {
        SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        }
    }

    fn syscall_ctx(frame: &mut SyscallContext) -> LinuxSyscallContext<'_> {
        LinuxSyscallContext {
            pid: 17,
            instance_generation: InstanceGeneration(4),
            frame,
        }
    }

    #[test]
    fn locate_iov_index_skips_zero_length_iov() {
        let iovecs = [
            IoVec {
                base: 0x1000,
                len: 2,
            },
            IoVec {
                base: 0x2000,
                len: 0,
            },
            IoVec {
                base: 0x3000,
                len: 3,
            },
        ];
        assert_eq!(locate_iov_index(&iovecs, 0), Ok((0, 0)));
        assert_eq!(locate_iov_index(&iovecs, 2), Ok((2, 0)));
    }

    #[test]
    fn writev_iovcnt_above_linux_iov_max_is_einval() {
        let pid = 88u64;
        let generation = InstanceGeneration(77);
        let mut ipc = IpcEndpointTable::new();
        let handle = ipc
            .grant_console_capability_for_pid(pid)
            .expect("console grant");
        linux_fd::install_stdio_for_process(pid, generation, handle, handle)
            .expect("install stdio");
        let mut frame = empty_frame();
        let mut ctx = LinuxSyscallContext {
            pid,
            instance_generation: generation,
            frame: &mut frame,
        };
        let request = LinuxSyscallRequest {
            nr: SYS_WRITEV,
            args: [LINUX_STDOUT_FD, 0x1000, (LINUX_IOV_MAX as u64) + 1, 0, 0, 0],
        };
        assert_eq!(handle_sys_writev(&request, &mut ctx), Err(EINVAL));
    }

    #[test]
    fn fcntl_unknown_command_is_einval() {
        let mut frame = empty_frame();
        let mut ctx = syscall_ctx(&mut frame);
        let request = LinuxSyscallRequest {
            nr: SYS_FCNTL,
            args: [1, 0xdead, 0, 0, 0, 0],
        };
        assert_eq!(handle_sys_fcntl(&request, &mut ctx), Err(EINVAL));
    }

    #[test]
    fn fcntl_without_fd_table_is_ebadf() {
        let mut frame = empty_frame();
        let mut ctx = syscall_ctx(&mut frame);
        let request = LinuxSyscallRequest {
            nr: SYS_FCNTL,
            args: [1, F_GETFD, 0, 0, 0, 0],
        };
        assert_eq!(handle_sys_fcntl(&request, &mut ctx), Err(EBADF));
    }

    #[test]
    fn dup2_same_fd_is_noop_when_already_open() {
        let (mut fds, mut ipc) = (LinuxFdRegistry::new(), IpcEndpointTable::new());
        let gen = InstanceGeneration(1);
        let handle = ipc.grant_console_capability_for_pid(2).expect("grant");
        fds.install(2, gen, handle, handle).expect("install");
        fds.dup2(2, gen, LINUX_STDOUT_FD, 5).expect("dup to 5");
        assert!(fds.dup2(2, gen, 5, 5).is_ok());
    }

    #[test]
    fn close_with_stale_generation_is_ebadf() {
        let (mut fds, mut ipc) = (LinuxFdRegistry::new(), IpcEndpointTable::new());
        let live = InstanceGeneration(1);
        let stale = InstanceGeneration(2);
        let handle = ipc.grant_console_capability_for_pid(3).expect("grant");
        fds.install(3, live, handle, handle).expect("install");
        assert_eq!(fds.close_fd(3, stale, LINUX_STDOUT_FD), Err(EBADF));
    }

    #[test]
    fn dup2_handler_maps_ebadf_without_fd_table() {
        let mut frame = empty_frame();
        let mut ctx = syscall_ctx(&mut frame);
        let request = LinuxSyscallRequest {
            nr: SYS_DUP2,
            args: [1, 5, 0, 0, 0, 0],
        };
        assert_eq!(handle_sys_dup2(&request, &mut ctx), Err(EBADF));
    }
}
