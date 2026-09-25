//! Linux fd syscalls: `close`, `dup2`, `fcntl`, `writev` (#147).

use super::table::LinuxSyscallContext;
use super::user_copy::copy_user_bytes;
use super::write::{ensure_fd_open, write_chunked};
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::process::linux_fd::{
    self, apply_linux_fl_to_status, ensure_open_fd, open_description::DescriptorKind,
    open_status_to_linux_fl, projection_for, LinuxFdProjection,
};
use clean_slate_linux_abi::{
    LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EBADF, EFAULT, EINVAL,
};

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
        DescriptorKind::PipeRead(_) => {
            #[cfg(not(any(
                feature = "m1-self-test",
                feature = "m2-double-fault-self-test",
                feature = "m2-timer-self-test"
            )))]
            {
                crate::process::linux_proc::pipe::read_fd(
                    request,
                    ctx,
                    pid,
                    generation,
                    fd,
                    &mut scratch[..want],
                )
            }
            #[cfg(any(
                feature = "m1-self-test",
                feature = "m2-double-fault-self-test",
                feature = "m2-timer-self-test"
            ))]
            {
                // M1/M2 boots exclude the Linux process substrate (no pipes exist).
                let _ = &mut scratch[..want];
                Err(EBADF)
            }
        }
        DescriptorKind::File(_) => {
            #[cfg(feature = "m9-rootfs")]
            {
                super::fs_io::read_file_fd(request, ctx, pid, generation, fd, &mut scratch[..want])
            }
            #[cfg(not(feature = "m9-rootfs"))]
            {
                let _ = (request, ctx, pid, generation, fd);
                Err(EBADF)
            }
        }
        DescriptorKind::Socket(socket) => {
            #[cfg(feature = "m9-linux-socket")]
            {
                crate::process::linux_socket::read_socket(
                    request,
                    ctx,
                    pid,
                    generation,
                    fd,
                    socket,
                    &mut scratch[..want],
                )
            }
            #[cfg(not(feature = "m9-linux-socket"))]
            {
                let _ = (request, ctx, pid, generation, fd, socket);
                Err(EBADF)
            }
        }
        DescriptorKind::Dir(_) | DescriptorKind::PipeWrite(_) => Err(EBADF),
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

    let projection = projection_for(pid, generation, fd)?;
    ensure_fd_open(Ok(projection))?;

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

    let write_chunk = |chunk: &[u8]| -> Result<usize, LinuxErrno> {
        if chunk.is_empty() {
            return Ok(0);
        }
        #[cfg(feature = "m9-rootfs")]
        if matches!(projection, LinuxFdProjection::FileBackend) {
            let n = super::fs_io::write_file_fd(request, ctx, pid, generation, fd, chunk)?;
            return usize::try_from(n).map_err(|_| EINVAL);
        }
        if matches!(projection, LinuxFdProjection::PipeBackend) {
            #[cfg(not(any(
                feature = "m1-self-test",
                feature = "m2-double-fault-self-test",
                feature = "m2-timer-self-test"
            )))]
            {
                let n = crate::process::linux_proc::pipe::write_fd_buffer(
                    request, ctx, pid, generation, fd, chunk,
                )?;
                return usize::try_from(n).map_err(|_| EINVAL);
            }
        }
        linux_fd::write_fd(pid, generation, fd, chunk)
    };

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
        write_chunk,
    )
}

#[cfg(test)]
fn locate_iov_index(
    iovecs: &[IoVec],
    offset: u64,
) -> Result<(usize, u64), clean_slate_linux_abi::LinuxErrno> {
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

pub(crate) fn handle_sys_lseek(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    use crate::process::linux_fd::open_description::DescriptorKind;
    use clean_slate_linux_abi::ESPIPE;
    let fd = request.args[0];
    let offset = request.args[1] as i64;
    let whence = request.args[2] as u32;
    let _ = request;
    let _ = ctx;
    ensure_open_fd(ctx.pid, ctx.instance_generation, fd)?;
    let open = linux_fd::open_description_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
    let desc = linux_fd::open_description_snapshot(open)?;
    match desc.kind {
        DescriptorKind::File(_) => {
            #[cfg(feature = "m9-rootfs")]
            {
                super::fs_io::lseek_file_fd(ctx.pid, ctx.instance_generation, fd, offset, whence)
            }
            #[cfg(not(feature = "m9-rootfs"))]
            {
                let _ = (offset, whence);
                Err(ESPIPE)
            }
        }
        _ => Err(ESPIPE),
    }
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
        ipc.grant_console_capability_for_pid(pid)
            .expect("console grant");
        let sink = linux_fd::console_sink_ref_from_table(&ipc).expect("console sink");
        linux_fd::install_stdio_for_process(pid, generation, sink)
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
        ipc.grant_console_capability_for_pid(2).expect("grant");
        let sink = linux_fd::console_sink_ref_from_table(&ipc).expect("sink");
        fds.install(2, gen, sink).expect("install");
        fds.dup2(2, gen, LINUX_STDOUT_FD, 5).expect("dup to 5");
        assert!(fds.dup2(2, gen, 5, 5).is_ok());
    }

    #[test]
    fn close_with_stale_generation_is_ebadf() {
        let (mut fds, mut ipc) = (LinuxFdRegistry::new(), IpcEndpointTable::new());
        let live = InstanceGeneration(1);
        let stale = InstanceGeneration(2);
        ipc.grant_console_capability_for_pid(3).expect("grant");
        let sink = linux_fd::console_sink_ref_from_table(&ipc).expect("sink");
        fds.install(3, live, sink).expect("install");
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
