//! Linux runtime/memory/time/poll syscall family (#103).

use super::block::{block_linux_syscall, LinuxTimeoutResult};
use super::poll::{
    clear_poll_interest_for_pid, nanosleep_wait_key, poll_wait_key, register_poll_interest,
    LINUX_POLL_MAX_FDS,
};
use super::table::{LinuxSyscallContext, LinuxSyscallHandler};
use super::user_copy::{copy_user_bytes, LINUX_USER_COPY_MAX_BYTES};
use crate::interrupt::timer::kernel_ticks;
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::process::linux_fd::{self, readiness::Readiness};
use crate::process::linux_mem;
use crate::process::linux_signal;
use crate::sched::wait::Deadline;
use crate::time::{
    monotonic_deadline_from_millis, monotonic_deadline_from_timespec, monotonic_ns,
    timespec_from_monotonic_ns, timespec_from_remaining_ns,
};
#[cfg(feature = "m9-linux-runtime-self-test")]
use crate::time::{sleep_budget_ns_from_millis, sleep_budget_ns_from_timespec};
use clean_slate_linux_abi::{
    decode_pollfd, decode_sigaction, decode_timespec, encode_pollfd, encode_sigaction, LinuxErrno,
    LinuxSyscallRequest, LinuxSyscallResult, PollFd, Sigaction, CLOCK_MONOTONIC, EFAULT, EINVAL,
    ENOTTY, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, SYS_ARCH_PRCTL, SYS_BRK,
    SYS_CLOCK_GETTIME, SYS_GETEUID, SYS_GETPID, SYS_IOCTL, SYS_MMAP, SYS_MUNMAP, SYS_NANOSLEEP,
    SYS_POLL, SYS_RT_SIGACTION, SYS_RT_SIGPROCMASK, SYS_SET_TID_ADDRESS, SYS_UNAME, TCGETS,
    TIOCGWINSZ,
};

/// Single-user M9 fixture personality: effective uid is 0 (matches auxv `AT_EUID`).
const LINUX_FIXTURE_UID: u64 = 0;

const USER_COPY_POLL: usize = 8;

pub(crate) fn lookup_handler(nr: u64) -> Option<LinuxSyscallHandler> {
    match nr {
        SYS_ARCH_PRCTL => Some(handle_sys_arch_prctl),
        SYS_BRK => Some(handle_sys_brk),
        SYS_CLOCK_GETTIME => Some(handle_sys_clock_gettime),
        SYS_GETPID => Some(handle_sys_getpid),
        SYS_GETEUID => Some(handle_sys_geteuid),
        SYS_IOCTL => Some(handle_sys_ioctl),
        SYS_MMAP => Some(handle_sys_mmap),
        SYS_MUNMAP => Some(handle_sys_munmap),
        SYS_NANOSLEEP => Some(handle_sys_nanosleep),
        SYS_POLL => Some(handle_sys_poll),
        SYS_RT_SIGACTION => Some(handle_sys_rt_sigaction),
        SYS_RT_SIGPROCMASK => Some(handle_sys_rt_sigprocmask),
        SYS_SET_TID_ADDRESS => Some(handle_sys_set_tid_address),
        SYS_UNAME => Some(handle_sys_uname),
        _ => None,
    }
}

fn handle_sys_arch_prctl(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    linux_mem::sys_arch_prctl(
        request.args[0],
        request.args[1],
        ctx.pid,
        ctx.instance_generation,
    )
}

fn handle_sys_brk(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    linux_mem::sys_brk(request.args[0], ctx.pid, ctx.instance_generation)
}

fn handle_sys_getpid(
    _request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    Ok(ctx.pid)
}

fn handle_sys_geteuid(
    _request: &LinuxSyscallRequest,
    _ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    Ok(LINUX_FIXTURE_UID)
}

/// Only `CLOCK_MONOTONIC` (calibrated TSC) is backed; there is no wall clock, so every other
/// clock id fails closed with `EINVAL`.
fn handle_sys_clock_gettime(
    request: &LinuxSyscallRequest,
    _ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    if request.args[0] != CLOCK_MONOTONIC {
        return Err(EINVAL);
    }
    let ts = timespec_from_monotonic_ns(monotonic_ns());
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&ts.tv_sec.to_le_bytes());
    bytes[8..16].copy_from_slice(&ts.tv_nsec.to_le_bytes());
    write_user(request.args[1], &bytes)?;
    Ok(0)
}

fn handle_sys_ioctl(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    linux_fd::ensure_open_fd(ctx.pid, ctx.instance_generation, fd)?;
    match request.args[1] {
        TIOCGWINSZ | TCGETS => Err(ENOTTY),
        _ => Err(ENOTTY),
    }
}

fn handle_sys_mmap(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    linux_mem::sys_mmap(
        request.args[0],
        request.args[1],
        request.args[2],
        request.args[3],
        request.args[4] as i64,
        request.args[5],
        ctx.pid,
        ctx.instance_generation,
    )
}

fn handle_sys_munmap(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    linux_mem::sys_munmap(
        request.args[0],
        request.args[1],
        ctx.pid,
        ctx.instance_generation,
    )
}

fn handle_sys_set_tid_address(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    linux_mem::sys_set_tid_address(request.args[0], ctx.pid, ctx.instance_generation)
}

fn handle_sys_uname(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    linux_mem::copy_utsname_to_user(request.args[0], ctx.pid, ctx.instance_generation)?;
    Ok(0)
}

fn handle_sys_rt_sigaction(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let signum = request.args[0];
    let act_ptr = request.args[1];
    let old_ptr = request.args[2];
    let sigsetsize = request.args[3];
    let act = if act_ptr != 0 {
        let mut scratch = [0u8; LINUX_USER_COPY_MAX_BYTES];
        let copied = copy_user_bytes(
            act_ptr,
            clean_slate_linux_abi::SIGACTION_SIZE as u64,
            &mut scratch,
        )?;
        let bytes = &scratch[..copied];
        Some(decode_sigaction(bytes)?)
    } else {
        None
    };
    let mut old = Sigaction::default();
    linux_signal::rt_sigaction(
        signum,
        act,
        if old_ptr != 0 { Some(&mut old) } else { None },
        sigsetsize,
        ctx.pid,
        ctx.instance_generation,
    )?;
    if old_ptr != 0 {
        write_user(old_ptr, &encode_sigaction(old))?;
    }
    Ok(0)
}

fn handle_sys_rt_sigprocmask(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let how = request.args[0] as i32;
    let set_ptr = request.args[1];
    let old_ptr = request.args[2];
    let sigsetsize = request.args[3];
    let set = if set_ptr != 0 {
        validate_user_pointer_range(set_ptr, 8).map_err(|_| EFAULT)?;
        Some(read_u64(set_ptr)?)
    } else {
        None
    };
    let mut old = 0u64;
    linux_signal::rt_sigprocmask(
        how,
        set,
        if old_ptr != 0 { Some(&mut old) } else { None },
        sigsetsize,
        ctx.pid,
        ctx.instance_generation,
    )?;
    if old_ptr != 0 {
        write_user(old_ptr, &old.to_le_bytes())?;
    }
    Ok(0)
}

fn handle_sys_nanosleep(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let req_ptr = request.args[0];
    let rem_ptr = request.args[1];
    let mut scratch = [0u8; LINUX_USER_COPY_MAX_BYTES];
    let copied = copy_user_bytes(req_ptr, 16, &mut scratch)?;
    let bytes = &scratch[..copied];
    let ts = decode_timespec(bytes)?;
    if ts.tv_sec == 0 && ts.tv_nsec == 0 {
        if rem_ptr != 0 {
            write_zero_timespec(rem_ptr)?;
        }
        linux_mem::set_pending_sleep_deadline(ctx.pid, ctx.instance_generation, None);
        return Ok(0);
    }
    let deadline = linux_mem::pending_sleep_deadline(ctx.pid, ctx.instance_generation);
    let deadline = match deadline {
        Some(existing) => existing,
        None => {
            let now = monotonic_ns();
            let abs = monotonic_deadline_from_timespec(now, ts)?;
            let d = Deadline::MonotonicNs(abs);
            linux_mem::set_pending_sleep_deadline(ctx.pid, ctx.instance_generation, Some(d));
            #[cfg(feature = "m9-linux-runtime-self-test")]
            {
                crate::selftest::m9_linux_runtime::record_nanosleep_self_test(ctx.pid, ts, now);
            }
            d
        }
    };
    if deadline_due(deadline) {
        linux_mem::set_pending_sleep_deadline(ctx.pid, ctx.instance_generation, None);
        if rem_ptr != 0 {
            write_zero_timespec(rem_ptr)?;
        }
        #[cfg(feature = "m9-linux-runtime-self-test")]
        {
            let budget = sleep_budget_ns_from_timespec(ts)?;
            let block_start = monotonic_deadline_ns(deadline).saturating_sub(budget);
            crate::selftest::m9_linux_runtime::on_nanosleep_complete_ns(ctx.pid, ts, block_start);
        }
        return Ok(0);
    }
    let result = block_linux_syscall(
        request,
        ctx,
        nanosleep_wait_key(ctx.pid),
        Some(deadline),
        LinuxTimeoutResult::Zero,
    );
    if super::block::is_block_restart_result(result) {
        if rem_ptr != 0 {
            write_remaining_timespec(rem_ptr, deadline)?;
        }
        return result;
    }
    #[cfg(feature = "m9-linux-runtime-self-test")]
    if result == Ok(0) {
        let budget = sleep_budget_ns_from_timespec(ts)?;
        let block_start = monotonic_deadline_ns(deadline).saturating_sub(budget);
        crate::selftest::m9_linux_runtime::on_nanosleep_complete_ns(ctx.pid, ts, block_start);
        linux_mem::set_pending_sleep_deadline(ctx.pid, ctx.instance_generation, None);
        if rem_ptr != 0 {
            write_zero_timespec(rem_ptr)?;
        }
    }
    result
}

fn handle_sys_poll(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let nfds = request.args[1] as usize;
    if nfds > LINUX_POLL_MAX_FDS {
        return Err(EINVAL);
    }
    let pollfds_ptr = request.args[0];
    let timeout_ms = request.args[2] as i32;
    if nfds == 0 {
        return poll_wait_with_timeout(ctx, request, pollfds_ptr, timeout_ms, &[]);
    }
    let total_bytes = nfds.checked_mul(USER_COPY_POLL).ok_or(EINVAL)?;
    let mut buf = [0u8; LINUX_USER_COPY_MAX_BYTES];
    let copied = copy_user_bytes(pollfds_ptr, total_bytes as u64, &mut buf)?;
    if copied < total_bytes {
        return Err(EINVAL);
    }
    let mut pollfds = [PollFd {
        fd: 0,
        events: 0,
        revents: 0,
    }; LINUX_POLL_MAX_FDS];
    for index in 0..nfds {
        pollfds[index] =
            decode_pollfd(&buf[index * USER_COPY_POLL..index * USER_COPY_POLL + USER_COPY_POLL])?;
    }
    for pollfd in &mut pollfds[..nfds] {
        if pollfd.fd >= 0 {
            if let Ok(open_id) = linux_fd::open_description_id_for_fd(
                ctx.pid,
                ctx.instance_generation,
                pollfd.fd as u64,
            ) {
                let _ = register_poll_interest(open_id, ctx.pid);
            }
        }
        pollfd.revents = fd_readiness(ctx, pollfd.fd, pollfd.events)?;
    }
    let ready = pollfds[..nfds].iter().filter(|p| p.revents != 0).count();
    if ready > 0 {
        write_pollfds(pollfds_ptr, &pollfds[..nfds])?;
        clear_poll_interest_for_pid(ctx.pid);
        linux_mem::set_pending_poll_deadline(ctx.pid, ctx.instance_generation, None);
        return Ok(ready as u64);
    }
    let result = poll_wait_with_timeout(ctx, request, pollfds_ptr, timeout_ms, &pollfds[..nfds]);
    clear_poll_interest_for_pid(ctx.pid);
    result
}

fn poll_wait_with_timeout(
    ctx: &mut LinuxSyscallContext<'_>,
    request: &LinuxSyscallRequest,
    pollfds_ptr: u64,
    timeout_ms: i32,
    pollfds: &[PollFd],
) -> LinuxSyscallResult {
    let nfds = pollfds.len();
    if timeout_ms == 0 {
        if nfds > 0 {
            write_pollfds(pollfds_ptr, pollfds)?;
        }
        return Ok(0);
    }
    let deadline = linux_mem::pending_poll_deadline(ctx.pid, ctx.instance_generation);
    let deadline = match deadline {
        Some(existing) => Some(existing),
        None if timeout_ms < 0 => None,
        None => {
            let now = monotonic_ns();
            let abs = monotonic_deadline_from_millis(now, timeout_ms as u64)?;
            let d = Deadline::MonotonicNs(abs);
            linux_mem::set_pending_poll_deadline(ctx.pid, ctx.instance_generation, Some(d));
            Some(d)
        }
    };
    if let Some(d) = deadline {
        if deadline_due(d) {
            if nfds > 0 {
                write_pollfds(pollfds_ptr, pollfds)?;
            }
            clear_poll_interest_for_pid(ctx.pid);
            linux_mem::set_pending_poll_deadline(ctx.pid, ctx.instance_generation, None);
            #[cfg(feature = "m9-linux-runtime-self-test")]
            if nfds == 0 && timeout_ms > 0 {
                let budget = sleep_budget_ns_from_millis(timeout_ms as u64)?;
                let block_start = monotonic_deadline_ns(d).saturating_sub(budget);
                crate::selftest::m9_linux_runtime::on_poll_timeout_complete_ns(
                    ctx.pid,
                    timeout_ms as u64,
                    block_start,
                );
            }
            return Ok(0);
        }
    }
    let result = block_linux_syscall(
        request,
        ctx,
        poll_wait_key(ctx.pid),
        deadline,
        LinuxTimeoutResult::Zero,
    );
    #[cfg(feature = "m9-linux-runtime-self-test")]
    if result == Ok(0) && nfds == 0 && timeout_ms > 0 {
        if let Some(d) = deadline {
            let budget = sleep_budget_ns_from_millis(timeout_ms as u64)?;
            let block_start = monotonic_deadline_ns(d).saturating_sub(budget);
            crate::selftest::m9_linux_runtime::on_poll_timeout_complete_ns(
                ctx.pid,
                timeout_ms as u64,
                block_start,
            );
        }
        linux_mem::set_pending_poll_deadline(ctx.pid, ctx.instance_generation, None);
    }
    result
}

fn fd_readiness(
    ctx: &mut LinuxSyscallContext<'_>,
    fd: i32,
    events: i16,
) -> Result<i16, LinuxErrno> {
    // Linux ignores negative fds in poll(2); do not set revents (BusyBox nslookup
    // uses placeholder nfds slots with fd=-1 alongside the real UDP socket).
    if fd < 0 {
        return Ok(0);
    }
    if linux_fd::ensure_open_fd(ctx.pid, ctx.instance_generation, fd as u64).is_err() {
        return Ok(POLLNVAL);
    }
    if (events & POLLIN) != 0 {
        let _ = crate::process::linux_socket::refresh_readiness_for_fd(ctx, fd as u64);
    }
    let readiness =
        match linux_fd::open_description_kind(ctx.pid, ctx.instance_generation, fd as u64) {
            Ok(crate::process::linux_fd::open_description::DescriptorKind::Socket(socket_ref)) => {
                crate::process::linux_socket::readiness_for(
                    crate::process::linux_socket::socket_ref_to_id(socket_ref),
                )
            }
            Ok(crate::process::linux_fd::open_description::DescriptorKind::Console(_)) => {
                console_readiness()
            }
            _ => Readiness::default(),
        };
    let mut revents = 0i16;
    if (events & POLLIN) != 0 && readiness.readable {
        revents |= POLLIN;
    }
    if (events & POLLOUT) != 0 && readiness.writable {
        revents |= POLLOUT;
    }
    if readiness.error {
        revents |= POLLERR;
    }
    if readiness.hangup {
        revents |= POLLHUP;
    }
    Ok(revents)
}

fn console_readiness() -> Readiness {
    Readiness {
        readable: false,
        writable: true,
        hangup: false,
        error: false,
    }
}

fn write_pollfds(ptr: u64, pollfds: &[PollFd]) -> Result<(), LinuxErrno> {
    let len = pollfds.len().checked_mul(USER_COPY_POLL).ok_or(EINVAL)?;
    validate_user_writable_pointer_range(ptr, len as u64).map_err(|_| EFAULT)?;
    for (index, pollfd) in pollfds.iter().enumerate() {
        let enc = encode_pollfd(*pollfd);
        let offset = (index as u64)
            .checked_mul(USER_COPY_POLL as u64)
            .ok_or(EINVAL)?;
        write_user(ptr.checked_add(offset).ok_or(EINVAL)?, &enc)?;
    }
    Ok(())
}

fn write_user(ptr: u64, bytes: &[u8]) -> Result<(), LinuxErrno> {
    validate_user_writable_pointer_range(ptr, bytes.len() as u64).map_err(|_| EFAULT)?;
    for (offset, byte) in bytes.iter().enumerate() {
        let addr = ptr.checked_add(offset as u64).ok_or(EFAULT)?;
        unsafe {
            *(addr as *mut u8) = *byte;
        }
    }
    Ok(())
}

fn read_u64(ptr: u64) -> Result<u64, LinuxErrno> {
    validate_user_pointer_range(ptr, 8).map_err(|_| EFAULT)?;
    Ok(unsafe { *(ptr as *const u64) })
}

fn write_zero_timespec(ptr: u64) -> Result<(), LinuxErrno> {
    write_user(ptr, &[0u8; 16])
}

#[cfg_attr(not(feature = "m9-linux-runtime-self-test"), allow(dead_code))]
fn monotonic_deadline_ns(deadline: Deadline) -> u64 {
    match deadline {
        Deadline::MonotonicNs(ns) => ns,
        Deadline::IrqTicks(_) => 0,
    }
}

fn deadline_due(deadline: Deadline) -> bool {
    match deadline {
        Deadline::MonotonicNs(ns) => monotonic_ns() >= ns,
        Deadline::IrqTicks(ticks) => kernel_ticks() >= ticks,
    }
}

fn write_remaining_timespec(ptr: u64, deadline: Deadline) -> Result<(), LinuxErrno> {
    let Deadline::MonotonicNs(deadline_ns) = deadline else {
        return Err(EINVAL);
    };
    let ts = timespec_from_remaining_ns(deadline_ns, monotonic_ns())?;
    let mut bytes = [0u8; 16];
    bytes[0..8].copy_from_slice(&ts.tv_sec.to_le_bytes());
    bytes[8..16].copy_from_slice(&ts.tv_nsec.to_le_bytes());
    write_user(ptr, &bytes)
}
