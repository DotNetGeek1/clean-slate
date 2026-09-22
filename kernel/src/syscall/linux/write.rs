//! Linux `write(2)` (nr 1) for the `LinuxX86_64` personality (#94).
//!
//! `write(fd, buf, count)` is a projection onto the capability-controlled
//! console path built by #95: the fd integer is resolved through
//! [`crate::process::linux_fd`] for the trusted `(pid, generation)` carried in
//! [`LinuxSyscallContext`], and every byte reaches serial through
//! `IpcEndpointTable::send_message`. There is no kernel serial shortcut.
//!
//! # Semantics (decided here, documented in docs/LINUX_PERSONALITY.md)
//!
//! 1. fd is resolved **first** (Linux `fdget_pos` ordering): an unmapped,
//!    closed, stale-generation or unowned fd yields `EBADF` even when the
//!    buffer pointer is invalid or `count == 0`.
//! 2. `count == 0` → `Ok(0)` without touching user memory or the endpoint.
//! 3. The request is delivered in chunks of [`LINUX_WRITE_CHUNK_BYTES`]
//!    (= `LINUX_USER_COPY_MAX_BYTES` = `IPC_MAX_MESSAGE_BYTES` = 64), each
//!    chunk copied in through `copy_user_bytes` (live page-table validation)
//!    and then sent through the fd projection. The loop is bounded by
//!    [`LINUX_WRITE_MAX_CHUNKS`]; a request longer than
//!    [`LINUX_WRITE_MAX_BYTES`] is a **short write** of exactly that many
//!    bytes (never `EINVAL`, never an unbounded spin). A conforming caller
//!    loops on short writes.
//! 4. A fault or delivery error on the **first** chunk is reported as the
//!    errno (`EFAULT` / `EBADF` / `EACCES`). A failure on a **later** chunk
//!    returns the bytes already delivered (Linux partial-write semantics).
//! 5. The returned count always equals the bytes actually delivered to the
//!    sink and never exceeds `count`.
//!
//! The chunk loop is a pure function over two injected primitives (`fetch`
//! and `deliver`) so host tests cover ordering, chunking, partial-write and
//! errno behaviour without a live user mapping or global state.

use super::table::LinuxSyscallContext;
use super::user_copy::{copy_user_bytes, LINUX_USER_COPY_MAX_BYTES};
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
use crate::mm::PAGE_SIZE;
use crate::process::linux_fd::{self, LinuxFdProjection};
use clean_slate_linux_abi::{
    LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EBADF, EFAULT, EINVAL,
};

/// One copy-in + one IPC send per chunk. Equal to both the user-copy budget
/// and the IPC payload limit so a fetched chunk is never short-written by the
/// fd projection's own clamp (asserted at compile time below).
pub(crate) const LINUX_WRITE_CHUNK_BYTES: usize = LINUX_USER_COPY_MAX_BYTES;

/// Upper bound on bytes one `write` call delivers (one page).
///
/// Justification: a page is the granularity at which `copy_user_bytes`
/// validates user ranges, and Linux permits any short write, so bounding a
/// single call at one page keeps the per-syscall IPC/serial work at
/// [`LINUX_WRITE_MAX_CHUNKS`] sends while letting a conforming caller (libc
/// `write` loops on short counts) complete arbitrarily long output. Requests
/// above this bound are truncated to it as a short write, not rejected.
pub(crate) const LINUX_WRITE_MAX_BYTES: usize = PAGE_SIZE as usize;

/// Hard iteration bound of the chunk loop, derived from the two constants above.
pub(crate) const LINUX_WRITE_MAX_CHUNKS: usize = LINUX_WRITE_MAX_BYTES / LINUX_WRITE_CHUNK_BYTES;

const _: () = assert!(
    LINUX_USER_COPY_MAX_BYTES == IPC_MAX_MESSAGE_BYTES,
    "write chunking assumes the user-copy budget equals the IPC payload limit"
);
const _: () = assert!(
    LINUX_WRITE_MAX_BYTES % LINUX_WRITE_CHUNK_BYTES == 0 && LINUX_WRITE_MAX_CHUNKS > 0,
    "write bound must be a whole number of chunks"
);

/// Map an fd projection lookup onto Linux `write` fd validity.
///
/// `Closed` is a valid table slot that is not open → `EBADF`, same as an
/// out-of-range fd, a missing table or a stale generation.
pub(crate) fn ensure_fd_open(
    projection: Result<LinuxFdProjection, LinuxErrno>,
) -> Result<(), LinuxErrno> {
    match projection? {
        LinuxFdProjection::Closed => Err(EBADF),
        LinuxFdProjection::ConsoleEndpoint { .. } => Ok(()),
    }
}

/// Clamp the user-requested `count` to the documented single-call bound.
///
/// Not a silent saturation: the clamped value is exactly the short-write count
/// returned to userspace when every chunk succeeds.
pub(crate) const fn clamp_write_count(count: u64) -> usize {
    if count > LINUX_WRITE_MAX_BYTES as u64 {
        LINUX_WRITE_MAX_BYTES
    } else {
        // Fits by construction: `count <= LINUX_WRITE_MAX_BYTES <= usize::MAX`.
        count as usize
    }
}

/// Pure bounded chunk loop shared by the production handler and host tests.
///
/// - `fetch(offset, len, dst)` copies exactly `len` (`1..=CHUNK`) bytes from
///   request offset `offset` into `dst[..len]`, or fails with an errno.
/// - `deliver(chunk)` sends one non-empty chunk and returns the bytes sent
///   (`<= chunk.len()`), or fails with an errno.
///
/// The caller must already have validated the fd (see [`ensure_fd_open`]) so
/// `EBADF` takes precedence over any fault reported by `fetch`.
pub(crate) fn write_chunked(
    count: u64,
    mut fetch: impl FnMut(u64, usize, &mut [u8; LINUX_WRITE_CHUNK_BYTES]) -> Result<usize, LinuxErrno>,
    mut deliver: impl FnMut(&[u8]) -> Result<usize, LinuxErrno>,
) -> LinuxSyscallResult {
    if count == 0 {
        return Ok(0);
    }
    let total = clamp_write_count(count);
    let mut written = 0usize;
    let mut chunk = [0u8; LINUX_WRITE_CHUNK_BYTES];
    // `for` over a fixed range keeps the loop bounded even if a primitive
    // misbehaves; `written` strictly increases on every continued iteration.
    for _ in 0..LINUX_WRITE_MAX_CHUNKS {
        if written >= total {
            break;
        }
        let want = (total - written).min(LINUX_WRITE_CHUNK_BYTES);
        let fetched = match fetch(written as u64, want, &mut chunk) {
            Ok(fetched) => fetched,
            Err(errno) => return partial_or_error(written, errno),
        };
        if fetched != want {
            // The fetch primitive must copy exactly what was asked; anything
            // else is a kernel invariant violation. Fail closed.
            return partial_or_error(written, EINVAL);
        }
        let sent = match deliver(&chunk[..fetched]) {
            Ok(sent) => sent,
            Err(errno) => return partial_or_error(written, errno),
        };
        if sent > fetched {
            // Never report more than was handed to the sink.
            return partial_or_error(written, EINVAL);
        }
        written += sent;
        if sent < fetched {
            // Sink accepted a short chunk: Linux returns the partial count.
            break;
        }
    }
    Ok(written as u64)
}

/// Linux partial-write rule: an error after some bytes were delivered reports
/// the delivered count; an error before any byte reports the errno.
fn partial_or_error(written: usize, errno: LinuxErrno) -> LinuxSyscallResult {
    if written == 0 {
        Err(errno)
    } else {
        Ok(written as u64)
    }
}

/// Host-testable composition over injected fd registry / endpoint table.
///
/// `bytes` stands in for the user buffer (already in kernel memory); the
/// production handler uses `copy_user_bytes` instead. Mirrors
/// [`handle_sys_write`] step for step so tests prove the same ordering.
#[cfg(test)]
pub(crate) fn write_with(
    registry: &mut linux_fd::LinuxFdRegistry,
    ipc: &mut crate::ipc::IpcEndpointTable,
    pid: u64,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    fd: u64,
    bytes: &[u8],
    personality: crate::process::personality::ExecutionPersonality,
) -> LinuxSyscallResult {
    ensure_fd_open(registry.projection_for(pid, generation, fd))?;
    write_chunked(
        bytes.len() as u64,
        |offset, len, dst| {
            let start = offset as usize;
            dst[..len].copy_from_slice(&bytes[start..start + len]);
            Ok(len)
        },
        |chunk| registry.write_fd(ipc, pid, generation, fd, chunk, personality),
    )
}

/// Production `write` handler: `rdi = fd`, `rsi = buf`, `rdx = count`.
///
/// Result is encoded into RAX by `dispatch_with` (`encode_rax`); this function
/// never encodes.
pub(crate) fn handle_sys_write(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let user_ptr = request.args[1];
    let count = request.args[2];
    let pid = ctx.pid;
    let generation = ctx.instance_generation;

    // 1. fd first: EBADF beats EFAULT and beats the zero-length shortcut.
    ensure_fd_open(linux_fd::projection_for(pid, generation, fd))?;

    // 2./3./4. bounded copy-in + capability-controlled delivery per chunk.
    write_chunked(
        count,
        |offset, len, dst| {
            let chunk_ptr = user_ptr.checked_add(offset).ok_or(EFAULT)?;
            copy_user_bytes(chunk_ptr, len as u64, dst)
        },
        |chunk| {
            let sent = linux_fd::write_fd(pid, generation, fd, chunk)?;
            #[cfg(feature = "m8-linux-dispatch-self-test")]
            crate::selftest::m8_linux_dispatch::observe_linux_delivered_chunk(
                pid,
                fd,
                &chunk[..sent.min(chunk.len())],
            );
            #[cfg(feature = "m8-linux-hello-self-test")]
            crate::service::linux_launch::note_linux_hello_delivered_bytes(sent.min(chunk.len()));
            Ok(sent)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcEndpointTable;
    use crate::process::linux_fd::{LinuxFdRegistry, LINUX_STDERR_FD, LINUX_STDOUT_FD};
    use crate::process::personality::ExecutionPersonality;
    use clean_slate_linux_abi::EACCES;
    use clean_slate_service_lifecycle::InstanceGeneration;

    const LINUX: ExecutionPersonality = ExecutionPersonality::LinuxX86_64;

    /// Mirror of `mm::USER_CANONICAL_TOP_EXCLUSIVE`: first non-canonical user VA.
    const NON_CANONICAL_USER_PTR: u64 = 1 << 47;

    fn linux_process(
        pid: u64,
        generation: InstanceGeneration,
    ) -> (LinuxFdRegistry, IpcEndpointTable) {
        let mut fds = LinuxFdRegistry::new();
        let mut ipc = IpcEndpointTable::new();
        let handle = ipc
            .grant_console_capability_for_pid(pid)
            .expect("console grant");
        fds.install(pid, generation, handle, handle)
            .expect("install stdio");
        (fds, ipc)
    }

    #[test]
    fn constants_are_derived_and_consistent() {
        assert_eq!(LINUX_WRITE_CHUNK_BYTES, 64);
        assert_eq!(LINUX_WRITE_CHUNK_BYTES, IPC_MAX_MESSAGE_BYTES);
        assert_eq!(LINUX_WRITE_MAX_BYTES, 4096);
        assert_eq!(LINUX_WRITE_MAX_CHUNKS, 64);
        assert_eq!(clamp_write_count(0), 0);
        assert_eq!(clamp_write_count(18), 18);
        assert_eq!(
            clamp_write_count(LINUX_WRITE_MAX_BYTES as u64),
            LINUX_WRITE_MAX_BYTES
        );
        assert_eq!(
            clamp_write_count(LINUX_WRITE_MAX_BYTES as u64 + 1),
            LINUX_WRITE_MAX_BYTES
        );
        assert_eq!(clamp_write_count(u64::MAX), LINUX_WRITE_MAX_BYTES);
    }

    #[test]
    fn write_stdout_delivers_exact_bytes_and_count() {
        let generation = InstanceGeneration(3);
        let (mut fds, mut ipc) = linux_process(10, generation);
        let message = b"Hello from Linux.\n";
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                10,
                generation,
                LINUX_STDOUT_FD,
                message,
                LINUX
            ),
            Ok(18)
        );
        assert_eq!(ipc.endpoint_message(0), Some(&message[..]));
    }

    #[test]
    fn write_stderr_delivers_through_same_console_projection() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = linux_process(11, generation);
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                11,
                generation,
                LINUX_STDERR_FD,
                b"err\n",
                LINUX
            ),
            Ok(4)
        );
        assert_eq!(ipc.endpoint_message(0), Some(&b"err\n"[..]));
    }

    #[test]
    fn write_ebadf_for_unmapped_closed_stale_and_missing() {
        let generation = InstanceGeneration(2);
        let (mut fds, mut ipc) = linux_process(12, generation);
        // fd 0 is Closed, fd 3 is Closed (spare), fd 99 is out of range.
        for fd in [0u64, 3, 99, u64::MAX] {
            assert_eq!(
                write_with(&mut fds, &mut ipc, 12, generation, fd, b"x", LINUX),
                Err(EBADF),
                "fd {fd}"
            );
        }
        // Stale generation for a live pid.
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                12,
                InstanceGeneration(99),
                LINUX_STDOUT_FD,
                b"x",
                LINUX
            ),
            Err(EBADF)
        );
        // Pid with no table at all.
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                77,
                generation,
                LINUX_STDOUT_FD,
                b"x",
                LINUX
            ),
            Err(EBADF)
        );
        // Nothing reached the sink.
        assert_eq!(ipc.endpoint_message(0), Some(&b""[..]));
    }

    #[test]
    fn write_unowned_handle_is_rejected_by_endpoint_table() {
        let generation = InstanceGeneration(1);
        let mut fds = LinuxFdRegistry::new();
        let mut ipc = IpcEndpointTable::new();
        let foreign = ipc
            .grant_console_capability_for_pid(50)
            .expect("grant to other pid");
        fds.install(51, generation, foreign, foreign)
            .expect("install");
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                51,
                generation,
                LINUX_STDOUT_FD,
                b"secret",
                LINUX
            ),
            Err(EACCES)
        );
        assert_eq!(ipc.endpoint_message(0), Some(&b""[..]));
    }

    #[test]
    fn write_after_release_fails_closed() {
        let generation = InstanceGeneration(4);
        let (mut fds, mut ipc) = linux_process(13, generation);
        fds.release(13, generation);
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                13,
                generation,
                LINUX_STDOUT_FD,
                b"late",
                LINUX
            ),
            Err(EBADF)
        );
    }

    #[test]
    fn zero_length_write_is_ok_zero_without_touching_memory_or_sink() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = linux_process(14, generation);
        assert_eq!(
            write_with(
                &mut fds,
                &mut ipc,
                14,
                generation,
                LINUX_STDOUT_FD,
                b"",
                LINUX
            ),
            Ok(0)
        );
        assert_eq!(ipc.endpoint_message(0), Some(&b""[..]));

        // Through the pure loop with a bogus pointer: fetch must never run.
        let result = write_chunked(
            0,
            |_, _, _| panic!("fetch must not run for count == 0"),
            |_| panic!("deliver must not run for count == 0"),
        );
        assert_eq!(result, Ok(0));
    }

    #[test]
    fn ebadf_takes_precedence_over_efault() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = linux_process(15, generation);
        // Bad fd + a fetch that would fault: fd check wins before any copy.
        let fd_check = ensure_fd_open(fds.projection_for(15, generation, 7));
        assert_eq!(fd_check, Err(EBADF));
        let mut fetch_calls = 0;
        let result = fd_check.and_then(|()| {
            write_chunked(
                8,
                |_, _, _| {
                    fetch_calls += 1;
                    Err(EFAULT)
                },
                |chunk| fds.write_fd(&mut ipc, 15, generation, 7, chunk, LINUX),
            )
        });
        assert_eq!(result, Err(EBADF));
        assert_eq!(fetch_calls, 0);
    }

    #[test]
    fn zero_length_write_to_bad_fd_is_ebadf() {
        // Linux resolves the fd before looking at count.
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = linux_process(16, generation);
        assert_eq!(
            write_with(&mut fds, &mut ipc, 16, generation, 0, b"", LINUX),
            Err(EBADF)
        );
    }

    #[test]
    fn efault_on_first_chunk_reports_errno() {
        let result = write_chunked(
            8,
            |_, _, _| Err(EFAULT),
            |_| panic!("deliver must not run when the first fetch faults"),
        );
        assert_eq!(result, Err(EFAULT));
    }

    #[test]
    fn efault_on_later_chunk_returns_partial_count() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = linux_process(17, generation);
        let result = write_chunked(
            (LINUX_WRITE_CHUNK_BYTES * 3) as u64,
            |offset, len, dst| {
                if offset >= LINUX_WRITE_CHUNK_BYTES as u64 * 2 {
                    Err(EFAULT)
                } else {
                    dst[..len].fill(b'a');
                    Ok(len)
                }
            },
            |chunk| fds.write_fd(&mut ipc, 17, generation, LINUX_STDOUT_FD, chunk, LINUX),
        );
        assert_eq!(result, Ok((LINUX_WRITE_CHUNK_BYTES * 2) as u64));
    }

    #[test]
    fn real_handler_efault_for_non_canonical_pointer_with_count() {
        // Exercise the production copy-in closure shape via copy_user_bytes:
        // validate_user_pointer_range rejects non-canonical VAs before any
        // page walk, so this is host-safe.
        let result = write_chunked(
            8,
            |offset, len, dst| {
                let ptr = NON_CANONICAL_USER_PTR.checked_add(offset).ok_or(EFAULT)?;
                copy_user_bytes(ptr, len as u64, dst)
            },
            |_| panic!("deliver must not run after EFAULT"),
        );
        assert_eq!(result, Err(EFAULT));
        // Pointer arithmetic overflow is also EFAULT, not a wrap.
        let result = write_chunked(
            8,
            |offset, len, dst| {
                let ptr = u64::MAX.checked_add(offset + 1).ok_or(EFAULT)?;
                copy_user_bytes(ptr, len as u64, dst)
            },
            |_| panic!("deliver must not run after EFAULT"),
        );
        assert_eq!(result, Err(EFAULT));
    }

    #[test]
    fn long_write_is_chunked_and_count_matches_delivery() {
        let generation = InstanceGeneration(1);
        let (mut fds, mut ipc) = linux_process(18, generation);
        let mut payload = [0u8; LINUX_WRITE_CHUNK_BYTES * 2 + 10];
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte = b'A' + (index % 26) as u8;
        }
        let mut delivered_total = 0usize;
        let mut deliveries = 0usize;
        let result = write_chunked(
            payload.len() as u64,
            |offset, len, dst| {
                let start = offset as usize;
                dst[..len].copy_from_slice(&payload[start..start + len]);
                Ok(len)
            },
            |chunk| {
                deliveries += 1;
                let sent = fds.write_fd(&mut ipc, 18, generation, LINUX_STDOUT_FD, chunk, LINUX)?;
                delivered_total += sent;
                Ok(sent)
            },
        );
        assert_eq!(result, Ok(payload.len() as u64));
        assert_eq!(delivered_total, payload.len());
        assert_eq!(deliveries, 3);
        // Last chunk (10 bytes) is what the sink holds now.
        assert_eq!(
            ipc.endpoint_message(0),
            Some(&payload[LINUX_WRITE_CHUNK_BYTES * 2..])
        );
    }

    #[test]
    fn oversized_request_is_short_write_at_documented_bound() {
        let mut fetches = 0usize;
        let mut delivered = 0usize;
        let result = write_chunked(
            (LINUX_WRITE_MAX_BYTES * 3) as u64,
            |_, len, dst| {
                fetches += 1;
                dst[..len].fill(b'z');
                Ok(len)
            },
            |chunk| {
                delivered += chunk.len();
                Ok(chunk.len())
            },
        );
        assert_eq!(result, Ok(LINUX_WRITE_MAX_BYTES as u64));
        assert_eq!(delivered, LINUX_WRITE_MAX_BYTES);
        assert_eq!(fetches, LINUX_WRITE_MAX_CHUNKS);
    }

    #[test]
    fn short_delivery_stops_loop_and_reports_partial_count() {
        let result = write_chunked(
            (LINUX_WRITE_CHUNK_BYTES * 2) as u64,
            |_, len, dst| {
                dst[..len].fill(b'q');
                Ok(len)
            },
            |chunk| Ok(chunk.len() / 2),
        );
        assert_eq!(result, Ok((LINUX_WRITE_CHUNK_BYTES / 2) as u64));
    }

    #[test]
    fn misbehaving_primitives_fail_closed_never_over_report() {
        // fetch returning fewer bytes than asked.
        assert_eq!(
            write_chunked(8, |_, _, _| Ok(1), |_| panic!("no delivery")),
            Err(EINVAL)
        );
        // deliver claiming more than handed over.
        assert_eq!(
            write_chunked(
                8,
                |_, len, dst| {
                    dst[..len].fill(1);
                    Ok(len)
                },
                |chunk| Ok(chunk.len() + 1)
            ),
            Err(EINVAL)
        );
        // Same misbehaviour after a good chunk reports only the good bytes.
        let mut calls = 0;
        assert_eq!(
            write_chunked(
                (LINUX_WRITE_CHUNK_BYTES * 2) as u64,
                |_, len, dst| {
                    dst[..len].fill(1);
                    Ok(len)
                },
                |chunk| {
                    calls += 1;
                    if calls == 1 {
                        Ok(chunk.len())
                    } else {
                        Ok(chunk.len() + 1)
                    }
                }
            ),
            Ok(LINUX_WRITE_CHUNK_BYTES as u64)
        );
    }

    #[test]
    fn delivery_error_after_partial_returns_partial_and_before_returns_errno() {
        let mut calls = 0;
        let result = write_chunked(
            (LINUX_WRITE_CHUNK_BYTES * 2) as u64,
            |_, len, dst| {
                dst[..len].fill(1);
                Ok(len)
            },
            |chunk| {
                calls += 1;
                if calls == 1 {
                    Ok(chunk.len())
                } else {
                    Err(EACCES)
                }
            },
        );
        assert_eq!(result, Ok(LINUX_WRITE_CHUNK_BYTES as u64));
        assert_eq!(
            write_chunked(
                8,
                |_, len, dst| {
                    dst[..len].fill(1);
                    Ok(len)
                },
                |_| Err(EACCES)
            ),
            Err(EACCES)
        );
    }
}
