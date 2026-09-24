//! Linux errno values and RAX result encoding.
//!
//! Linux returns success as a non-negative value in RAX, and failures as the
//! two's-complement representation of `-errno` (i.e. values in `[-4095, -1]`
//! when interpreted as signed `i64`).
//!
//! Clean-Slate native syscalls use a separate sentinel encoding
//! (`SYSCALL_ENOSYS = u64::MAX - 37`, etc.). Those patterns must never be
//! constructed or interpreted through [`LinuxErrno`] / [`encode_rax`] /
//! [`decode_rax`]. The type system keeps the spaces apart: native code uses
//! raw `u64` sentinels; Linux personality code uses [`LinuxSyscallResult`].

/// Linux errno as a positive `i32` (the magnitude used in `-errno`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct LinuxErrno(pub i32);

/// Operation not permitted.
pub const EPERM: LinuxErrno = LinuxErrno(1);
/// No such file or directory.
pub const ENOENT: LinuxErrno = LinuxErrno(2);
/// No such process.
pub const ESRCH: LinuxErrno = LinuxErrno(3);
/// Bad file descriptor.
pub const EBADF: LinuxErrno = LinuxErrno(9);
/// Exec format error.
pub const ENOEXEC: LinuxErrno = LinuxErrno(8);
/// Cannot allocate memory.
pub const ENOMEM: LinuxErrno = LinuxErrno(12);
/// Permission denied.
pub const EACCES: LinuxErrno = LinuxErrno(13);
/// Bad address.
pub const EFAULT: LinuxErrno = LinuxErrno(14);
/// Invalid argument.
pub const EINVAL: LinuxErrno = LinuxErrno(22);
/// Too many open files in system.
pub const ENFILE: LinuxErrno = LinuxErrno(23);
/// Too many open files.
pub const EMFILE: LinuxErrno = LinuxErrno(24);
/// Function not implemented.
pub const ENOSYS: LinuxErrno = LinuxErrno(38);
/// Interrupted system call (#102).
pub const EINTR: LinuxErrno = LinuxErrno(4);
/// Argument list too long (#102).
pub const E2BIG: LinuxErrno = LinuxErrno(7);
/// No child processes (#102).
pub const ECHILD: LinuxErrno = LinuxErrno(10);
/// Try again (#102).
pub const EAGAIN: LinuxErrno = LinuxErrno(11);
/// Broken pipe (#102).
pub const EPIPE: LinuxErrno = LinuxErrno(32);
/// No space left on device.
pub const ENOSPC: LinuxErrno = LinuxErrno(28);
/// Stale file handle (#105).
pub const ESTALE: LinuxErrno = LinuxErrno(116);

/// Maximum magnitude Linux treats as an errno when decoding RAX (`-1` … `-4095`).
pub const LINUX_ERRNO_MAX: i32 = 4095;

impl LinuxErrno {
    /// Returns the positive errno magnitude, or `None` if out of the Linux range.
    pub const fn as_i32(self) -> i32 {
        self.0
    }

    /// Constructs an errno if `code` is in `1..=LINUX_ERRNO_MAX`.
    pub const fn from_positive(code: i32) -> Option<Self> {
        if code >= 1 && code <= LINUX_ERRNO_MAX {
            Some(Self(code))
        } else {
            None
        }
    }
}

/// Linux syscall result carried in RAX after encoding.
pub type LinuxSyscallResult = Result<u64, LinuxErrno>;

/// Encode a Linux syscall result as the `u64` value written to RAX.
///
/// Errors become `(-errno) as i64 as u64` (two's complement).
pub const fn encode_rax(result: LinuxSyscallResult) -> u64 {
    match result {
        Ok(value) => value,
        Err(LinuxErrno(code)) => (-(code as i64)) as u64,
    }
}

/// Decode a RAX value using the Linux rule: values in `[-4095, -1]` are errors.
pub const fn decode_rax(rax: u64) -> LinuxSyscallResult {
    let signed = rax as i64;
    if signed >= -LINUX_ERRNO_MAX as i64 && signed <= -1 {
        Err(LinuxErrno((-signed) as i32))
    } else {
        Ok(rax)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Native sentinel from `kernel/src/syscall/mod.rs` / capability `syscall_abi`.
    /// Documented here only to prove the bit pattern coincidence — never mix encodings.
    const NATIVE_SYSCALL_ENOSYS: u64 = u64::MAX - 37;

    #[test]
    fn encode_decode_round_trip_success() {
        assert_eq!(encode_rax(Ok(0)), 0);
        assert_eq!(decode_rax(0), Ok(0));
        assert_eq!(encode_rax(Ok(42)), 42);
        assert_eq!(decode_rax(42), Ok(42));
    }

    #[test]
    fn encode_decode_round_trip_errors() {
        for err in [
            EPERM, ENOENT, ESRCH, EBADF, ENOMEM, EACCES, EFAULT, EINVAL, ENOSYS,
        ] {
            let encoded = encode_rax(Err(err));
            assert_eq!(decode_rax(encoded), Err(err));
            assert_eq!(encoded, (-(err.0 as i64)) as u64);
        }
    }

    #[test]
    fn enosys_is_negative_thirty_eight() {
        let encoded = encode_rax(Err(ENOSYS));
        assert_eq!(encoded as i64, -38);
        assert_eq!(decode_rax(encoded), Err(ENOSYS));
    }

    #[test]
    fn native_enosys_sentinel_is_not_a_linux_encoding_path() {
        // By coincidence of shape, the native bit pattern `u64::MAX - 37` equals
        // `(-38) as u64`, so Linux `decode_rax` would report Err(ENOSYS). That is
        // ONLY a numeric coincidence: the two ABI spaces are never mixed. Native
        // dispatch uses raw sentinel constants; Linux dispatch uses
        // `LinuxSyscallResult` + `encode_rax`/`decode_rax`. Personality routing
        // (#93) selects which space applies before interpreting RAX.
        assert_eq!(NATIVE_SYSCALL_ENOSYS, (-38i64) as u64);
        assert_eq!(decode_rax(NATIVE_SYSCALL_ENOSYS), Err(ENOSYS));
        assert_eq!(encode_rax(Err(ENOSYS)), NATIVE_SYSCALL_ENOSYS);
        // Native success/error discrimination is NOT the Linux [-4095,-1] rule.
        // Example: native SYSCALL_EINVAL = u64::MAX - 21 is also in that range
        // if mis-decoded as Linux, which is why personality must gate decoding.
        let native_einval = u64::MAX - 21;
        assert_eq!(decode_rax(native_einval), Err(EINVAL));
    }

    #[test]
    fn values_outside_errno_window_are_success() {
        // -4096 is just outside the Linux errno window.
        assert_eq!(decode_rax((-4096i64) as u64), Ok((-4096i64) as u64));
        // Large positive success values stay success.
        assert_eq!(decode_rax(4096), Ok(4096));
        assert_eq!(decode_rax(u64::MAX / 2), Ok(u64::MAX / 2));
    }
}
