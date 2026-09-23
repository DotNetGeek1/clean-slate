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

/// Maximum magnitude Linux treats as an errno when decoding RAX (`-1` … `-4095`).
pub const LINUX_ERRNO_MAX: i32 = 4095;

const fn in_i32_range(value: i32, lo: i32, hi: i32) -> bool {
    if value < lo {
        return false;
    }
    value <= hi
}

const fn in_linux_negative_errno_range(signed: i64) -> bool {
    let lo = -(LINUX_ERRNO_MAX as i64);
    signed >= lo && signed <= -1
}

impl LinuxErrno {
    /// Returns the positive errno magnitude, or `None` if out of the Linux range.
    pub const fn as_i32(self) -> i32 {
        self.0
    }

    /// Constructs an errno if `code` is in `1..=LINUX_ERRNO_MAX`.
    pub const fn from_positive(code: i32) -> Option<Self> {
        if in_i32_range(code, 1, LINUX_ERRNO_MAX) {
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
    if in_linux_negative_errno_range(signed) {
        Err(LinuxErrno((-signed) as i32))
    } else {
        Ok(rax)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        assert_eq!(decode_rax(encode_rax(Ok(42))), Ok(42));
        assert_eq!(decode_rax(encode_rax(Err(EINVAL))), Err(EINVAL));
    }

    #[test]
    fn from_positive_bounds() {
        assert_eq!(LinuxErrno::from_positive(0), None);
        assert_eq!(LinuxErrno::from_positive(1), Some(LinuxErrno(1)));
        assert_eq!(
            LinuxErrno::from_positive(LINUX_ERRNO_MAX),
            Some(LinuxErrno(LINUX_ERRNO_MAX))
        );
        assert_eq!(LinuxErrno::from_positive(LINUX_ERRNO_MAX + 1), None);
    }
}
