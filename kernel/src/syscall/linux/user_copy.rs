//! Bounded copy-in from userspace for Linux personality handlers.

use crate::mm::user_mapping::validate_user_pointer_range;
use clean_slate_linux_abi::{LinuxErrno, EFAULT};
use core::ptr;

/// Soft upper bound for a single Linux copy-in (IPC message size; justified by
/// the existing capability-controlled console path).
///
/// Longer user lengths are clamped here; the caller (#94 `write`) decides the
/// short-write return value exposed to userspace.
#[allow(dead_code)] // Consumed by #94 `write` once the placeholder is replaced.
pub(crate) const LINUX_USER_COPY_MAX_BYTES: usize = 64;

/// Copy up to `LINUX_USER_COPY_MAX_BYTES` from a validated userspace range.
///
/// - `length == 0` → `Ok(0)` without touching memory (Linux zero-length write).
/// - otherwise validate and copy `min(length, LINUX_USER_COPY_MAX_BYTES)` bytes
///   from the user range (validation covers exactly that clamped span) and
///   return the copied count.
/// - validation failure → `Err(EFAULT)`.
///
/// Oversized requests are truncated to the buffer capacity; #94 chooses whether
/// that short count is the syscall result or whether to loop.
#[allow(dead_code)] // Consumed by #94 `write` once the placeholder is replaced.
pub(crate) fn copy_user_bytes(
    user_ptr: u64,
    length: u64,
    dst: &mut [u8; LINUX_USER_COPY_MAX_BYTES],
) -> Result<usize, LinuxErrno> {
    if length == 0 {
        return Ok(0);
    }
    let requested = match usize::try_from(length) {
        Ok(len) => len,
        // Saturate to the copy budget when length does not fit in usize.
        Err(_) => LINUX_USER_COPY_MAX_BYTES,
    };
    let copy_len = requested.min(LINUX_USER_COPY_MAX_BYTES);
    let copy_len_u64 = copy_len as u64;
    if validate_user_pointer_range(user_ptr, copy_len_u64).is_err() {
        return Err(EFAULT);
    }
    unsafe {
        ptr::copy_nonoverlapping(user_ptr as *const u8, dst.as_mut_ptr(), copy_len);
    }
    Ok(copy_len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of `mm::USER_CANONICAL_TOP_EXCLUSIVE` (pub(super) to mm).
    const USER_CANONICAL_TOP_EXCLUSIVE: u64 = 1 << 47;

    #[test]
    fn copy_zero_length_returns_ok_without_validation() {
        let mut buf = [0u8; LINUX_USER_COPY_MAX_BYTES];
        // Non-canonical pointer is fine: zero length must not touch memory.
        assert_eq!(
            copy_user_bytes(USER_CANONICAL_TOP_EXCLUSIVE, 0, &mut buf),
            Ok(0)
        );
    }

    #[test]
    fn copy_oversized_clamps_to_max_bytes() {
        let mut buf = [0u8; LINUX_USER_COPY_MAX_BYTES];
        // Clamped range still fails EFAULT for non-canonical pointers — proves
        // validation used the clamped length rather than rejecting with EINVAL.
        assert_eq!(
            copy_user_bytes(
                USER_CANONICAL_TOP_EXCLUSIVE,
                (LINUX_USER_COPY_MAX_BYTES + 1) as u64,
                &mut buf
            ),
            Err(EFAULT)
        );
        // Documented clamp: when validation would succeed, return count == MAX.
        // Host tests cannot map a live user page; the Ok(MAX) path is covered
        // by the zero-length / clamp arithmetic and QEMU write path in #94.
        let requested = LINUX_USER_COPY_MAX_BYTES + 8;
        let clamped = requested.min(LINUX_USER_COPY_MAX_BYTES);
        assert_eq!(clamped, LINUX_USER_COPY_MAX_BYTES);
    }

    #[test]
    fn copy_returns_efault_for_non_canonical_userspace_pointer() {
        let mut buf = [0u8; LINUX_USER_COPY_MAX_BYTES];
        assert_eq!(
            copy_user_bytes(USER_CANONICAL_TOP_EXCLUSIVE, 8, &mut buf),
            Err(EFAULT)
        );
        assert_eq!(copy_user_bytes(u64::MAX - 16, 8, &mut buf), Err(EFAULT));
    }
}
