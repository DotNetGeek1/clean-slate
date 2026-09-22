//! Bounded copy-in from userspace for Linux personality handlers.

use crate::mm::user_mapping::validate_user_pointer_range;
use clean_slate_linux_abi::{LinuxErrno, EFAULT, EINVAL};
use core::ptr;

/// Soft upper bound for a single Linux copy-in (IPC message size; justified by
/// the existing capability-controlled console path).
#[allow(dead_code)] // Consumed by #94 `write` once the placeholder is replaced.
pub(crate) const LINUX_USER_COPY_MAX_BYTES: usize = 64;

/// Copy up to `LINUX_USER_COPY_MAX_BYTES` from a validated userspace range.
///
/// Returns `Err(EFAULT)` when the pointer range fails
/// [`validate_user_pointer_range`], and `Err(EINVAL)` for a zero or oversized
/// length. On success, returns the number of bytes copied into `dst`.
#[allow(dead_code)] // Consumed by #94 `write` once the placeholder is replaced.
pub(crate) fn copy_user_bytes(
    user_ptr: u64,
    length: u64,
    dst: &mut [u8; LINUX_USER_COPY_MAX_BYTES],
) -> Result<usize, LinuxErrno> {
    let len = match usize::try_from(length) {
        Ok(len) => len,
        Err(_) => return Err(EINVAL),
    };
    if len == 0 || len > LINUX_USER_COPY_MAX_BYTES {
        return Err(EINVAL);
    }
    if validate_user_pointer_range(user_ptr, length).is_err() {
        return Err(EFAULT);
    }
    unsafe {
        ptr::copy_nonoverlapping(user_ptr as *const u8, dst.as_mut_ptr(), len);
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirror of `mm::USER_CANONICAL_TOP_EXCLUSIVE` (pub(super) to mm).
    const USER_CANONICAL_TOP_EXCLUSIVE: u64 = 1 << 47;

    #[test]
    fn copy_rejects_zero_and_oversized_length() {
        let mut buf = [0u8; LINUX_USER_COPY_MAX_BYTES];
        assert_eq!(copy_user_bytes(0x1000, 0, &mut buf), Err(EINVAL));
        assert_eq!(
            copy_user_bytes(0x1000, (LINUX_USER_COPY_MAX_BYTES + 1) as u64, &mut buf),
            Err(EINVAL)
        );
    }

    #[test]
    fn copy_returns_efault_for_non_canonical_userspace_pointer() {
        let mut buf = [0u8; LINUX_USER_COPY_MAX_BYTES];
        // Kernel-half canonical addresses fail before a page walk.
        assert_eq!(
            copy_user_bytes(USER_CANONICAL_TOP_EXCLUSIVE, 8, &mut buf),
            Err(EFAULT)
        );
        assert_eq!(copy_user_bytes(u64::MAX - 16, 8, &mut buf), Err(EFAULT));
    }
}
