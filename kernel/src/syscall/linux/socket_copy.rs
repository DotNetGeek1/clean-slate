//! Bounded user copies for the socket family (#105).

use crate::mm::user_mapping::validate_user_pointer_range;
use clean_slate_linux_abi::{LinuxErrno, EFAULT};

pub(crate) fn copy_user_socket_bytes(
    user_ptr: u64,
    length: usize,
    dst: &mut [u8],
) -> Result<(), LinuxErrno> {
    if length == 0 {
        return Ok(());
    }
    if length > dst.len() {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    if validate_user_pointer_range(user_ptr, length as u64).is_err() {
        return Err(EFAULT);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(user_ptr as *const u8, dst.as_mut_ptr(), length);
    }
    Ok(())
}
