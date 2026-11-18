//! Bounded user copies for the socket family (#105).

use crate::mm::user_access::copy_from_user;
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
    copy_from_user(&mut dst[..length], user_ptr).map_err(|_| EFAULT)
}
