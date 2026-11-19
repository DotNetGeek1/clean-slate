//! User `sockaddr_in` validation (kernel side).

use clean_slate_linux_abi::{LinuxErrno, SockaddrIn, EFAULT, EINVAL, SOCKADDR_IN_LEN};

use crate::mm::user_access::{copy_from_user, copy_to_user, write_user};
use crate::mm::user_mapping::validate_user_writable_pointer_range;
pub(crate) fn read_sockaddr_in(ptr: u64, socklen: u32) -> Result<SockaddrIn, LinuxErrno> {
    if socklen != SOCKADDR_IN_LEN as u32 {
        return Err(EINVAL);
    }
    let mut buf = [0u8; SOCKADDR_IN_LEN];
    copy_from_user(&mut buf, ptr).map_err(|_| EFAULT)?;
    SockaddrIn::decode(&buf, socklen)
}

#[allow(dead_code)]
pub(crate) fn write_sockaddr_in(
    ptr: u64,
    socklen_ptr: u64,
    addr: &SockaddrIn,
) -> Result<(), LinuxErrno> {
    // Both ranges are checked before either is written, so a bad `socklen_ptr` writes nothing.
    if validate_user_writable_pointer_range(socklen_ptr, 4).is_err() {
        return Err(EFAULT);
    }
    copy_to_user(ptr, &addr.encode()).map_err(|_| EFAULT)?;
    write_user(socklen_ptr, &(SOCKADDR_IN_LEN as u32).to_le_bytes()).map_err(|_| EFAULT)
}
