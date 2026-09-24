//! User `sockaddr_in` validation (kernel side).

use clean_slate_linux_abi::{LinuxErrno, SockaddrIn, EFAULT, EINVAL, SOCKADDR_IN_LEN};

use crate::mm::user_mapping::validate_user_pointer_range;
pub(crate) fn read_sockaddr_in(ptr: u64, socklen: u32) -> Result<SockaddrIn, LinuxErrno> {
    if socklen != SOCKADDR_IN_LEN as u32 {
        return Err(EINVAL);
    }
    if validate_user_pointer_range(ptr, SOCKADDR_IN_LEN as u64).is_err() {
        return Err(EFAULT);
    }
    let mut buf = [0u8; SOCKADDR_IN_LEN];
    unsafe {
        core::ptr::copy_nonoverlapping(ptr as *const u8, buf.as_mut_ptr(), SOCKADDR_IN_LEN);
    }
    SockaddrIn::decode(&buf, socklen)
}

#[allow(dead_code)]
pub(crate) fn write_sockaddr_in(
    ptr: u64,
    socklen_ptr: u64,
    addr: &SockaddrIn,
) -> Result<(), LinuxErrno> {
    if validate_user_pointer_range(ptr, SOCKADDR_IN_LEN as u64).is_err() {
        return Err(EFAULT);
    }
    if validate_user_pointer_range(socklen_ptr, 4).is_err() {
        return Err(EFAULT);
    }
    let wire = addr.encode();
    unsafe {
        core::ptr::copy_nonoverlapping(wire.as_ptr(), ptr as *mut u8, SOCKADDR_IN_LEN);
        let len = (SOCKADDR_IN_LEN as u32).to_le_bytes();
        core::ptr::copy_nonoverlapping(len.as_ptr(), socklen_ptr as *mut u8, 4);
    }
    Ok(())
}
