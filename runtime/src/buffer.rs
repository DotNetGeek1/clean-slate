//! Shared buffers (syscall 16), allocated and mapped read-write as one step.

use clean_slate_native_abi::{
    SHARED_BUFFER_ACCESS_READ_WRITE, SHARED_BUFFER_SUBOP_ALLOCATE, SHARED_BUFFER_SUBOP_MAP,
    SHARED_BUFFER_SUBOP_RELEASE, SHARED_BUFFER_SUBOP_UNMAP, SYSCALL_NR_SHARED_BUFFER,
};

use crate::{Error, Syscalls};

/// A shared buffer this process owns, mapped read-write.
#[derive(Debug, PartialEq, Eq)]
pub struct SharedBuffer {
    handle: u64,
    va: u64,
    len: usize,
}

impl SharedBuffer {
    /// Allocates `len` bytes and maps them. A buffer that cannot be mapped is released again.
    pub fn allocate<S: Syscalls>(sys: &mut S, len: usize) -> Result<Self, Error> {
        let handle = sys.call(
            SYSCALL_NR_SHARED_BUFFER,
            [SHARED_BUFFER_SUBOP_ALLOCATE, 0, len as u64, 0, 0, 0],
        )?;
        match sys.call(
            SYSCALL_NR_SHARED_BUFFER,
            [
                SHARED_BUFFER_SUBOP_MAP,
                handle,
                SHARED_BUFFER_ACCESS_READ_WRITE,
                0,
                0,
                0,
            ],
        ) {
            Ok(va) => Ok(Self { handle, va, len }),
            Err(error) => {
                let _ = sys.call(
                    SYSCALL_NR_SHARED_BUFFER,
                    [SHARED_BUFFER_SUBOP_RELEASE, handle, 0, 0, 0, 0],
                );
                Err(error)
            }
        }
    }

    /// The capability handle, for a port transfer.
    pub const fn handle(&self) -> u64 {
        self.handle
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The mapped bytes.
    pub fn bytes(&mut self) -> &mut [u8] {
        // SAFETY: MAP returned `len` read-write bytes at `va` for this process, mapped until
        // `release` consumes `self`; the borrow is tied to `&mut self`, so no alias outlives it.
        unsafe { core::slice::from_raw_parts_mut(self.va as *mut u8, self.len) }
    }

    /// Unmaps, then releases (`RELEASE` refuses a mapped buffer). Both steps are attempted; the
    /// first error is returned.
    pub fn release<S: Syscalls>(self, sys: &mut S) -> Result<(), Error> {
        let unmapped = sys.call(
            SYSCALL_NR_SHARED_BUFFER,
            [SHARED_BUFFER_SUBOP_UNMAP, 0, self.va, 0, 0, 0],
        );
        let released = sys.call(
            SYSCALL_NR_SHARED_BUFFER,
            [SHARED_BUFFER_SUBOP_RELEASE, self.handle, 0, 0, 0, 0],
        );
        unmapped.and(released).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::STATUS_ENOSPC;

    #[test]
    fn a_buffer_is_mapped_writable_then_released() {
        let mut sys = FakeKernel::new();
        let mut buffer = SharedBuffer::allocate(&mut sys, 8192).expect("allocate");
        assert_eq!(buffer.len(), 8192);
        buffer.bytes()[8191] = 0xAB;
        assert_eq!(buffer.bytes()[8191], 0xAB);
        assert_eq!((sys.live_buffers(), sys.mapped_buffers()), (1, 1));
        buffer.release(&mut sys).expect("release");
        assert_eq!(sys.live_buffers(), 0);
    }

    #[test]
    fn a_failed_map_releases_the_buffer() {
        let mut sys = FakeKernel::new();
        // ALLOCATE runs; MAP is refused.
        sys.answer_next(SYSCALL_NR_SHARED_BUFFER, 0x1234);
        sys.answer_next(SYSCALL_NR_SHARED_BUFFER, STATUS_ENOSPC);
        assert_eq!(
            SharedBuffer::allocate(&mut sys, 4096),
            Err(Error::Failed(STATUS_ENOSPC))
        );
        assert_eq!(
            sys.last_call().1,
            [SHARED_BUFFER_SUBOP_RELEASE, 0x1234, 0, 0, 0, 0]
        );
    }
}
