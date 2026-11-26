//! Console lines through the console capability (syscall 3 `IPC_SEND`).
//!
//! Today the kernel's console sink is the far end; when a console service exists, only this
//! module changes.

use clean_slate_native_abi::desktop::{CONSOLE_LINE_BYTES, SYSCALL_NR_IPC_SEND};
use clean_slate_native_abi::status::STATUS_EINVAL;

use crate::{Error, Syscalls};

/// A console capability handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Console {
    handle: u64,
}

impl Console {
    pub const fn new(handle: u64) -> Self {
        Self { handle }
    }

    pub const fn handle(self) -> u64 {
        self.handle
    }

    /// One message of at most [`CONSOLE_LINE_BYTES`]; returns the bytes the kernel took.
    /// A refusal keeps its status (`EBADF` on a handle that is not a console).
    pub fn send<S: Syscalls>(self, sys: &mut S, message: &[u8]) -> Result<usize, Error> {
        if message.len() > CONSOLE_LINE_BYTES {
            return Err(Error::Failed(STATUS_EINVAL));
        }
        let sent = sys.call(
            SYSCALL_NR_IPC_SEND,
            [
                self.handle,
                message.as_ptr() as u64,
                message.len() as u64,
                0,
                0,
                0,
            ],
        )?;
        if sent == 0 || sent > message.len() as u64 {
            return Err(Error::Failed(sent));
        }
        Ok(sent as usize)
    }

    /// Writes `text` in as many messages as it takes. A lost piece is skipped, never retried:
    /// a console line must not stall or fail the caller.
    pub fn write<S: Syscalls>(self, sys: &mut S, text: &[u8]) {
        for chunk in text.chunks(CONSOLE_LINE_BYTES) {
            let _ = self.send(sys, chunk);
        }
    }

    pub fn write_str<S: Syscalls>(self, sys: &mut S, text: &str) {
        self.write(sys, text.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::STATUS_EBADF;

    #[test]
    fn long_text_is_split_into_messages() {
        let mut sys = FakeKernel::new();
        let text = [b'x'; CONSOLE_LINE_BYTES * 2 + 5];
        Console::new(9).write(&mut sys, &text);
        let lengths: Vec<usize> = sys.console().iter().map(Vec::len).collect();
        assert_eq!(lengths, [CONSOLE_LINE_BYTES, CONSOLE_LINE_BYTES, 5]);
        assert!(sys.calls().iter().all(|(_, args)| args[0] == 9));
    }

    #[test]
    fn a_refusal_keeps_its_status() {
        let mut sys = FakeKernel::new();
        sys.answer_next(SYSCALL_NR_IPC_SEND, STATUS_EBADF);
        assert_eq!(
            Console::new(1).send(&mut sys, b"hi"),
            Err(Error::Failed(STATUS_EBADF))
        );
        assert_eq!(
            Console::new(1).send(&mut sys, &[0; CONSOLE_LINE_BYTES + 1]),
            Err(Error::Failed(STATUS_EINVAL))
        );
        sys.answer_next(SYSCALL_NR_IPC_SEND, 0);
        assert_eq!(Console::new(1).send(&mut sys, b"hi"), Err(Error::Failed(0)));
        assert_eq!(Console::new(1).send(&mut sys, b"hi"), Ok(2));
    }
}
