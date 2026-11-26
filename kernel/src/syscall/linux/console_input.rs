//! `read(2)` and `poll(2)` readiness on the serial console input description (#218 S5).
//!
//! fd 0 of a process started from a row with the `ConsoleInput` grant refers to
//! [`DescriptorKind::ConsoleInput`](crate::process::linux_fd::open_description::DescriptorKind).
//! A read copies committed bytes from the COM1 line discipline and stops after a `\n`. With
//! nothing committed it returns 0 once for a pending end-of-file (Ctrl-D on an empty line) and
//! otherwise blocks on [`CONSOLE_INPUT_KEY`] and restarts when the receive interrupt commits a
//! line. Syscalls run with interrupts masked (`IA32_FMASK` clears IF on entry, pinned by
//! `syscall::validation`), so the receive interrupt cannot run between the empty check and the
//! waiter registration.

use clean_slate_linux_abi::{LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EAGAIN};

use super::block::{block_linux_syscall, LinuxTimeoutResult};
use super::table::LinuxSyscallContext;
use crate::device::serial_console::{self, CONSOLE_INPUT_KEY};
use crate::process::linux_fd::readiness::Readiness;

/// What a console-input read does with the line discipline in its current state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConsoleRead {
    /// Return this many copied bytes.
    Bytes(usize),
    /// Return 0: the end-of-file was consumed.
    EndOfFile,
    /// Nothing to return and the description is non-blocking.
    WouldBlock,
    /// Nothing to return: block until the next commit.
    Block,
}

/// The decision a console-input read makes from what the discipline returned.
pub(crate) const fn console_read_outcome(copied: usize, eof: bool, nonblock: bool) -> ConsoleRead {
    if copied > 0 {
        ConsoleRead::Bytes(copied)
    } else if eof {
        ConsoleRead::EndOfFile
    } else if nonblock {
        ConsoleRead::WouldBlock
    } else {
        ConsoleRead::Block
    }
}

/// `read(fd, …)` where `fd` refers to console input. `out` is the handler's scratch; the
/// caller copies the returned byte count to user memory.
pub(crate) fn read(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    nonblock: bool,
    out: &mut [u8],
) -> LinuxSyscallResult {
    // A process whose console goes through the service reads what the service answers (#310);
    // the line discipline is read here only while the service cannot be reached.
    #[cfg(clean_slate_system_init)]
    if let Some(result) = crate::service::console_stream::read_input(request, ctx, nonblock, out) {
        return result;
    }
    let copied = serial_console::read(out);
    // `take_eof` only when nothing was copied: an EOF behind committed bytes stays pending.
    let eof = copied == 0 && serial_console::take_eof();
    match console_read_outcome(copied, eof, nonblock) {
        ConsoleRead::Bytes(count) => Ok(count as u64),
        ConsoleRead::EndOfFile => Ok(0),
        ConsoleRead::WouldBlock => Err(EAGAIN),
        ConsoleRead::Block => {
            #[cfg(clean_slate_system_init)]
            crate::service::system_shell::on_console_input_wait(ctx.pid);
            block_linux_syscall(
                request,
                ctx,
                CONSOLE_INPUT_KEY,
                None,
                LinuxTimeoutResult::Zero,
            )
        }
    }
}

/// `poll(2)` readiness of console input for `pid`: readable while a read would not block.
/// Never writable.
pub(crate) fn readiness(pid: u64) -> Readiness {
    #[cfg(clean_slate_system_init)]
    let routed = crate::service::console_stream::input_readable(pid);
    #[cfg(not(clean_slate_system_init))]
    let routed: Option<bool> = {
        let _ = pid;
        None
    };
    Readiness {
        readable: routed.unwrap_or_else(|| !serial_console::would_block()),
        writable: false,
        hangup: false,
        error: false,
    }
}

/// `ENOMEM` for a `poll` on console input whose producer interest could not be recorded:
/// without it the receive interrupt could not wake the caller.
pub(crate) const POLL_INTEREST_FULL: LinuxErrno = clean_slate_linux_abi::ENOMEM;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_win_over_eof_and_blocking() {
        assert_eq!(console_read_outcome(5, false, false), ConsoleRead::Bytes(5));
        assert_eq!(console_read_outcome(5, false, true), ConsoleRead::Bytes(5));
    }

    #[test]
    fn an_empty_read_returns_the_eof_once_then_blocks() {
        assert_eq!(console_read_outcome(0, true, false), ConsoleRead::EndOfFile);
        assert_eq!(console_read_outcome(0, true, true), ConsoleRead::EndOfFile);
        assert_eq!(console_read_outcome(0, false, false), ConsoleRead::Block);
    }

    #[test]
    fn a_non_blocking_empty_read_is_eagain_not_a_block() {
        assert_eq!(
            console_read_outcome(0, false, true),
            ConsoleRead::WouldBlock
        );
    }
}
