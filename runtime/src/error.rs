//! The one error mapping every native client shares.

use clean_slate_native_abi::status::{
    is_status, STATUS_EAGAIN, STATUS_EPIPE, STATUS_ESTALE, STATUS_ETIMEDOUT,
};

/// Why a call failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The peer or server has ended: a port connection whose server exited or disconnected
    /// (`ESTALE`, `EPIPE`), or a handle to something that no longer exists. Nothing on the same
    /// object can succeed again; reconnect or exit.
    Gone,
    /// A deadline passed first (`ETIMEDOUT`).
    TimedOut,
    /// A non-blocking call found nothing ready (`EAGAIN`).
    WouldBlock,
    /// Any other refusal, with its status.
    Failed(u64),
}

impl Error {
    /// The error for a status. The only place `ESTALE` and `EPIPE` are told apart from other
    /// failures.
    pub const fn from_status(raw: u64) -> Self {
        match raw {
            STATUS_ESTALE | STATUS_EPIPE => Self::Gone,
            STATUS_ETIMEDOUT => Self::TimedOut,
            STATUS_EAGAIN => Self::WouldBlock,
            other => Self::Failed(other),
        }
    }

    /// A syscall result: the value, or the error its status names.
    pub const fn check(raw: u64) -> Result<u64, Self> {
        if is_status(raw) {
            Err(Self::from_status(raw))
        } else {
            Ok(raw)
        }
    }

    pub const fn is_gone(self) -> bool {
        matches!(self, Self::Gone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_ENOSPC};

    #[test]
    fn a_peer_that_has_ended_is_gone() {
        assert_eq!(Error::from_status(STATUS_ESTALE), Error::Gone);
        assert_eq!(Error::from_status(STATUS_EPIPE), Error::Gone);
        assert!(Error::check(STATUS_EPIPE).unwrap_err().is_gone());
    }

    #[test]
    fn other_statuses_keep_their_value() {
        for status in [STATUS_EINVAL, STATUS_EACCES, STATUS_ENOSPC] {
            assert_eq!(Error::from_status(status), Error::Failed(status));
        }
        assert_eq!(Error::from_status(STATUS_ETIMEDOUT), Error::TimedOut);
        assert_eq!(Error::from_status(STATUS_EAGAIN), Error::WouldBlock);
    }

    #[test]
    fn values_pass_through() {
        assert_eq!(Error::check(0), Ok(0));
        assert_eq!(Error::check(0x6000_0000_0000), Ok(0x6000_0000_0000));
    }
}
