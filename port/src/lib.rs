//! Bounded, class-agnostic service port engine (#200).
//!
//! The pure state machine behind syscall 17 `SERVICE_PORT`: port registry, connection pool,
//! request pool, per-connection event rings and capability transfer on send. The kernel
//! instantiates it once (`kernel/src/service/port.rs`) and supplies every policy input:
//! caller identity and liveness, launch-policy registration, and the shared-buffer attestor.
//!
//! Nothing here wakes or signals. Every operation appends [`Effect`]s, which the caller applies
//! after the call returns, so state always changes before any waiter observes it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

mod effects;
mod engine;
mod transfer;

#[cfg(feature = "fake")]
pub mod fake;

#[cfg(test)]
mod tests;

pub use effects::{Effect, Effects, EFFECTS_CAPACITY};
pub use engine::{
    HolderPortCounts, PortCore, PortCounts, PortReleaseCounts, RegistrationError, WakeBinding,
};
pub use transfer::Transfer;

use clean_slate_capability::HolderId;
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_ECONNREFUSED, STATUS_EINVAL, STATUS_ENOSPC, STATUS_EPIPE,
    STATUS_ESTALE,
};

/// Kernel-internal port identity; never crosses the ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortKey {
    slot: u8,
    generation: u32,
}

impl PortKey {
    pub const fn slot(self) -> u8 {
        self.slot
    }

    pub const fn generation(self) -> u32 {
        self.generation
    }

    /// `slot << 32 | generation`: the low 40 bits of the server and send-space wait keys.
    pub const fn raw(self) -> u64 {
        ((self.slot as u64) << 32) | self.generation as u64
    }
}

/// Trusted identity of the process making a call, supplied by the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Caller {
    pub holder: HolderId,
    /// Live process instance generation; 0 is never live.
    pub generation: u64,
    /// Envelope `domain` (equal to the pid today).
    pub domain: u64,
}

impl Caller {
    const fn is_process(self) -> bool {
        self.holder.0 != HolderId::KERNEL.0 && self.generation != 0
    }
}

/// Operation failure; maps one-to-one onto the syscall 17 statuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortError {
    /// Malformed argument: bad class, role, handle or id encoding, or bit index.
    Invalid,
    /// Wrong resource, missing right, not the registered server, or not the connection's client.
    Denied,
    /// Stale or retired id or handle, revoked capability, or old instance generation.
    Stale,
    /// Connection limit, capability table full, or delegation depth on transfer.
    NoSpace,
    /// Capacity or nothing pending; the syscall layer blocks or returns `EAGAIN`.
    WouldBlock,
    /// The peer closed: SEND after `DISCONNECT`, or POST/DISCONNECT after the client closed.
    PeerClosed,
    /// No live port for the requested resource.
    Refused,
}

impl PortError {
    pub const fn status(self) -> u64 {
        match self {
            PortError::Invalid => STATUS_EINVAL,
            PortError::Denied => STATUS_EACCES,
            PortError::Stale => STATUS_ESTALE,
            PortError::NoSpace => STATUS_ENOSPC,
            PortError::WouldBlock => STATUS_EAGAIN,
            PortError::PeerClosed => STATUS_EPIPE,
            PortError::Refused => STATUS_ECONNREFUSED,
        }
    }
}
