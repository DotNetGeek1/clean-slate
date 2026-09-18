//! Socket/session identity separate from process identity.

use core::fmt;

/// Network-service instance epoch. A replaced service must bump this value so
/// stale [`SessionId`] values from a prior instance are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionGeneration(pub u64);

impl SessionGeneration {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Session handle scoped to one network-service instance generation.
///
/// The trusted caller identity (holder, domain, instance generation) is supplied
/// externally by the kernel/service and must never be taken from client request fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub const fn new(generation: SessionGeneration, index: u32) -> Self {
        let packed = (generation.get() << 32) | (index as u64);
        Self(packed)
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn raw(self) -> u64 {
        self.0
    }

    pub const fn generation(self) -> SessionGeneration {
        SessionGeneration(self.0 >> 32)
    }

    pub const fn index(self) -> u32 {
        self.0 as u32
    }

    pub const fn matches_generation(self, expected: SessionGeneration) -> bool {
        self.generation().get() == expected.get()
    }

    pub fn write_to(self, f: &mut impl fmt::Write) -> fmt::Result {
        write!(
            f,
            "session(gen={}, idx={})",
            self.generation().get(),
            self.index()
        )
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SocketKind {
    Udp = 1,
    Tcp = 2,
}

impl SocketKind {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Udp),
            2 => Some(Self::Tcp),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SessionState {
    Opening = 1,
    Open = 2,
    Closing = 3,
    Closed = 4,
    Failed = 5,
}

impl SessionState {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Opening),
            2 => Some(Self::Open),
            3 => Some(Self::Closing),
            4 => Some(Self::Closed),
            5 => Some(Self::Failed),
            _ => None,
        }
    }
}
