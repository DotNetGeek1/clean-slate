//! Rights bitset and class-specific valid masks.

use core::fmt;

use crate::resource::ResourceClass;

/// Capability rights as a fixed bitset (`Copy`, no heap).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Rights(u32);

impl Rights {
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const INSPECT: Self = Self(1 << 2);
    pub const DELEGATE: Self = Self(1 << 3);
    pub const REVOKE: Self = Self(1 << 4);
    pub const OBSERVE: Self = Self(1 << 5);
    pub const SIGNAL: Self = Self(1 << 6);
    pub const TERMINATE: Self = Self(1 << 7);
    pub const AUDIT_READ: Self = Self(1 << 8);

    const ALL_KNOWN: u32 = (1 << 0)
        | (1 << 1)
        | (1 << 2)
        | (1 << 3)
        | (1 << 4)
        | (1 << 5)
        | (1 << 6)
        | (1 << 7)
        | (1 << 8);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub fn from_bits(bits: u32) -> Option<Self> {
        if bits & !Self::ALL_KNOWN != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    pub const fn contains(self, required: Self) -> bool {
        (self.0 & required.0) == required.0
    }

    pub const fn is_subset_of(self, allowed: Self) -> bool {
        (self.0 & allowed.0) == self.0
    }

    /// Bitwise AND — delegation and attenuation never add bits.
    pub const fn attenuate(self, mask: Self) -> Self {
        Self(self.0 & mask.0)
    }

    /// Union of grant sources only — **not** for delegation (which must shrink via `attenuate`).
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Allowed rights mask for a resource class (unknown / future bits rejected elsewhere).
    pub const fn valid_for(class: ResourceClass) -> Self {
        match class {
            ResourceClass::PersistentObject => Self(
                Self::READ.0 | Self::WRITE.0 | Self::INSPECT.0 | Self::DELEGATE.0 | Self::REVOKE.0,
            ),
            ResourceClass::ProcessControl => Self(
                Self::OBSERVE.0
                    | Self::SIGNAL.0
                    | Self::TERMINATE.0
                    | Self::DELEGATE.0
                    | Self::REVOKE.0,
            ),
            ResourceClass::IpcEndpoint => {
                Self(Self::READ.0 | Self::WRITE.0 | Self::DELEGATE.0 | Self::REVOKE.0)
            }
            ResourceClass::BlockDevice => Self(
                Self::READ.0 | Self::WRITE.0 | Self::INSPECT.0 | Self::DELEGATE.0 | Self::REVOKE.0,
            ),
            ResourceClass::LifecycleControl => Self(
                Self::OBSERVE.0
                    | Self::SIGNAL.0
                    | Self::TERMINATE.0
                    | Self::DELEGATE.0
                    | Self::REVOKE.0,
            ),
            ResourceClass::Audit => Self(Self::AUDIT_READ.0 | Self::DELEGATE.0),
            ResourceClass::Network => Self::empty(),
        }
    }

    /// Lowercase, pipe-separated names in deterministic bit order.
    pub fn write_names(&self, f: &mut impl fmt::Write) -> fmt::Result {
        const NAMES: [(&str, u32); 9] = [
            ("read", 1 << 0),
            ("write", 1 << 1),
            ("inspect", 1 << 2),
            ("delegate", 1 << 3),
            ("revoke", 1 << 4),
            ("observe", 1 << 5),
            ("signal", 1 << 6),
            ("terminate", 1 << 7),
            ("audit_read", 1 << 8),
        ];
        let mut first = true;
        for (name, bit) in NAMES {
            if self.0 & bit != 0 {
                if !first {
                    f.write_str("|")?;
                }
                f.write_str(name)?;
                first = false;
            }
        }
        Ok(())
    }
}
