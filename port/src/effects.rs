use clean_slate_capability::ResourceRef;
use clean_slate_native_abi::ConnectionId;

use crate::PortKey;

/// A wake or signal owed after an operation. `B` is the caller's work-set binding type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect<B> {
    /// Waiters in server `RECV` on this port.
    WakeServer(PortKey),
    /// Senders blocked for capacity on this port.
    WakeSendSpace(PortKey),
    /// Client waiters on this connection (`RECV_EVENT`).
    WakeConnection(ConnectionId),
    /// Set this bit on the server's bound work set.
    Signal(B, u32),
}

/// Distinct effects of one operation are at most `4 * PORTS + CONNS` (a server wake, a
/// send-space wake and two signal bits per port, one wake per connection); `PortCore::new`
/// asserts that bound fits.
pub const EFFECTS_CAPACITY: usize = 32;

/// One operation revokes at most every undelivered transfer child, which is at most
/// `PORTS * PORT_MAX_TRANSFERS_IN_FLIGHT`; `PortCore::new` asserts that bound fits.
pub const REVOKED_TRANSFERS_CAPACITY: usize = 16;

/// Deduplicated, fixed-capacity effect list, plus the resources of the undelivered transfer
/// children the operation revoked. The caller must reconcile each of those resources (for a
/// `SharedBuffer`, drop mappings made through the child) once it has released the table.
pub struct Effects<B> {
    items: [Option<Effect<B>>; EFFECTS_CAPACITY],
    len: usize,
    revoked: [Option<ResourceRef>; REVOKED_TRANSFERS_CAPACITY],
    revoked_len: usize,
    overflowed: bool,
}

impl<B: Copy + PartialEq> Default for Effects<B> {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: Copy + PartialEq> Effects<B> {
    pub const fn new() -> Self {
        Self {
            items: [None; EFFECTS_CAPACITY],
            len: 0,
            revoked: [None; REVOKED_TRANSFERS_CAPACITY],
            revoked_len: 0,
            overflowed: false,
        }
    }

    pub(crate) fn push(&mut self, effect: Effect<B>) {
        if self.iter().any(|existing| existing == effect) {
            return;
        }
        match self.items.get_mut(self.len) {
            Some(slot) => {
                *slot = Some(effect);
                self.len += 1;
            }
            None => self.overflowed = true,
        }
    }

    pub(crate) fn note_revoked(&mut self, resource: ResourceRef) {
        if self
            .revoked_transfers()
            .any(|existing| existing == resource)
        {
            return;
        }
        match self.revoked.get_mut(self.revoked_len) {
            Some(slot) => {
                *slot = Some(resource);
                self.revoked_len += 1;
            }
            None => self.overflowed = true,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = Effect<B>> + '_ {
        self.items[..self.len].iter().flatten().copied()
    }

    /// Resources of the undelivered transfer children this operation revoked, deduplicated.
    pub fn revoked_transfers(&self) -> impl Iterator<Item = ResourceRef> + '_ {
        self.revoked[..self.revoked_len].iter().flatten().copied()
    }

    /// Counts wakes and signals only; see [`Self::revoked_transfers`].
    pub const fn len(&self) -> usize {
        self.len
    }

    /// No wakes or signals; see [`Self::revoked_transfers`].
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Never true for a `PortCore` whose bounds fit; callers treat it as fatal.
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}
