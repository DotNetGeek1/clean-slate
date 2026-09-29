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

/// Deduplicated, fixed-capacity effect list.
pub struct Effects<B> {
    items: [Option<Effect<B>>; EFFECTS_CAPACITY],
    len: usize,
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

    pub fn iter(&self) -> impl Iterator<Item = Effect<B>> + '_ {
        self.items[..self.len].iter().flatten().copied()
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Never true for a `PortCore` whose bound fits; callers treat it as fatal.
    pub const fn overflowed(&self) -> bool {
        self.overflowed
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}
