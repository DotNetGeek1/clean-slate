//! Per-connection state: object table, buffer tracker, serials and the bounded event outbox.

use clean_slate_graphics::connection::ConnectionPhase;
use clean_slate_graphics::geometry::Size;
use clean_slate_graphics::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::limits::{CLIENT_EVENT_QUEUE_DEPTH, MAX_BUFFERS_PER_CLIENT};
use clean_slate_graphics::objects::{GlobalBudget, ObjectTable};
use clean_slate_graphics::pixel::BufferLayout;
use clean_slate_graphics::protocol::{DisconnectReason, Event, Tagged};
use clean_slate_graphics::surface::{ConnectionBufferTracker, SurfaceState};
use clean_slate_graphics::window::{ConfigureState, SerialMinter, WindowConfig, WindowTitle};
use clean_slate_native_abi::ConnectionId;

use crate::backend::BufferMapping;

/// Compositor-side surface: the #110 state machine plus the compositor's own bookkeeping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceEntry {
    pub state: SurfaceState,
    /// The window whose role object this surface is (Toplevel only).
    pub window: Option<WindowId>,
    /// Popup parent, resolved in the same connection's table at `AssignRole`.
    pub parent: Option<SurfaceId>,
}

impl SurfaceEntry {
    pub const fn new() -> Self {
        Self {
            state: SurfaceState::new(),
            window: None,
            parent: None,
        }
    }
}

impl Default for SurfaceEntry {
    fn default() -> Self {
        Self::new()
    }
}

/// Compositor-side window. Placement, focus and decorations are window-manager policy (#115).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowEntry {
    pub surface: SurfaceId,
    pub configure: ConfigureState,
    /// The newest config refused with `LimitExceeded`; re-sent after the next ack (S4).
    pub wanted: Option<WindowConfig>,
    pub title: WindowTitle,
    pub min_size: Size,
    pub max_size: Size,
    pub shown: bool,
}

impl WindowEntry {
    pub fn new(surface: SurfaceId) -> Self {
        Self {
            surface,
            configure: ConfigureState::new(),
            wanted: None,
            title: WindowTitle::from_str_truncating(""),
            min_size: Size {
                width: 0,
                height: 0,
            },
            max_size: Size {
                width: 0,
                height: 0,
            },
            shown: false,
        }
    }
}

/// A registered client buffer: the validated layout and the compositor's read mapping.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferEntry {
    pub layout: BufferLayout,
    pub mapping: BufferMapping,
}

pub type ClientObjects = ObjectTable<SurfaceEntry, WindowEntry, BufferEntry>;

/// Bounded FIFO of events not yet accepted by the client's port event ring.
#[derive(Clone, Copy, Debug)]
pub struct Outbox {
    events: [Option<Tagged<Event>>; CLIENT_EVENT_QUEUE_DEPTH],
    head: usize,
    len: usize,
}

impl Outbox {
    pub const fn new() -> Self {
        Self {
            events: [None; CLIENT_EVENT_QUEUE_DEPTH],
            head: 0,
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `false` when the outbox is full; the caller disconnects the client (`QueueOverflow`).
    pub fn push(&mut self, event: Tagged<Event>) -> bool {
        if self.len == CLIENT_EVENT_QUEUE_DEPTH {
            return false;
        }
        let index = (self.head + self.len) % CLIENT_EVENT_QUEUE_DEPTH;
        self.events[index] = Some(event);
        self.len += 1;
        true
    }

    pub fn front(&self) -> Option<Tagged<Event>> {
        if self.len == 0 {
            None
        } else {
            self.events[self.head]
        }
    }

    pub fn pop(&mut self) {
        if self.len > 0 {
            self.events[self.head] = None;
            self.head = (self.head + 1) % CLIENT_EVENT_QUEUE_DEPTH;
            self.len -= 1;
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

impl Default for Outbox {
    fn default() -> Self {
        Self::new()
    }
}

/// Kernel-stamped identity of a connection's client, from the first request's envelope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    pub connection: ConnectionId,
    pub pid: u64,
    pub domain: u64,
    pub instance_generation: u64,
}

/// One connection slot. Slots are reused in place so the ~24 KB object table never moves
/// through the stack (S8).
pub struct ClientSlot {
    pub(crate) identity: Option<ClientIdentity>,
    pub(crate) phase: ConnectionPhase,
    pub(crate) objects: ClientObjects,
    pub(crate) tracker: ConnectionBufferTracker,
    pub(crate) minter: SerialMinter,
    /// Ids of every registered buffer, for teardown (the object table cannot be iterated).
    pub(crate) registered: [Option<ClientBufferId>; MAX_BUFFERS_PER_CLIENT],
    pub(crate) outbox: Outbox,
    /// Consecutive flushes that left events behind because the client's ring was full.
    pub(crate) stall_iterations: u32,
    /// Set by a fatal protocol error or overflow; applied at the next flush.
    pub(crate) pending_disconnect: Option<DisconnectReason>,
    /// Serial of the newest pointer press delivered to this client (`BeginMove`/`BeginResize`).
    pub(crate) last_press_serial: Option<Serial>,
}

impl ClientSlot {
    pub const fn new() -> Self {
        Self {
            identity: None,
            phase: ConnectionPhase::new(),
            objects: ObjectTable::new(),
            tracker: ConnectionBufferTracker::new(),
            minter: SerialMinter::new(),
            registered: [None; MAX_BUFFERS_PER_CLIENT],
            outbox: Outbox::new(),
            stall_iterations: 0,
            pending_disconnect: None,
            last_press_serial: None,
        }
    }

    pub fn identity(&self) -> Option<ClientIdentity> {
        self.identity
    }

    pub fn is_live(&self) -> bool {
        self.identity.is_some()
    }

    pub fn objects(&self) -> &ClientObjects {
        &self.objects
    }

    pub fn phase(&self) -> ConnectionPhase {
        self.phase
    }

    pub fn outbox_len(&self) -> usize {
        self.outbox.len()
    }

    /// Queues an event; a full outbox schedules a `QueueOverflow` disconnect.
    pub(crate) fn queue(&mut self, tag: u32, event: Event) {
        if self.pending_disconnect.is_some() {
            return;
        }
        if !self.outbox.push(Tagged {
            tag,
            message: event,
        }) {
            self.pending_disconnect = Some(DisconnectReason::QueueOverflow);
        }
    }

    pub(crate) fn note_registered(&mut self, id: ClientBufferId) {
        if let Some(slot) = self.registered.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(id);
        }
    }

    pub(crate) fn note_unregistered(&mut self, id: ClientBufferId) {
        if let Some(slot) = self.registered.iter_mut().find(|slot| **slot == Some(id)) {
            *slot = None;
        }
    }

    /// Resets the slot in place for the next connection. The caller has already released every
    /// mapping; this returns the object budget (`ObjectTable::close`, S8).
    pub(crate) fn reset(&mut self, budget: &mut GlobalBudget) {
        self.objects.close(budget);
        self.identity = None;
        self.phase = ConnectionPhase::new();
        self.tracker = ConnectionBufferTracker::new();
        self.minter = SerialMinter::new();
        self.registered = [None; MAX_BUFFERS_PER_CLIENT];
        self.outbox.clear();
        self.stall_iterations = 0;
        self.pending_disconnect = None;
        self.last_press_serial = None;
    }
}

impl Default for ClientSlot {
    fn default() -> Self {
        Self::new()
    }
}
