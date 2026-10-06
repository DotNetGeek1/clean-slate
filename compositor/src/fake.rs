//! Backend adapters over the host fakes (`cfg(any(test, feature = "fake"))`).
//!
//! [`FakePort`] and [`FakeDisplay`] are the same engines the kernel lanes use, so host tests
//! drive the real port admission, envelope stamping, capability transfer and present rules.
//! [`FakeSharedMemory`] stands in for the #195 shared-window mappings: it only hands out bytes
//! for a transferred `SharedBuffer{READ}` child, bounded to the kernel-attested length.

use clean_slate_capability::{ResourceClass, Rights};
use clean_slate_graphics::abi::display::{
    DisplayError, DisplayModeInfo, PresentRequest, PresentStatus,
};
use clean_slate_graphics::fake::FakeDisplay;
use clean_slate_graphics::limits::{MAX_PRESENT_DAMAGE_RECTS, SCANOUT_BUFFER_COUNT};
use clean_slate_graphics::protocol::DisconnectReason;
use clean_slate_graphics::raw_input::RawInputRecord;
use clean_slate_native_abi::status::{STATUS_EAGAIN, STATUS_EPIPE, STATUS_ESTALE};
use clean_slate_native_abi::{ConnectionId, PortRecvRecord, TransferredCap};
use clean_slate_port::fake::FakePort;

use crate::backend::{
    BufferMapping, DisplayBackend, InputFailure, InputSource, MapFailure, PortFailure, PortServer,
    SharedBufferMapper, WaitFailure, WorkWaiter,
};

fn port_failure(status: u64) -> PortFailure {
    match status {
        STATUS_EAGAIN => PortFailure::Full,
        STATUS_EPIPE | STATUS_ESTALE => PortFailure::Gone,
        other => PortFailure::Status(other),
    }
}

impl PortServer for FakePort {
    fn recv(&mut self) -> Result<Option<PortRecvRecord>, PortFailure> {
        match self.server_recv() {
            Ok(record) => Ok(Some(record)),
            Err(STATUS_EAGAIN) => Ok(None),
            Err(status) => Err(port_failure(status)),
        }
    }

    fn post(&mut self, connection: ConnectionId, frame: &[u8; 64]) -> Result<(), PortFailure> {
        self.server_post(connection, frame).map_err(port_failure)
    }

    fn disconnect(
        &mut self,
        connection: ConnectionId,
        reason: DisconnectReason,
    ) -> Result<(), PortFailure> {
        self.server_disconnect(connection, reason.encode())
            .map_err(port_failure)
    }
}

impl<const BYTES: usize> DisplayBackend for FakeDisplay<BYTES> {
    fn query_mode(&mut self) -> Result<DisplayModeInfo, DisplayError> {
        Ok(DisplayModeInfo {
            output: self.output(),
            mode: self.mode(),
            scanout_buffer_count: SCANOUT_BUFFER_COUNT as u8,
            max_present_damage_rects: MAX_PRESENT_DAMAGE_RECTS as u8,
        })
    }

    fn scanout(&mut self, index: u8) -> Result<&mut [u8], DisplayError> {
        self.buffer_mut(index)
    }

    fn present(&mut self, request: &PresentRequest) -> Result<u64, DisplayError> {
        FakeDisplay::present(self, request)
    }

    fn status(&mut self) -> Result<PresentStatus, DisplayError> {
        Ok(FakeDisplay::status(self))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Backing {
    buffer_id: u64,
    byte_len: usize,
    mappings: u32,
}

/// Shared-buffer backing store for host tests: `SLOTS` buffers of up to `BYTES` bytes.
///
/// Clients write through [`Self::client_bytes`] (their own read-write mapping); the compositor
/// can only read through [`SharedBufferMapper`], which demands a transferred capability.
pub struct FakeSharedMemory<const SLOTS: usize, const BYTES: usize> {
    store: [[u8; BYTES]; SLOTS],
    backing: [Option<Backing>; SLOTS],
    mapped: u32,
    unmapped: u32,
    discarded: u32,
    /// Remaining `map_read` calls before `NoSpace` (`u32::MAX` = unlimited).
    map_budget: u32,
}

impl<const SLOTS: usize, const BYTES: usize> FakeSharedMemory<SLOTS, BYTES> {
    pub const fn new() -> Self {
        Self {
            store: [[0; BYTES]; SLOTS],
            backing: [None; SLOTS],
            mapped: 0,
            unmapped: 0,
            discarded: 0,
            map_budget: u32::MAX,
        }
    }

    /// Allocates the backing for `buffer_id` (the client's `ALLOCATE`).
    pub fn allocate(&mut self, buffer_id: u64, byte_len: usize) -> bool {
        if byte_len > BYTES {
            return false;
        }
        match self.backing.iter_mut().find(|b| b.is_none()) {
            Some(slot) => {
                *slot = Some(Backing {
                    buffer_id,
                    byte_len,
                    mappings: 0,
                });
                true
            }
            None => false,
        }
    }

    fn slot_of(&self, buffer_id: u64) -> Option<usize> {
        self.backing
            .iter()
            .position(|b| matches!(b, Some(b) if b.buffer_id == buffer_id))
    }

    /// The owning client's read-write view.
    pub fn client_bytes(&mut self, buffer_id: u64) -> Option<&mut [u8]> {
        let slot = self.slot_of(buffer_id)?;
        let len = self.backing[slot]?.byte_len;
        Some(&mut self.store[slot][..len])
    }

    /// Mappings currently held by the compositor.
    pub fn live_mappings(&self) -> u32 {
        self.mapped - self.unmapped
    }

    pub fn discarded(&self) -> u32 {
        self.discarded
    }

    /// Makes the next `n` maps succeed and every later one fail with `NoSpace`.
    pub fn limit_maps(&mut self, n: u32) {
        self.map_budget = n;
    }
}

impl<const SLOTS: usize, const BYTES: usize> Default for FakeSharedMemory<SLOTS, BYTES> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const SLOTS: usize, const BYTES: usize> SharedBufferMapper for FakeSharedMemory<SLOTS, BYTES> {
    fn map_read(&mut self, transfer: &TransferredCap) -> Result<BufferMapping, MapFailure> {
        if transfer.class != ResourceClass::SharedBuffer.as_u8()
            || transfer.rights & Rights::READ.bits() == 0
        {
            return Err(MapFailure::Denied);
        }
        let slot = self.slot_of(transfer.buffer_id).ok_or(MapFailure::Denied)?;
        if self.map_budget == 0 {
            return Err(MapFailure::NoSpace);
        }
        if self.map_budget != u32::MAX {
            self.map_budget -= 1;
        }
        let backing = self.backing[slot].as_mut().ok_or(MapFailure::Denied)?;
        backing.mappings += 1;
        self.mapped += 1;
        Ok(BufferMapping {
            handle: transfer.handle,
            buffer_id: transfer.buffer_id,
            byte_len: transfer.byte_len.min(backing.byte_len as u64),
            token: slot as u64,
        })
    }

    fn bytes(&self, mapping: &BufferMapping) -> Option<&[u8]> {
        let slot = usize::try_from(mapping.token).ok()?;
        let backing = (*self.backing.get(slot)?)?;
        if backing.buffer_id != mapping.buffer_id || backing.mappings == 0 {
            return None;
        }
        let len = usize::try_from(mapping.byte_len)
            .ok()?
            .min(backing.byte_len);
        Some(&self.store[slot][..len])
    }

    fn unmap(&mut self, mapping: BufferMapping) {
        if let Some(Some(backing)) = usize::try_from(mapping.token)
            .ok()
            .and_then(|slot| self.backing.get_mut(slot))
        {
            backing.mappings = backing.mappings.saturating_sub(1);
        }
        self.unmapped += 1;
    }

    fn discard(&mut self, _transfer: &TransferredCap) {
        self.discarded += 1;
    }
}

/// Bounded raw-input queue for host tests.
pub struct FakeInput {
    queue: [Option<RawInputRecord>; 256],
    head: usize,
    len: usize,
}

impl FakeInput {
    pub const fn new() -> Self {
        Self {
            queue: [None; 256],
            head: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, record: RawInputRecord) -> bool {
        if self.len == self.queue.len() {
            return false;
        }
        let at = (self.head + self.len) % self.queue.len();
        self.queue[at] = Some(record);
        self.len += 1;
        true
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for FakeInput {
    fn default() -> Self {
        Self::new()
    }
}

impl InputSource for FakeInput {
    fn read_batch(
        &mut self,
        max: usize,
        sink: &mut dyn FnMut(RawInputRecord),
    ) -> Result<usize, InputFailure> {
        let mut n = 0;
        while n < max && self.len > 0 {
            if let Some(record) = self.queue[self.head].take() {
                sink(record);
            }
            self.head = (self.head + 1) % self.queue.len();
            self.len -= 1;
            n += 1;
        }
        Ok(n)
    }
}

/// `WAIT` status the scripted waiter returns instead of blocking forever.
pub const WAIT_WOULD_BLOCK_FOREVER: u64 = u64::MAX - 0x100;

/// Work set with a manual clock: ready bits are raised by the test; a wait with nothing ready
/// jumps the clock to its deadline, and a wait with neither fails with
/// [`WAIT_WOULD_BLOCK_FOREVER`] so a test can prove the loop is idle-blocked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScriptedWaiter {
    pub now_ns: u64,
    pub ready: u32,
    pub waits: u32,
    pub deadline_wakes: u32,
    pub last_deadline: Option<u64>,
}

impl ScriptedWaiter {
    pub const fn new() -> Self {
        Self {
            now_ns: 1,
            ready: 0,
            waits: 0,
            deadline_wakes: 0,
            last_deadline: None,
        }
    }

    pub fn raise(&mut self, bits: u32) {
        self.ready |= bits;
    }
}

impl WorkWaiter for ScriptedWaiter {
    fn wait(&mut self, mask: u32, deadline_ns: Option<u64>) -> Result<u32, WaitFailure> {
        self.waits += 1;
        self.last_deadline = deadline_ns;
        let bits = self.ready & mask;
        if bits != 0 {
            self.ready &= !bits;
            return Ok(bits);
        }
        match deadline_ns {
            Some(deadline) => {
                self.now_ns = self.now_ns.max(deadline);
                self.deadline_wakes += 1;
                Ok(0)
            }
            None => Err(WaitFailure(WAIT_WOULD_BLOCK_FOREVER)),
        }
    }

    fn now_ns(&mut self) -> u64 {
        self.now_ns
    }
}
