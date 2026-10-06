//! Kernel-facing backend traits.
//!
//! The compositor core never issues a syscall. Everything it needs from the kernel goes through
//! the five traits below, so the production adapter (`src/bin/compositor.rs`) is a thin layer
//! over syscalls 16–20 and host tests drive the same core with `FakePort`, `FakeDisplay` and a
//! fake shared-memory mapper. None of the traits names a device: the display backend is the
//! syscall-18 vocabulary, identical for the GOP framebuffer and VirtIO-GPU.

use clean_slate_graphics::abi::display::{
    DisplayError, DisplayModeInfo, PresentRequest, PresentStatus,
};
use clean_slate_graphics::protocol::DisconnectReason;
use clean_slate_graphics::raw_input::RawInputRecord;
use clean_slate_native_abi::{ConnectionId, PortRecvRecord, TransferredCap};

/// Failure of a port operation, already classified from the syscall-17 status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortFailure {
    /// The client's event ring is full (`EAGAIN`); retry on a later iteration.
    Full,
    /// The connection is gone (`EPIPE` or `ESTALE`); tear it down locally.
    Gone,
    /// Any other status, carried raw for diagnostics.
    Status(u64),
}

/// Server side of the compositor's service port (syscall 17, `GFX_SERVE`).
pub trait PortServer {
    /// Non-blocking `RECV`: `Ok(None)` when nothing is pending.
    fn recv(&mut self) -> Result<Option<PortRecvRecord>, PortFailure>;
    /// `POST` one event frame to `connection`.
    fn post(&mut self, connection: ConnectionId, frame: &[u8; 64]) -> Result<(), PortFailure>;
    /// `DISCONNECT` `connection` with `reason`.
    fn disconnect(
        &mut self,
        connection: ConnectionId,
        reason: DisconnectReason,
    ) -> Result<(), PortFailure>;
}

/// Why a transferred shared buffer could not be mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MapFailure {
    /// No mapping row or address space left (`ENOSPC`, `EAGAIN`).
    NoSpace,
    /// The capability is stale, revoked, of the wrong class, or not readable.
    Denied,
}

/// A read-only compositor mapping of one client buffer, bounded to the kernel-attested length.
///
/// The compositor never learns a physical address or frame number: `token` is adapter-private
/// (the shared-window VA in production, an index in the host fake).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferMapping {
    /// The compositor's `SharedBuffer{READ}` child handle from the port transfer.
    pub handle: u64,
    /// Raw kernel `SharedBufferId` attested by the port transfer.
    pub buffer_id: u64,
    /// Kernel-attested buffer length; [`SharedBufferMapper::bytes`] never exceeds it.
    pub byte_len: u64,
    pub token: u64,
}

/// Read access to client pixels, only through explicit #195 shared-buffer grants.
pub trait SharedBufferMapper {
    /// Maps the transferred `SharedBuffer{READ}` child read-only.
    fn map_read(&mut self, transfer: &TransferredCap) -> Result<BufferMapping, MapFailure>;
    /// The mapped bytes, exactly `mapping.byte_len` long, or `None` if the mapping is unknown.
    fn bytes(&self, mapping: &BufferMapping) -> Option<&[u8]>;
    /// Unmaps and drops the child capability; called exactly once per successful map.
    fn unmap(&mut self, mapping: BufferMapping);
    /// Drops a transferred child that was never mapped (rejected or unexpected transfer).
    fn discard(&mut self, transfer: &TransferredCap);
}

/// Narrow present/scanout authority (syscall 18, `DISPLAY_PRESENT`); backend-independent.
pub trait DisplayBackend {
    /// `QUERY_MODE`: current output id (with backend epoch) and mode.
    fn query_mode(&mut self) -> Result<DisplayModeInfo, DisplayError>;
    /// Write access to kernel-owned scanout buffer `index` (`MAP_SCANOUT`); `BufferBusy` while it
    /// is in flight.
    fn scanout(&mut self, index: u8) -> Result<&mut [u8], DisplayError>;
    /// `PRESENT`; returns `present_seq`. Never blocks.
    fn present(&mut self, request: &PresentRequest) -> Result<u64, DisplayError>;
    /// `PRESENT_STATUS`.
    fn status(&mut self) -> Result<PresentStatus, DisplayError>;
}

/// Raw input drain (syscall 19, `INPUT_CONSUME`).
pub trait InputSource {
    /// `READ_BATCH` of at most `max` records, each handed to `sink` in queue order. Never
    /// blocks; `Ok(0)` when the queue is empty.
    fn read_batch(
        &mut self,
        max: usize,
        sink: &mut dyn FnMut(RawInputRecord),
    ) -> Result<usize, InputFailure>;
}

/// Raw input could not be read; the compositor keeps serving clients without input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputFailure(pub u64);

/// An input source for compositors without input authority.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoInput;

impl InputSource for NoInput {
    fn read_batch(
        &mut self,
        _max: usize,
        _sink: &mut dyn FnMut(RawInputRecord),
    ) -> Result<usize, InputFailure> {
        Ok(0)
    }
}

/// Work-set bit set by the port when a request is queued (`BIND_WAKE` request bit).
pub const WAKE_REQUESTS: u32 = 1 << 0;
/// Work-set bit set by the port for close, exit and revoke notices (`BIND_WAKE` notice bit).
pub const WAKE_NOTICES: u32 = 1 << 1;
/// Work-set bit set by the input queue (syscall 19 `BIND_WAKE`).
pub const WAKE_INPUT: u32 = 1 << 2;
/// Work-set bit set by the display on completion and state change (syscall 18 `BIND_WAKE`).
pub const WAKE_DISPLAY: u32 = 1 << 3;
/// Every bit the service loop waits on.
pub const WAKE_ALL: u32 = WAKE_REQUESTS | WAKE_NOTICES | WAKE_INPUT | WAKE_DISPLAY;

/// Work-set wait failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WaitFailure(pub u64);

/// Blocking wait on the compositor's work set (syscall 20).
pub trait WorkWaiter {
    /// `WAIT(mask, deadline)`: returns the ready bits (cleared on return), or `0` on deadline
    /// expiry. `None` waits without a deadline.
    fn wait(&mut self, mask: u32, deadline_ns: Option<u64>) -> Result<u32, WaitFailure>;
    /// Monotonic nanoseconds (`WORK_SET NOW`).
    fn now_ns(&mut self) -> u64;
}
