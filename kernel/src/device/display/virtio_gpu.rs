//! VirtIO-GPU 2D scanout backend (#114) over the #196 modern PCI transport.
//!
//! One host resource (`RESOURCE_ID`, `B8G8R8X8`, the reference mode) is scanout 0 for the boot.
//! A present attaches the named kernel-owned buffer as the resource's backing when it is not the
//! one attached already (detach, then attach its pinned extents), transfers exactly the damaged
//! rects into the host resource and flushes their bounding box. Host pixels outside the damage
//! keep what was presented before (R8), whichever buffer is attached.
//!
//! The commands of one present go out as one batch behind one notify; the device executes a
//! control queue in order. Every command carries the `DISPLAY_COMMAND_TIMEOUT_NS` W3 deadline.
//! Completions arrive through the transport's interrupt sink and are harvested by
//! [`ScanoutBackend::poll`]. A transport timeout or failure, or any response other than the
//! expected OK, ends the batch with an error exactly once and latches `needs_reset`; only
//! [`ScanoutBackend::reset`] (a device reset, which strands every earlier token, then the bring-up
//! batch again) clears it. No descriptor names anything but the static command slots and the
//! extents of a bound, pinned scanout buffer.

use clean_slate_graphics::{
    BufferRect, DisplayMode, DISPLAY_COMMAND_TIMEOUT_NS, MAX_PRESENT_DAMAGE_RECTS,
    REFERENCE_FRAME_BYTES, REFERENCE_MODE, SCANOUT_BUFFER_COUNT,
};
use clean_slate_native_abi::MAX_EXTENTS_PER_BUFFER;

use super::source::{FrameSource, FrameSourceId, PhysExtent};
use super::{BackendError, ScanoutBackend, Submitted};
use crate::device::virtio::dma::DmaRegion;
#[cfg(not(test))]
use crate::device::virtio::modern::{DeviceRequest, QueueRequest};
use crate::device::virtio::modern::{
    ResetReason, TransportError, TransportState, VirtqueueTransport,
};
use crate::device::virtio::virtqueue::Token;
use crate::mm::PAGE_SIZE;
use crate::sched::wait::Deadline;

#[cfg(not(test))]
pub(crate) const VIRTIO_ID_GPU: u16 = 16;
const CONTROL_QUEUE: u16 = 0;
/// Two descriptors per command: room for a bring-up batch and a full present batch at once.
const CONTROL_QUEUE_SIZE: u16 = 64;

#[cfg(not(test))]
static GPU_QUEUES: [QueueRequest; 2] = [
    QueueRequest {
        index: CONTROL_QUEUE,
        max_size: CONTROL_QUEUE_SIZE,
    },
    QueueRequest {
        index: 1,
        max_size: 8,
    },
];

/// `virtio_gpu_config` is 16 bytes (`events_read`, `events_clear`, `num_scanouts`, `num_capsets`).
#[cfg(not(test))]
pub(crate) const GPU_REQUEST: DeviceRequest = DeviceRequest {
    virtio_id: VIRTIO_ID_GPU,
    required_features: 0,
    optional_features: 0,
    queues: &GPU_QUEUES,
    min_device_cfg_len: 16,
};
#[cfg(not(test))]
const CONFIG_NUM_SCANOUTS: u32 = 8;

/// Bring-up (3) plus the largest present: detach, attach, 16 transfers, one flush.
const MAX_PRESENT_COMMANDS: usize = 3 + MAX_PRESENT_DAMAGE_RECTS;
pub(crate) const COMMAND_SLOTS: usize = 3 + MAX_PRESENT_COMMANDS + 2;
pub(crate) const SLOT_BYTES: usize = 1024;
const REQUEST_CAPACITY: usize = 512;
const RESPONSE_OFFSET: u32 = 512;
const _: () = assert!(COMMAND_SLOTS * 2 <= CONTROL_QUEUE_SIZE as usize);
const _: () = assert!(
    wire::ATTACH_HEADER_BYTES + MAX_EXTENTS_PER_BUFFER * wire::MEM_ENTRY_BYTES <= REQUEST_CAPACITY
);
const _: () = assert!(wire::DISPLAY_INFO_BYTES <= SLOT_BYTES - RESPONSE_OFFSET as usize);

const RESOURCE_ID: u32 = 1;
const SCANOUT_ID: u32 = 0;

/// `virtio_gpu` 2D wire format (VirtIO 1.2 §5.7.6), little-endian.
mod wire {
    pub(super) const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
    pub(super) const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
    pub(super) const CMD_RESOURCE_UNREF: u32 = 0x0102;
    pub(super) const CMD_SET_SCANOUT: u32 = 0x0103;
    pub(super) const CMD_RESOURCE_FLUSH: u32 = 0x0104;
    pub(super) const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
    pub(super) const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;
    pub(super) const CMD_RESOURCE_DETACH_BACKING: u32 = 0x0107;
    pub(super) const RESP_OK_NODATA: u32 = 0x1100;
    pub(super) const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
    pub(super) const FORMAT_B8G8R8X8_UNORM: u32 = 2;

    pub(super) const HEADER_BYTES: usize = 24;
    pub(super) const MAX_SCANOUTS: usize = 16;
    pub(super) const DISPLAY_ONE_BYTES: usize = 24;
    pub(super) const DISPLAY_INFO_BYTES: usize = HEADER_BYTES + MAX_SCANOUTS * DISPLAY_ONE_BYTES;
    pub(super) const ATTACH_HEADER_BYTES: usize = HEADER_BYTES + 8;
    pub(super) const MEM_ENTRY_BYTES: usize = 16;

    pub(super) fn put_u32(out: &mut [u8], offset: usize, value: u32) {
        out[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    pub(super) fn put_u64(out: &mut [u8], offset: usize, value: u64) {
        out[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    pub(super) fn get_u32(bytes: &[u8], offset: usize) -> u32 {
        let mut raw = [0u8; 4];
        raw.copy_from_slice(&bytes[offset..offset + 4]);
        u32::from_le_bytes(raw)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Command {
    GetDisplayInfo,
    Create2d,
    SetScanout,
    AttachBacking(u8),
    DetachBacking,
    Transfer(BufferRect),
    Flush(BufferRect),
    Unref,
}

impl Command {
    fn expected_response(self) -> u32 {
        match self {
            Self::GetDisplayInfo => wire::RESP_OK_DISPLAY_INFO,
            _ => wire::RESP_OK_NODATA,
        }
    }

    fn response_len(self) -> usize {
        match self {
            Self::GetDisplayInfo => wire::DISPLAY_INFO_BYTES,
            _ => wire::HEADER_BYTES,
        }
    }
}

const BRING_UP: [Command; 3] = [
    Command::GetDisplayInfo,
    Command::Create2d,
    Command::SetScanout,
];

fn full_mode_rect() -> BufferRect {
    BufferRect {
        x: 0,
        y: 0,
        width: REFERENCE_MODE.width_px as u16,
        height: REFERENCE_MODE.height_px as u16,
    }
}

fn put_rect(out: &mut [u8], offset: usize, rect: BufferRect) {
    wire::put_u32(out, offset, u32::from(rect.x));
    wire::put_u32(out, offset + 4, u32::from(rect.y));
    wire::put_u32(out, offset + 8, u32::from(rect.width));
    wire::put_u32(out, offset + 12, u32::from(rect.height));
}

/// Byte offset of `rect`'s first pixel in a reference-mode backing.
fn transfer_offset(rect: BufferRect) -> u64 {
    u64::from(rect.y) * u64::from(REFERENCE_MODE.stride_bytes) + u64::from(rect.x) * 4
}

/// Encodes `command` into `out`; returns the request length.
fn encode(
    command: Command,
    backings: &[Option<Backing>; SCANOUT_BUFFER_COUNT],
    out: &mut [u8; REQUEST_CAPACITY],
) -> Result<usize, BackendError> {
    out.fill(0);
    let (kind, len) = match command {
        Command::GetDisplayInfo => (wire::CMD_GET_DISPLAY_INFO, wire::HEADER_BYTES),
        Command::Create2d => {
            wire::put_u32(out, 24, RESOURCE_ID);
            wire::put_u32(out, 28, wire::FORMAT_B8G8R8X8_UNORM);
            wire::put_u32(out, 32, REFERENCE_MODE.width_px);
            wire::put_u32(out, 36, REFERENCE_MODE.height_px);
            (wire::CMD_RESOURCE_CREATE_2D, 40)
        }
        Command::Unref => {
            wire::put_u32(out, 24, RESOURCE_ID);
            (wire::CMD_RESOURCE_UNREF, 32)
        }
        Command::SetScanout => {
            put_rect(out, 24, full_mode_rect());
            wire::put_u32(out, 40, SCANOUT_ID);
            wire::put_u32(out, 44, RESOURCE_ID);
            (wire::CMD_SET_SCANOUT, 48)
        }
        Command::Flush(rect) => {
            put_rect(out, 24, rect);
            wire::put_u32(out, 40, RESOURCE_ID);
            (wire::CMD_RESOURCE_FLUSH, 48)
        }
        Command::Transfer(rect) => {
            put_rect(out, 24, rect);
            wire::put_u64(out, 40, transfer_offset(rect));
            wire::put_u32(out, 48, RESOURCE_ID);
            (wire::CMD_TRANSFER_TO_HOST_2D, 56)
        }
        Command::AttachBacking(index) => {
            let backing = backings
                .get(usize::from(index))
                .copied()
                .flatten()
                .ok_or(BackendError::SourceRejected)?;
            let extents = backing.extents();
            wire::put_u32(out, 24, RESOURCE_ID);
            wire::put_u32(out, 28, extents.len() as u32);
            for (entry, extent) in extents.iter().enumerate() {
                let offset = wire::ATTACH_HEADER_BYTES + entry * wire::MEM_ENTRY_BYTES;
                wire::put_u64(out, offset, extent.phys);
                wire::put_u32(out, offset + 8, extent.pages * PAGE_SIZE as u32);
            }
            (
                wire::CMD_RESOURCE_ATTACH_BACKING,
                wire::ATTACH_HEADER_BYTES + extents.len() * wire::MEM_ENTRY_BYTES,
            )
        }
        Command::DetachBacking => {
            wire::put_u32(out, 24, RESOURCE_ID);
            (wire::CMD_RESOURCE_DETACH_BACKING, 32)
        }
    };
    wire::put_u32(out, 0, kind);
    Ok(len)
}

/// Scanout 0 must be enabled at exactly the reference geometry.
fn display_info_matches(response: &[u8]) -> bool {
    let first = wire::HEADER_BYTES;
    let width = wire::get_u32(response, first + 8);
    let height = wire::get_u32(response, first + 12);
    let enabled = wire::get_u32(response, first + 16);
    enabled != 0 && width == REFERENCE_MODE.width_px && height == REFERENCE_MODE.height_px
}

fn bounding_rect(damage: &[BufferRect]) -> BufferRect {
    let left = damage.iter().map(|r| r.x).min().unwrap_or(0);
    let top = damage.iter().map(|r| r.y).min().unwrap_or(0);
    let right = damage.iter().map(|r| r.x + r.width).max().unwrap_or(0);
    let bottom = damage.iter().map(|r| r.y + r.height).max().unwrap_or(0);
    BufferRect {
        x: left,
        y: top,
        width: right - left,
        height: bottom - top,
    }
}

/// A bound buffer's validated backing: page-aligned extents covering exactly one reference frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Backing {
    source: FrameSourceId,
    extents: [PhysExtent; MAX_EXTENTS_PER_BUFFER],
    count: usize,
}

impl Backing {
    fn validate(source: &dyn FrameSource) -> Result<Self, BackendError> {
        let extents = source.phys_extents();
        if extents.is_empty() || extents.len() > MAX_EXTENTS_PER_BUFFER {
            return Err(BackendError::SourceRejected);
        }
        let mut total = 0u64;
        let mut copied = [PhysExtent { phys: 0, pages: 0 }; MAX_EXTENTS_PER_BUFFER];
        for (slot, extent) in copied.iter_mut().zip(extents) {
            if extent.pages == 0 || extent.phys % PAGE_SIZE != 0 {
                return Err(BackendError::SourceRejected);
            }
            let bytes = u64::from(extent.pages) * PAGE_SIZE;
            extent
                .phys
                .checked_add(bytes)
                .ok_or(BackendError::SourceRejected)?;
            total += bytes;
            *slot = *extent;
        }
        if total != REFERENCE_FRAME_BYTES as u64 {
            return Err(BackendError::SourceRejected);
        }
        Ok(Self {
            source: source.id(),
            extents: copied,
            count: extents.len(),
        })
    }

    fn extents(&self) -> &[PhysExtent] {
        &self.extents[..self.count]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Outstanding {
    token: Token,
    command: Command,
}

#[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct GpuStats {
    pub(crate) submitted: u32,
    pub(crate) completed: u32,
    pub(crate) attaches: u32,
    pub(crate) detaches: u32,
    pub(crate) transfers: u32,
    pub(crate) flushes: u32,
    pub(crate) transferred_bytes: u64,
    pub(crate) resets: u32,
}

/// One damage rect copied from a bound buffer, in submission order (self-test readback model).
#[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LoggedTransfer {
    pub(crate) buffer_index: u8,
    pub(crate) rect: BufferRect,
}

#[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
const TRANSFER_LOG: usize = 2 * MAX_PRESENT_DAMAGE_RECTS;

pub(crate) struct VirtioGpuBackend<T: VirtqueueTransport> {
    transport: T,
    slots: [DmaRegion; COMMAND_SLOTS],
    outstanding: [Option<Outstanding>; COMMAND_SLOTS],
    backings: [Option<Backing>; SCANOUT_BUFFER_COUNT],
    attached: Option<(u8, FrameSourceId)>,
    /// A submitted batch whose outcome `poll` has not reported yet.
    batch_open: bool,
    batch_error: Option<BackendError>,
    needs_reset: bool,
    clock: fn() -> u64,
    #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
    stats: GpuStats,
    #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
    hold_notify: bool,
    #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
    transfer_log: [Option<LoggedTransfer>; TRANSFER_LOG],
}

impl<T: VirtqueueTransport> VirtioGpuBackend<T> {
    pub(crate) fn new(transport: T, slots: [DmaRegion; COMMAND_SLOTS], clock: fn() -> u64) -> Self {
        Self {
            transport,
            slots,
            outstanding: [None; COMMAND_SLOTS],
            backings: [None; SCANOUT_BUFFER_COUNT],
            attached: None,
            batch_open: false,
            batch_error: None,
            needs_reset: false,
            clock,
            #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
            stats: GpuStats::default(),
            #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
            hold_notify: false,
            #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
            transfer_log: [None; TRANSFER_LOG],
        }
    }

    /// `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D`, `SET_SCANOUT`: the first `poll` outcome.
    pub(crate) fn begin_bring_up(&mut self) -> Result<(), BackendError> {
        self.submit_batch(&BRING_UP)
    }

    #[cfg(not(test))]
    pub(crate) fn into_transport(self) -> T {
        self.transport
    }

    fn submit_batch(&mut self, commands: &[Command]) -> Result<(), BackendError> {
        if self.needs_reset {
            return Err(BackendError::Failed);
        }
        let free = self
            .outstanding
            .iter()
            .filter(|slot| slot.is_none())
            .count();
        if commands.len() > free {
            return Err(BackendError::Failed);
        }
        let deadline =
            Deadline::MonotonicNs((self.clock)().saturating_add(DISPLAY_COMMAND_TIMEOUT_NS));
        for command in commands {
            let slot = self
                .outstanding
                .iter()
                .position(Option::is_none)
                .ok_or(BackendError::Failed)?;
            let mut request = [0u8; REQUEST_CAPACITY];
            let len = encode(*command, &self.backings, &mut request)?;
            let region = &mut self.slots[slot];
            let chain = region
                .copy_in(0, &request[..len])
                .and_then(|()| region.copy_in(RESPONSE_OFFSET, &[0u8; wire::HEADER_BYTES]))
                .and_then(|()| {
                    Ok([
                        region.readable(0, len as u32)?,
                        region.writable(RESPONSE_OFFSET, command.response_len() as u32)?,
                    ])
                })
                .map_err(|_| BackendError::Failed)?;
            match self.transport.submit(CONTROL_QUEUE, &chain, deadline) {
                Ok(token) => {
                    self.outstanding[slot] = Some(Outstanding {
                        token,
                        command: *command,
                    })
                }
                Err(error) => return Err(self.fail(error)),
            }
            #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
            self.count(*command);
        }
        self.batch_open = true;
        #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
        if core::mem::take(&mut self.hold_notify) {
            return Ok(());
        }
        self.transport
            .notify(CONTROL_QUEUE)
            .map_err(|error| self.fail(error))
    }

    #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
    fn count(&mut self, command: Command) {
        self.stats.submitted += 1;
        match command {
            Command::AttachBacking(_) => self.stats.attaches += 1,
            Command::DetachBacking => self.stats.detaches += 1,
            Command::Transfer(rect) => {
                self.stats.transfers += 1;
                self.stats.transferred_bytes += u64::from(rect.width) * u64::from(rect.height) * 4;
            }
            Command::Flush(_) => self.stats.flushes += 1,
            _ => {}
        }
    }

    /// Drops every outstanding command after a transport failure and latches `needs_reset`.
    fn fail(&mut self, error: TransportError) -> BackendError {
        self.outstanding = [None; COMMAND_SLOTS];
        self.batch_open = false;
        self.batch_error = None;
        self.needs_reset = true;
        match (error, self.transport.state()) {
            (_, TransportState::ResetRequired(ResetReason::Timeout)) => BackendError::Timeout,
            _ => BackendError::Failed,
        }
    }

    fn check_response(&mut self, slot: usize, command: Command, written_len: u32) {
        let mut response = [0u8; wire::DISPLAY_INFO_BYTES];
        let response = &mut response[..command.response_len()];
        let read = self.slots[slot].copy_out(RESPONSE_OFFSET, response);
        let ok = read.is_ok()
            && written_len as usize >= response.len()
            && wire::get_u32(response, 0) == command.expected_response()
            && (command != Command::GetDisplayInfo || display_info_matches(response));
        if !ok {
            self.batch_error.get_or_insert(BackendError::Failed);
            self.needs_reset = true;
        }
    }

    fn outstanding_count(&self) -> usize {
        self.outstanding.iter().flatten().count()
    }
}

#[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
impl<T: VirtqueueTransport> VirtioGpuBackend<T> {
    pub(crate) fn stats(&self) -> GpuStats {
        self.stats
    }

    pub(crate) fn generation(&self) -> u32 {
        self.transport.generation()
    }

    /// No batch is waiting for its outcome.
    pub(crate) fn is_idle(&self) -> bool {
        !self.batch_open
    }

    /// The next batch is published but not notified: with `ioeventfd=off` the device never sees
    /// it, so only the W3 deadline can end it.
    pub(crate) fn hold_next_notify(&mut self) {
        self.hold_notify = true;
    }

    pub(crate) fn transfer_log(&self) -> impl Iterator<Item = LoggedTransfer> + '_ {
        self.transfer_log.iter().flatten().copied()
    }

    /// Detaches the backing and unreferences the resource; the outcome is the next `poll`.
    pub(crate) fn begin_release(&mut self) -> Result<(), BackendError> {
        let detach = self.attached.take().is_some();
        let commands = [Command::DetachBacking, Command::Unref];
        self.submit_batch(if detach { &commands } else { &commands[1..] })
    }

    fn log_transfer(&mut self, buffer_index: u8, rect: BufferRect) {
        if let Some(entry) = self.transfer_log.iter_mut().find(|entry| entry.is_none()) {
            *entry = Some(LoggedTransfer { buffer_index, rect });
        }
    }
}

impl<T: VirtqueueTransport> ScanoutBackend for VirtioGpuBackend<T> {
    fn mode(&self) -> DisplayMode {
        REFERENCE_MODE
    }

    fn bind(&mut self, index: u8, source: &dyn FrameSource) -> Result<(), BackendError> {
        let backing = Backing::validate(source)?;
        let slot = self
            .backings
            .get_mut(usize::from(index))
            .ok_or(BackendError::SourceRejected)?;
        *slot = Some(backing);
        Ok(())
    }

    fn submit(
        &mut self,
        index: u8,
        source: &dyn FrameSource,
        damage: &[BufferRect],
    ) -> Result<Submitted, BackendError> {
        let backing = self
            .backings
            .get(usize::from(index))
            .copied()
            .flatten()
            .filter(|backing| backing.source == source.id())
            .ok_or(BackendError::SourceRejected)?;
        if damage.is_empty() || damage.len() > MAX_PRESENT_DAMAGE_RECTS {
            return Err(BackendError::SourceRejected);
        }
        let mut commands = [Command::Unref; MAX_PRESENT_COMMANDS];
        let mut count = 0;
        let mut push = |command| {
            commands[count] = command;
            count += 1;
        };
        let attach = self.attached != Some((index, backing.source));
        if attach {
            if self.attached.is_some() {
                push(Command::DetachBacking);
            }
            push(Command::AttachBacking(index));
        }
        for rect in damage {
            push(Command::Transfer(*rect));
        }
        push(Command::Flush(bounding_rect(damage)));
        self.submit_batch(&commands[..count])?;
        self.attached = Some((index, backing.source));
        #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
        for rect in damage {
            self.log_transfer(index, *rect);
        }
        Ok(Submitted::Pending)
    }

    fn poll(&mut self) -> Option<Result<(), BackendError>> {
        if !self.batch_open {
            return None;
        }
        loop {
            match self.transport.take_completion(CONTROL_QUEUE) {
                Ok(Some(completion)) => {
                    let slot = self.outstanding.iter().position(|outstanding| {
                        outstanding.is_some_and(|outstanding| outstanding.token == completion.token)
                    });
                    let Some(slot) = slot else {
                        self.fail(TransportError::StaleToken);
                        return Some(Err(BackendError::Failed));
                    };
                    let command = self.outstanding[slot].take().map(|o| o.command)?;
                    #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
                    {
                        self.stats.completed += 1;
                    }
                    self.check_response(slot, command, completion.written_len);
                }
                Ok(None) => break,
                Err(error) => return Some(Err(self.fail(error))),
            }
        }
        if self.outstanding_count() != 0 {
            return None;
        }
        self.batch_open = false;
        Some(self.batch_error.take().map_or(Ok(()), Err))
    }

    fn reset(&mut self) -> Result<Submitted, BackendError> {
        self.outstanding = [None; COMMAND_SLOTS];
        self.batch_open = false;
        self.batch_error = None;
        self.attached = None;
        self.transport.reset().map_err(|_| BackendError::Failed)?;
        self.needs_reset = false;
        #[cfg(any(test, feature = "m10-virtio-gpu-self-test"))]
        {
            self.stats.resets += 1;
        }
        self.begin_bring_up()?;
        Ok(Submitted::Pending)
    }
}

#[cfg(not(test))]
pub(crate) type MmioGpuBackend = VirtioGpuBackend<crate::device::virtio::modern::MmioTransport>;
#[cfg(test)]
pub(crate) type MmioGpuBackend = VirtioGpuBackend<fake::FakeGpu>;

#[cfg(not(test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GpuInitError {
    DisplayPresent,
    Installed,
    Transport(TransportError),
    NoScanout,
    Dma,
    Mode,
    BringUp,
}

#[cfg(not(test))]
impl GpuInitError {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::DisplayPresent => "display-present",
            Self::Installed => "installed",
            Self::Transport(TransportError::NotFound) => "absent",
            Self::Transport(_) => "transport",
            Self::NoScanout => "no-scanout",
            Self::Dma => "dma",
            Self::Mode => "mode",
            Self::BringUp => "bring-up",
        }
    }
}

#[cfg(not(test))]
mod slots {
    use core::ptr::addr_of_mut;
    use core::sync::atomic::{AtomicBool, Ordering};

    use super::{COMMAND_SLOTS, SLOT_BYTES};
    use crate::device::virtio::dma::DmaRegion;

    const PAGES: usize = COMMAND_SLOTS * SLOT_BYTES / 4096;
    const _: () = assert!(PAGES * 4096 == COMMAND_SLOTS * SLOT_BYTES);

    #[repr(C, align(4096))]
    struct CommandPages([u8; PAGES * 4096]);

    static mut COMMAND_PAGES: CommandPages = CommandPages([0; PAGES * 4096]);
    static TAKEN: AtomicBool = AtomicBool::new(false);

    /// The command slots, once per boot. Each slot sits inside one page, so its physical range is
    /// contiguous whatever the kernel image's page layout.
    pub(super) fn take() -> Option<[DmaRegion; COMMAND_SLOTS]> {
        if TAKEN.swap(true, Ordering::AcqRel) {
            return None;
        }
        // SAFETY: `TAKEN` hands the pages out once; the regions own them for the rest of the boot.
        let pages = unsafe { &mut (*addr_of_mut!(COMMAND_PAGES)).0 };
        let mut chunks = pages.chunks_mut(SLOT_BYTES);
        let regions: [Option<DmaRegion>; COMMAND_SLOTS] = core::array::from_fn(|_| {
            chunks
                .next()
                .and_then(|chunk| DmaRegion::from_static(chunk).ok())
        });
        if regions.iter().any(Option::is_none) {
            return None;
        }
        Some(regions.map(|region| region.expect("checked above")))
    }
}

#[cfg(not(test))]
static INSTALLED: crate::sync::global_cell::GlobalCell<Option<MmioGpuBackend>> =
    crate::sync::global_cell::GlobalCell::new(None);

/// Moves the boot's one GPU backend into its static; the returned borrow is the display's.
#[cfg(not(test))]
pub(crate) fn install(
    backend: MmioGpuBackend,
) -> Result<&'static mut MmioGpuBackend, GpuInitError> {
    crate::arch::x86_64::cpu::without_interrupts(|| {
        // SAFETY: single CPU with interrupts masked; once installed, the slot is only reached
        // through the returned borrow (and `take_installed` after the display dropped it).
        let slot = unsafe { &mut *INSTALLED.get() };
        if slot.is_some() {
            backend.into_transport().release();
            return Err(GpuInitError::Installed);
        }
        Ok(slot.insert(backend))
    })
}

/// Moves the backend back out once the display that borrowed it is gone (self-test release).
#[cfg(all(not(test), feature = "m10-virtio-gpu-self-test"))]
pub(crate) fn take_installed() -> Option<MmioGpuBackend> {
    // SAFETY: as in `install`; the caller already dropped the display's borrow.
    crate::arch::x86_64::cpu::without_interrupts(|| unsafe { (*INSTALLED.get()).take() })
}

/// Discovers the GPU, checks it has a scanout, and submits the bring-up batch.
#[cfg(not(test))]
pub(crate) fn begin_mmio(sink: fn()) -> Result<MmioGpuBackend, GpuInitError> {
    use crate::device::virtio::modern::MmioTransport;

    let mut transport =
        MmioTransport::discover(&GPU_REQUEST, sink).map_err(GpuInitError::Transport)?;
    let scanouts = transport.read_device_config(|config| config.read_u32(CONFIG_NUM_SCANOUTS));
    let error = match scanouts {
        Ok((0, _)) => Some(GpuInitError::NoScanout),
        Ok(_) => None,
        Err(error) => Some(GpuInitError::Transport(error)),
    };
    if let Some(error) = error {
        transport.release();
        return Err(error);
    }
    let Some(slots) = slots::take() else {
        transport.release();
        return Err(GpuInitError::Dma);
    };
    let mut backend = VirtioGpuBackend::new(transport, slots, crate::time::monotonic_ns);
    if backend.begin_bring_up().is_err() {
        backend.into_transport().release();
        return Err(GpuInitError::BringUp);
    }
    Ok(backend)
}

#[cfg(test)]
pub(crate) mod fake;

#[cfg(test)]
mod tests;
