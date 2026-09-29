//! VirtIO 1.x modern PCI transport (#196): capability discovery, the
//! fail-closed status/feature state machine, split virtqueues with 64-bit ring
//! addresses, MSI-X or INTx completion interrupts, per-device request timeouts
//! (W3) and a real reset that strands every earlier token.
//!
//! Nothing here waits (W4). A consumer submits and notifies; the queue
//! interrupt, or the device's W3 timeout firing from the timer path, runs the
//! consumer's sink; the consumer then harvests with
//! [`VirtqueueTransport::take_completion`] or learns the deadline to block on
//! from [`step_completion`]. Multi-step device init is a state machine advanced
//! by those notifications, with every command under the same timeout.
//!
//! The legacy block/net drivers never reach this module: it matches only
//! modern-only device IDs (`0x1040 + id`, revision >= 1).

#![cfg_attr(not(feature = "m10-virtio-modern-self-test"), allow(dead_code))]

pub(crate) mod caps;
#[cfg(test)]
mod fake;
pub(crate) mod features;
pub(crate) mod regs;

use core::ptr::read_volatile;
use core::sync::atomic::{fence, Ordering};

use caps::{
    check_device_identity, decode_modern_layout, notify_address, BarKind, Bars, CapError, CapKind,
    ModernLayout, Region, VIRTIO_PCI_MODERN_DEVICE_BASE, VIRTIO_PCI_VENDOR_ID,
};
use features::{negotiate, NegotiationError, DEVICE_CLASS_MASK};
use regs::{
    check_window, AccessError, DeviceAccess, Width, Window, CONFIG_GENERATION, CONFIG_MSIX_VECTOR,
    DEVICE_FEATURE, DEVICE_FEATURE_SELECT, DEVICE_STATUS, DRIVER_FEATURE, DRIVER_FEATURE_SELECT,
    ISR_CONFIG, ISR_QUEUE, NO_VECTOR, NUM_QUEUES, QUEUE_DESC, QUEUE_DEVICE, QUEUE_DRIVER,
    QUEUE_ENABLE, QUEUE_MSIX_VECTOR, QUEUE_NOTIFY_OFF, QUEUE_SELECT, QUEUE_SIZE,
    STATUS_ACKNOWLEDGE, STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED,
    STATUS_FEATURES_OK,
};

use super::dma::{kernel_physical_range, DmaSegment};
use super::virtqueue::{Completion, QueueError, SplitQueue, Token, MAX_QUEUE_SIZE};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::device::pci::{
    find_single_function, intx_gsi, release_intx, revision_id, route_intx, IntxRoute,
    MsixCapability, PciFunction, PCI_COMMAND_BUS_MASTER, PCI_COMMAND_MEMORY_SPACE,
};
use crate::diagnostics::log::kernel_log_fmt;
use crate::interrupt::irq::{
    allocate_device_vector, gsi_is_routed, msi_message, release_device_vector,
};
use crate::mm::mmio::with_kernel_identity_mmio;
use crate::sched::timeout::{self, CancelOutcome, TimeoutHandle};
use crate::sched::wait::Deadline;
use crate::sync::global_cell::GlobalCell;

/// Probe device plus the #114 GPU.
pub(crate) const MAX_MODERN_DEVICES: usize = 2;
pub(crate) const MAX_QUEUES_PER_DEVICE: usize = 2;
/// Bounded read-back of a status-0 write; QEMU resets inside the write.
const MAX_RESET_READS: usize = 4;
/// A device whose config changes four times inside one read loop is misbehaving.
pub(crate) const MAX_CONFIG_GENERATION_ATTEMPTS: u8 = 4;
/// Every queue shares MSI-X table entry 0; config changes get no vector.
const MSIX_QUEUE_ENTRY: u16 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct QueueRequest {
    pub(crate) index: u16,
    /// Power of two; the transport uses `min(device max, max_size, 256)`.
    pub(crate) max_size: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DeviceRequest {
    pub(crate) virtio_id: u16,
    /// Device-class bits only (0..=23); `VERSION_1` is always negotiated.
    pub(crate) required_features: u64,
    pub(crate) optional_features: u64,
    pub(crate) queues: &'static [QueueRequest],
    /// Nonzero requires a device-config region at least this long.
    pub(crate) min_device_cfg_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportError {
    NotFound,
    Multiple,
    AlreadyClaimed,
    SlotsExhausted,
    Capability(CapError),
    /// A region is not identity-mapped in the kernel root.
    MmioUnmapped,
    /// A register access fell outside its window.
    InvalidAccess,
    InvalidRequest,
    FeatureRequired(u64),
    FeaturesRejected,
    ResetStuck,
    QueueUnavailable,
    StaleQueueEnable,
    MsixVectorRejected,
    DeviceNeedsReset,
    Interrupt(&'static str),
    NoVector,
    IrqShared,
    Dma,
    ConfigUnstable,
    ResetRequired,
    Poisoned,
    StaleToken,
    QueueFull,
    InvalidChain,
    TimeoutsExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetReason {
    Timeout,
    ProtocolViolation,
    DeviceNeedsReset,
    ConfigUnstable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PoisonReason {
    ResetStuck,
    BringUpFailed(TransportError),
    GenerationExhausted,
    InterruptLost,
}

/// `Released` is not a state: [`ModernTransport::release`] consumes the transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransportState {
    Ready,
    ResetRequired(ResetReason),
    Poisoned(PoisonReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IrqMode {
    Msix,
    Intx,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InterruptRoute {
    Msix { vector: u8 },
    Intx { vector: u8, gsi: u32 },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct InterruptStats {
    pub(crate) queue: u64,
    pub(crate) config: u64,
    pub(crate) spurious: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReleaseReport {
    /// The device read back status 0 before its interrupts and slot were freed.
    pub(crate) device_reset: bool,
}

/// What a waiter does next for `queue` (see [`step_completion`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitStep {
    Complete(Completion),
    /// Block until the queue interrupt or this deadline (the earliest in flight).
    Wait(Deadline),
    /// Nothing is in flight.
    Idle,
}

/// The queue operations a device driver (#114) runs against; host fakes
/// implement it to test driver state machines.
pub(crate) trait VirtqueueTransport {
    /// Current state, folding in any timeout or interrupt failure recorded
    /// since the last call.
    fn state(&mut self) -> TransportState;
    fn generation(&self) -> u32;
    /// Publish `chain` on `queue`; the device sees it at the next [`Self::notify`].
    /// The device moves to `ResetRequired(Timeout)` if the request is still
    /// in flight at `deadline`.
    fn submit(
        &mut self,
        queue: u16,
        chain: &[DmaSegment],
        deadline: Deadline,
    ) -> Result<Token, TransportError>;
    fn notify(&mut self, queue: u16) -> Result<(), TransportError>;
    fn take_completion(&mut self, queue: u16) -> Result<Option<Completion>, TransportError>;
    /// Whether `token`'s request is still owned by the device; `StaleToken`
    /// for a token from before the last reset.
    fn token_in_flight(&self, token: Token) -> Result<bool, TransportError>;
    fn earliest_deadline(&self) -> Option<Deadline>;
    /// Reset the device, drop every in-flight request, and bring it up again
    /// under a new generation. Failure is permanent (`Poisoned`).
    fn reset(&mut self) -> Result<(), TransportError>;
}

/// Harvest one completion of `queue`, or say what to wait for. Callers step
/// with interrupts masked and block (or halt) in the same masked section, so a
/// completion cannot land between the check and the wait.
pub(crate) fn step_completion<T: VirtqueueTransport>(
    transport: &mut T,
    queue: u16,
) -> Result<WaitStep, TransportError> {
    if let Some(completion) = transport.take_completion(queue)? {
        return Ok(WaitStep::Complete(completion));
    }
    Ok(match transport.earliest_deadline() {
        Some(deadline) => WaitStep::Wait(deadline),
        None => WaitStep::Idle,
    })
}

fn ignore_interrupt() {}

/// Per-slot state shared with the interrupt and timeout handlers, accessed
/// with interrupts masked.
#[derive(Clone, Copy)]
struct SlotShared {
    claimed: bool,
    function: Option<PciFunction>,
    sink: fn(),
    /// Generation of the transport in this slot; handlers for older ones are ignored.
    generation: u32,
    timed_out: bool,
    interrupt_lost: bool,
    /// ISR byte read to acknowledge INTx; `None` with MSI-X, where it is never read.
    intx: Option<IntxBinding>,
    stats: InterruptStats,
}

#[derive(Clone, Copy)]
struct IntxBinding {
    isr_phys: u64,
    function: PciFunction,
    route: IntxRoute,
    released: bool,
}

impl SlotShared {
    const FREE: Self = Self {
        claimed: false,
        function: None,
        sink: ignore_interrupt,
        generation: 0,
        timed_out: false,
        interrupt_lost: false,
        intx: None,
        stats: InterruptStats {
            queue: 0,
            config: 0,
            spurious: 0,
        },
    };
}

static SLOTS: GlobalCell<[SlotShared; MAX_MODERN_DEVICES]> =
    GlobalCell::new([SlotShared::FREE; MAX_MODERN_DEVICES]);

/// Ring memory of each slot's queues, owned by whoever holds the slot claim.
static QUEUE_POOL: GlobalCell<[[SplitQueue; MAX_QUEUES_PER_DEVICE]; MAX_MODERN_DEVICES]> =
    GlobalCell::new([const { [SplitQueue::EMPTY; MAX_QUEUES_PER_DEVICE] }; MAX_MODERN_DEVICES]);

fn slots_mut() -> &'static mut [SlotShared; MAX_MODERN_DEVICES] {
    unsafe { &mut *SLOTS.get() }
}

const SLOT_HANDLERS: [fn(); MAX_MODERN_DEVICES] = [modern_irq_slot0, modern_irq_slot1];

fn modern_irq_slot0() {
    on_device_interrupt(0);
}

fn modern_irq_slot1() {
    on_device_interrupt(1);
}

/// Interrupt context: count, acknowledge INTx through the ISR, run the sink.
fn on_device_interrupt(slot: usize) {
    let shared = &mut slots_mut()[slot];
    if !shared.claimed {
        return;
    }
    let Some(intx) = shared.intx.as_mut() else {
        shared.stats.queue = shared.stats.queue.saturating_add(1);
        (shared.sink)();
        return;
    };
    // SAFETY: the ISR byte was validated inside its BAR and identity-mapped at discovery.
    match with_kernel_identity_mmio(intx.isr_phys, 1, |va| unsafe {
        read_volatile(va as *const u8)
    }) {
        Ok(0) => shared.stats.spurious = shared.stats.spurious.saturating_add(1),
        Ok(isr) => {
            if isr & ISR_QUEUE != 0 {
                shared.stats.queue = shared.stats.queue.saturating_add(1);
            }
            if isr & ISR_CONFIG != 0 {
                shared.stats.config = shared.stats.config.saturating_add(1);
            }
            (shared.sink)();
        }
        Err(_) => {
            // The line stays asserted until the ISR is read: silence it rather
            // than take a level-triggered storm, and fail the device closed.
            if !intx.released {
                intx.released = true;
                release_intx(intx.function, intx.route);
            }
            shared.interrupt_lost = true;
            (shared.sink)();
        }
    }
}

/// W3 handler (timer interrupt context): mark the slot's transport timed out
/// if it is still the generation that armed it, and tell the consumer.
fn on_request_timeout(context: u64) {
    let slot = (context >> 32) as usize;
    let generation = context as u32;
    let sink = without_interrupts(|| {
        let shared = slots_mut().get_mut(slot)?;
        if !shared.claimed || shared.generation != generation {
            return None;
        }
        shared.timed_out = true;
        Some(shared.sink)
    });
    if let Some(sink) = sink {
        sink();
    }
}

fn timeout_context(slot: usize, generation: u32) -> u64 {
    ((slot as u64) << 32) | u64::from(generation)
}

/// Claim a free slot for `function` (host tests pass `None`) and its queue memory.
fn claim_slot(
    function: Option<PciFunction>,
    sink: fn(),
) -> Result<(usize, u32, &'static mut [SplitQueue; MAX_QUEUES_PER_DEVICE]), TransportError> {
    let (slot, generation) = without_interrupts(|| {
        let slots = slots_mut();
        if function.is_some()
            && slots
                .iter()
                .any(|shared| shared.claimed && shared.function == function)
        {
            return Err(TransportError::AlreadyClaimed);
        }
        let slot = slots
            .iter()
            .position(|shared| !shared.claimed)
            .ok_or(TransportError::SlotsExhausted)?;
        let generation = slots[slot]
            .generation
            .checked_add(1)
            .ok_or(TransportError::SlotsExhausted)?;
        slots[slot] = SlotShared {
            claimed: true,
            function,
            sink,
            generation,
            ..SlotShared::FREE
        };
        Ok((slot, generation))
    })?;
    // SAFETY: the claim above makes this slot's queue memory exclusively ours
    // until `release_slot`.
    let queues = unsafe { &mut (*QUEUE_POOL.get())[slot] };
    Ok((slot, generation, queues))
}

/// Free `slot`; its generation survives so a later claim strands older tokens.
fn release_slot(slot: usize) {
    without_interrupts(|| {
        let generation = slots_mut()[slot].generation;
        slots_mut()[slot] = SlotShared {
            generation,
            ..SlotShared::FREE
        };
    });
}

/// PCI resources a kernel transport releases; host-test transports have none.
struct PciBinding {
    function: PciFunction,
    route: InterruptRoute,
    msix: Option<MsixCapability>,
}

/// A modern VirtIO device bound to a slot. Generic over its register access so
/// the state machine runs against a device model in host tests.
pub(crate) struct ModernTransport<A: DeviceAccess> {
    access: A,
    slot: usize,
    layout: ModernLayout,
    request: DeviceRequest,
    irq_mode: IrqMode,
    features: u64,
    generation: u32,
    state: TransportState,
    queues: &'static mut [SplitQueue; MAX_QUEUES_PER_DEVICE],
    notify_addresses: [u64; MAX_QUEUES_PER_DEVICE],
    /// Armed while any request is in flight, at the earliest in-flight deadline.
    timeout: Option<(TimeoutHandle, u64)>,
    pci: Option<PciBinding>,
}

fn access_error(error: AccessError) -> TransportError {
    match error {
        AccessError::OutOfWindow => TransportError::InvalidAccess,
        AccessError::Unmapped => TransportError::MmioUnmapped,
    }
}

fn queue_error(error: QueueError) -> TransportError {
    match error {
        QueueError::InvalidChain => TransportError::InvalidChain,
        QueueError::QueueFull => TransportError::QueueFull,
        QueueError::ProtocolViolation => TransportError::ResetRequired,
    }
}

fn validate_request(request: &DeviceRequest) -> Result<(), TransportError> {
    let queues = request.queues;
    let features = request.required_features | request.optional_features;
    if queues.is_empty()
        || queues.len() > MAX_QUEUES_PER_DEVICE
        || features & !DEVICE_CLASS_MASK != 0
    {
        return Err(TransportError::InvalidRequest);
    }
    for (position, queue) in queues.iter().enumerate() {
        if queue.max_size == 0
            || !queue.max_size.is_power_of_two()
            || queues[..position]
                .iter()
                .any(|other| other.index == queue.index)
        {
            return Err(TransportError::InvalidRequest);
        }
    }
    Ok(())
}

impl<A: DeviceAccess> ModernTransport<A> {
    /// Validate `request` and claim a slot without touching the device.
    /// `initialize` brings it up; after a failed bring-up the device is FAILED
    /// with bus mastering off, and only `release()` frees its interrupts and slot.
    fn attach(
        access: A,
        layout: ModernLayout,
        request: DeviceRequest,
        irq_mode: IrqMode,
        sink: fn(),
        function: Option<PciFunction>,
    ) -> Result<Self, TransportError> {
        validate_request(&request)?;
        if request.min_device_cfg_len > 0
            && layout
                .device
                .is_none_or(|device| device.length < request.min_device_cfg_len)
        {
            return Err(TransportError::Capability(CapError::Missing(
                CapKind::Device,
            )));
        }
        let (slot, generation, queues) = claim_slot(function, sink)?;
        Ok(Self {
            access,
            slot,
            layout,
            request,
            irq_mode,
            features: 0,
            generation,
            state: TransportState::Ready,
            queues,
            notify_addresses: [0; MAX_QUEUES_PER_DEVICE],
            timeout: None,
            pci: None,
        })
    }

    fn initialize(&mut self) -> Result<(), TransportError> {
        self.reset_device()?;
        if let Err(error) = self.bring_up_after_reset() {
            self.fail_device();
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn negotiated_features(&self) -> u64 {
        self.features
    }

    pub(crate) fn layout(&self) -> &ModernLayout {
        &self.layout
    }

    pub(crate) fn queue_size(&self, queue: u16) -> Option<u16> {
        self.queue_position(queue)
            .ok()
            .map(|position| self.queues[position].size())
    }

    pub(crate) fn interrupt_stats(&self) -> InterruptStats {
        without_interrupts(|| slots_mut()[self.slot].stats)
    }

    /// Read device config through the generation loop: `read` runs until the
    /// generation is unchanged across it, at most four times. Returns the value
    /// and the attempts used; an unstable config is `ResetRequired`.
    pub(crate) fn read_device_config<R>(
        &mut self,
        mut read: impl FnMut(&mut DeviceConfigReader<'_, A>) -> Result<R, TransportError>,
    ) -> Result<(R, u8), TransportError> {
        self.ensure_ready()?;
        let length = self.device_config_length()?;
        for attempt in 1..=MAX_CONFIG_GENERATION_ATTEMPTS {
            let before = self.read_common(CONFIG_GENERATION, Width::U8)?;
            let value = read(&mut DeviceConfigReader {
                access: &mut self.access,
                length,
            })?;
            if self.read_common(CONFIG_GENERATION, Width::U8)? == before {
                return Ok((value, attempt));
            }
        }
        self.require_reset(ResetReason::ConfigUnstable);
        Err(TransportError::ConfigUnstable)
    }

    #[cfg(test)]
    pub(crate) fn write_device_config_u32(
        &mut self,
        offset: u32,
        value: u32,
    ) -> Result<(), TransportError> {
        self.ensure_ready()?;
        check_window(self.device_config_length()?, offset, Width::U32).map_err(access_error)?;
        self.access
            .write(Window::Device, offset, Width::U32, value)
            .map_err(access_error)
    }

    /// Stop the device and free the slot: reset (bounded read-back), bus
    /// mastering off, interrupts masked and freed, then the claim. Every step
    /// runs even if an earlier one failed.
    pub(crate) fn release(mut self) -> ReleaseReport {
        if let Some((handle, _)) = self.timeout.take() {
            timeout::cancel(handle);
        }
        let device_reset = self.reset_device().is_ok();
        self.access.set_bus_master(false);
        if let Some(binding) = self.pci.take() {
            release_interrupts(self.slot, &binding);
        }
        release_slot(self.slot);
        ReleaseReport { device_reset }
    }

    fn device_config_length(&self) -> Result<u32, TransportError> {
        self.layout
            .device
            .map(|device| device.length)
            .ok_or(TransportError::Capability(CapError::Missing(
                CapKind::Device,
            )))
    }

    fn queue_position(&self, queue: u16) -> Result<usize, TransportError> {
        self.request
            .queues
            .iter()
            .position(|request| request.index == queue)
            .ok_or(TransportError::InvalidRequest)
    }

    fn read_common(&mut self, offset: u32, width: Width) -> Result<u32, TransportError> {
        self.access
            .read(Window::Common, offset, width)
            .map_err(access_error)
    }

    fn write_common(
        &mut self,
        offset: u32,
        width: Width,
        value: u32,
    ) -> Result<(), TransportError> {
        self.access
            .write(Window::Common, offset, width, value)
            .map_err(access_error)
    }

    fn read_status(&mut self) -> Result<u8, TransportError> {
        Ok(self.read_common(DEVICE_STATUS, Width::U8)? as u8)
    }

    fn write_status(&mut self, status: u8) -> Result<(), TransportError> {
        self.write_common(DEVICE_STATUS, Width::U8, u32::from(status))
    }

    fn write_u64_pair(&mut self, offset: u32, value: u64) -> Result<(), TransportError> {
        self.write_common(offset, Width::U32, value as u32)?;
        self.write_common(offset + 4, Width::U32, (value >> 32) as u32)
    }

    /// Write status 0 and read it back until 0, at most [`MAX_RESET_READS`]
    /// times. Once it reads 0 the device has stopped touching the rings.
    fn reset_device(&mut self) -> Result<(), TransportError> {
        self.write_status(0)?;
        for _ in 0..MAX_RESET_READS {
            if self.read_status()? == 0 {
                return Ok(());
            }
        }
        Err(TransportError::ResetStuck)
    }

    /// virtio 1.2 §3.1.1 from a device that reads back status 0.
    fn bring_up_after_reset(&mut self) -> Result<(), TransportError> {
        self.write_status(STATUS_ACKNOWLEDGE)?;
        self.write_status(STATUS_ACKNOWLEDGE | STATUS_DRIVER)?;

        let mut offered = 0u64;
        for select in 0..2u32 {
            self.write_common(DEVICE_FEATURE_SELECT, Width::U32, select)?;
            offered |= u64::from(self.read_common(DEVICE_FEATURE, Width::U32)?) << (32 * select);
        }
        let accepted = negotiate(
            offered,
            self.request.required_features,
            self.request.optional_features,
        )
        .map_err(|error| match error {
            NegotiationError::InvalidRequest => TransportError::InvalidRequest,
            NegotiationError::FeatureRequired(missing) => TransportError::FeatureRequired(missing),
        })?;
        for select in 0..2u32 {
            self.write_common(DRIVER_FEATURE_SELECT, Width::U32, select)?;
            self.write_common(
                DRIVER_FEATURE,
                Width::U32,
                (accepted >> (32 * select)) as u32,
            )?;
        }
        let features_ok = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK;
        self.write_status(features_ok)?;
        if self.read_status()? & STATUS_FEATURES_OK == 0 {
            return Err(TransportError::FeaturesRejected);
        }
        self.features = accepted;

        self.write_common(CONFIG_MSIX_VECTOR, Width::U16, u32::from(NO_VECTOR))?;
        let num_queues = self.read_common(NUM_QUEUES, Width::U16)?;
        for position in 0..self.request.queues.len() {
            let queue = self.request.queues[position];
            if u32::from(queue.index) >= num_queues {
                return Err(TransportError::QueueUnavailable);
            }
            self.set_up_queue(position, queue)?;
        }

        self.access.set_bus_master(true);
        self.write_status(features_ok | STATUS_DRIVER_OK)?;
        if self.read_status()? & (STATUS_DEVICE_NEEDS_RESET | STATUS_FAILED) != 0 {
            return Err(TransportError::DeviceNeedsReset);
        }
        Ok(())
    }

    fn set_up_queue(
        &mut self,
        position: usize,
        request: QueueRequest,
    ) -> Result<(), TransportError> {
        self.write_common(QUEUE_SELECT, Width::U16, u32::from(request.index))?;
        let device_max = self.read_common(QUEUE_SIZE, Width::U16)? as u16;
        if device_max == 0 || !device_max.is_power_of_two() {
            return Err(TransportError::QueueUnavailable);
        }
        if self.read_common(QUEUE_ENABLE, Width::U16)? != 0 {
            return Err(TransportError::StaleQueueEnable);
        }
        let size = device_max.min(request.max_size).min(MAX_QUEUE_SIZE);
        self.write_common(QUEUE_SIZE, Width::U16, u32::from(size))?;

        let queue = &mut self.queues[position];
        if !queue.configure(request.index, size, self.generation) {
            return Err(TransportError::QueueUnavailable);
        }
        let mut rings = [0u64; 3];
        for (ring, area) in rings.iter_mut().zip(queue.area_pointers()) {
            *ring = self
                .access
                .dma_address(area, crate::mm::PAGE_SIZE as usize)
                .map_err(|_| TransportError::Dma)?;
        }
        self.write_u64_pair(QUEUE_DESC, rings[0])?;
        self.write_u64_pair(QUEUE_DRIVER, rings[1])?;
        self.write_u64_pair(QUEUE_DEVICE, rings[2])?;

        let vector = match self.irq_mode {
            IrqMode::Msix => MSIX_QUEUE_ENTRY,
            IrqMode::Intx => NO_VECTOR,
        };
        self.write_common(QUEUE_MSIX_VECTOR, Width::U16, u32::from(vector))?;
        if self.read_common(QUEUE_MSIX_VECTOR, Width::U16)? != u32::from(vector) {
            return Err(TransportError::MsixVectorRejected);
        }

        let notify_off = self.read_common(QUEUE_NOTIFY_OFF, Width::U16)? as u16;
        self.notify_addresses[position] = notify_address(
            &self.layout.notify,
            self.layout.notify_off_multiplier,
            notify_off,
        )
        .map_err(TransportError::Capability)?;
        self.write_common(QUEUE_ENABLE, Width::U16, 1)
    }

    /// Best effort: FAILED, bus mastering off, timeout cancelled.
    fn fail_device(&mut self) {
        if let Some((handle, _)) = self.timeout.take() {
            timeout::cancel(handle);
        }
        let status = self.read_status().unwrap_or(0);
        let _ = self.write_status(status | STATUS_FAILED);
        self.access.set_bus_master(false);
    }

    fn poison(&mut self, reason: PoisonReason) -> TransportError {
        self.fail_device();
        self.state = TransportState::Poisoned(reason);
        TransportError::Poisoned
    }

    fn timed_out(&mut self) -> TransportError {
        self.timeout = None;
        self.state = TransportState::ResetRequired(ResetReason::Timeout);
        TransportError::ResetRequired
    }

    /// A non-timeout `ResetRequired`. The registry entry must not outlive the
    /// `Ready` state it guards.
    fn require_reset(&mut self, reason: ResetReason) -> TransportError {
        if let Some((handle, _)) = self.timeout.take() {
            timeout::cancel(handle);
        }
        self.state = TransportState::ResetRequired(reason);
        TransportError::ResetRequired
    }

    /// Fold what the handlers recorded into `state`.
    fn observe(&mut self) {
        if self.state != TransportState::Ready {
            return;
        }
        let (timed_out, interrupt_lost) = without_interrupts(|| {
            let shared = &slots_mut()[self.slot];
            (shared.timed_out, shared.interrupt_lost)
        });
        if interrupt_lost {
            self.poison(PoisonReason::InterruptLost);
        } else if timed_out {
            self.timed_out();
        }
    }

    fn ensure_ready(&mut self) -> Result<(), TransportError> {
        self.observe();
        match self.state {
            TransportState::Ready => Ok(()),
            TransportState::ResetRequired(_) => Err(TransportError::ResetRequired),
            TransportState::Poisoned(_) => Err(TransportError::Poisoned),
        }
    }

    /// Arm the device timeout, or move it earlier, to cover `deadline_ns`.
    fn cover_deadline(&mut self, deadline_ns: u64) -> Result<(), TransportError> {
        match self.timeout {
            None => {
                let handle = timeout::arm(
                    Deadline::MonotonicNs(deadline_ns),
                    on_request_timeout,
                    timeout_context(self.slot, self.generation),
                )
                .map_err(|_| TransportError::TimeoutsExhausted)?;
                self.timeout = Some((handle, deadline_ns));
            }
            Some((handle, armed_ns)) if deadline_ns < armed_ns => {
                match timeout::rearm(handle, Deadline::MonotonicNs(deadline_ns)) {
                    CancelOutcome::Cancelled => self.timeout = Some((handle, deadline_ns)),
                    CancelOutcome::NotArmed => return Err(self.timed_out()),
                }
            }
            Some(_) => {}
        }
        Ok(())
    }

    /// After a completion: follow the earliest remaining deadline, or cancel.
    /// A timeout that fired first wins, even over the completion just taken.
    fn track_earliest_deadline(&mut self) -> Result<(), TransportError> {
        let Some((handle, armed_ns)) = self.timeout else {
            return Ok(());
        };
        let outcome = match self.earliest_deadline_ns() {
            None => {
                let outcome = timeout::cancel(handle);
                if outcome == CancelOutcome::Cancelled {
                    self.timeout = None;
                }
                outcome
            }
            Some(earliest_ns) if earliest_ns != armed_ns => {
                let outcome = timeout::rearm(handle, Deadline::MonotonicNs(earliest_ns));
                if outcome == CancelOutcome::Cancelled {
                    self.timeout = Some((handle, earliest_ns));
                }
                outcome
            }
            Some(_) => CancelOutcome::Cancelled,
        };
        match outcome {
            CancelOutcome::Cancelled => Ok(()),
            CancelOutcome::NotArmed => Err(self.timed_out()),
        }
    }

    fn earliest_deadline_ns(&self) -> Option<u64> {
        self.queues[..self.request.queues.len()]
            .iter()
            .filter_map(SplitQueue::earliest_deadline_ns)
            .min()
    }

    fn publish_generation(&self) {
        let (slot, generation) = (self.slot, self.generation);
        without_interrupts(|| {
            let shared = &mut slots_mut()[slot];
            shared.generation = generation;
            shared.timed_out = false;
        });
    }
}

impl<A: DeviceAccess> VirtqueueTransport for ModernTransport<A> {
    fn state(&mut self) -> TransportState {
        self.observe();
        self.state
    }

    fn generation(&self) -> u32 {
        self.generation
    }

    fn submit(
        &mut self,
        queue: u16,
        chain: &[DmaSegment],
        deadline: Deadline,
    ) -> Result<Token, TransportError> {
        self.ensure_ready()?;
        let position = self.queue_position(queue)?;
        if self.read_status()? & STATUS_DEVICE_NEEDS_RESET != 0 {
            return Err(self.require_reset(ResetReason::DeviceNeedsReset));
        }
        self.queues[position]
            .check_chain(chain)
            .map_err(queue_error)?;
        let Deadline::MonotonicNs(deadline_ns) = deadline;
        self.cover_deadline(deadline_ns)?;
        self.queues[position]
            .submit(chain, deadline_ns)
            .map_err(queue_error)
    }

    fn notify(&mut self, queue: u16) -> Result<(), TransportError> {
        self.ensure_ready()?;
        let position = self.queue_position(queue)?;
        fence(Ordering::SeqCst);
        self.access
            .notify(self.notify_addresses[position], queue)
            .map_err(access_error)
    }

    fn take_completion(&mut self, queue: u16) -> Result<Option<Completion>, TransportError> {
        self.ensure_ready()?;
        let position = self.queue_position(queue)?;
        match self.queues[position].take_used() {
            Ok(None) => Ok(None),
            Ok(Some(completion)) => {
                self.track_earliest_deadline()?;
                Ok(Some(completion))
            }
            Err(_) => Err(self.require_reset(ResetReason::ProtocolViolation)),
        }
    }

    fn token_in_flight(&self, token: Token) -> Result<bool, TransportError> {
        if token.generation != self.generation {
            return Err(TransportError::StaleToken);
        }
        let position = self.queue_position(token.queue)?;
        Ok(self.queues[position].owns(token))
    }

    fn earliest_deadline(&self) -> Option<Deadline> {
        self.earliest_deadline_ns().map(Deadline::MonotonicNs)
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        self.observe();
        if let TransportState::Poisoned(_) = self.state {
            return Err(TransportError::Poisoned);
        }
        if let Some((handle, _)) = self.timeout.take() {
            timeout::cancel(handle);
        }
        let Some(generation) = self.generation.checked_add(1) else {
            return Err(self.poison(PoisonReason::GenerationExhausted));
        };
        self.generation = generation;
        self.publish_generation();
        if self.reset_device().is_err() {
            return Err(self.poison(PoisonReason::ResetStuck));
        }
        if let Err(error) = self.bring_up_after_reset() {
            return Err(self.poison(PoisonReason::BringUpFailed(error)));
        }
        self.state = TransportState::Ready;
        Ok(())
    }
}

/// Bounded device-config access inside [`ModernTransport::read_device_config`].
pub(crate) struct DeviceConfigReader<'a, A: DeviceAccess> {
    access: &'a mut A,
    length: u32,
}

impl<A: DeviceAccess> DeviceConfigReader<'_, A> {
    fn read(&mut self, offset: u32, width: Width) -> Result<u32, TransportError> {
        check_window(self.length, offset, width).map_err(access_error)?;
        self.access
            .read(Window::Device, offset, width)
            .map_err(access_error)
    }

    #[cfg(test)]
    pub(crate) fn read_u8(&mut self, offset: u32) -> Result<u8, TransportError> {
        Ok(self.read(offset, Width::U8)? as u8)
    }

    #[cfg(test)]
    pub(crate) fn read_u16(&mut self, offset: u32) -> Result<u16, TransportError> {
        Ok(self.read(offset, Width::U16)? as u16)
    }

    pub(crate) fn read_u32(&mut self, offset: u32) -> Result<u32, TransportError> {
        self.read(offset, Width::U32)
    }

    /// Two 32-bit reads, low then high; the generation loop makes the pair consistent.
    pub(crate) fn read_u64(&mut self, offset: u32) -> Result<u64, TransportError> {
        let low = self.read(offset, Width::U32)?;
        let high = self.read(
            offset.checked_add(4).ok_or(TransportError::InvalidAccess)?,
            Width::U32,
        )?;
        Ok(u64::from(low) | (u64::from(high) << 32))
    }
}

/// `common_cfg` and device config through the kernel identity map.
pub(crate) struct MmioAccess {
    function: PciFunction,
    common: Region,
    device: Option<Region>,
}

impl MmioAccess {
    fn window(&self, window: Window) -> Result<Region, AccessError> {
        match window {
            Window::Common => Ok(self.common),
            Window::Device => self.device.ok_or(AccessError::OutOfWindow),
        }
    }
}

impl DeviceAccess for MmioAccess {
    fn read(&mut self, window: Window, offset: u32, width: Width) -> Result<u32, AccessError> {
        let region = self.window(window)?;
        check_window(region.length, offset, width)?;
        let phys = region.phys + u64::from(offset);
        // SAFETY: `phys` lies inside a region validated against its BAR, and
        // `with_kernel_identity_mmio` checks it is identity-mapped.
        with_kernel_identity_mmio(phys, u64::from(width.bytes()), |va| unsafe {
            match width {
                Width::U8 => u32::from(read_volatile(va as *const u8)),
                Width::U16 => u32::from(read_volatile(va as *const u16)),
                Width::U32 => read_volatile(va as *const u32),
            }
        })
        .map_err(|_| AccessError::Unmapped)
    }

    fn write(
        &mut self,
        window: Window,
        offset: u32,
        width: Width,
        value: u32,
    ) -> Result<(), AccessError> {
        let region = self.window(window)?;
        check_window(region.length, offset, width)?;
        let phys = region.phys + u64::from(offset);
        // SAFETY: as in `read`.
        with_kernel_identity_mmio(phys, u64::from(width.bytes()), |va| unsafe {
            match width {
                Width::U8 => core::ptr::write_volatile(va as *mut u8, value as u8),
                Width::U16 => core::ptr::write_volatile(va as *mut u16, value as u16),
                Width::U32 => core::ptr::write_volatile(va as *mut u32, value),
            }
        })
        .map_err(|_| AccessError::Unmapped)
    }

    fn notify(&mut self, address: u64, queue: u16) -> Result<(), AccessError> {
        // SAFETY: `address` came from `notify_address` over the validated notify region.
        with_kernel_identity_mmio(address, 2, |va| unsafe {
            core::ptr::write_volatile(va as *mut u16, queue)
        })
        .map_err(|_| AccessError::Unmapped)
    }

    fn set_bus_master(&mut self, enabled: bool) {
        if enabled {
            self.function.update_command(PCI_COMMAND_BUS_MASTER, 0);
        } else {
            self.function.update_command(0, PCI_COMMAND_BUS_MASTER);
        }
    }

    fn dma_address(&self, va: *const u8, len: usize) -> Result<u64, AccessError> {
        kernel_physical_range(va as u64, len).map_err(|_| AccessError::Unmapped)
    }
}

pub(crate) type MmioTransport = ModernTransport<MmioAccess>;

impl ModernTransport<MmioAccess> {
    /// Find the single modern-only function for `request.virtio_id`, validate
    /// its capabilities, route its interrupt and bring it up. `sink` runs in
    /// interrupt context for every queue interrupt and W3 timeout and may only
    /// record state or wake.
    pub(crate) fn discover(request: &DeviceRequest, sink: fn()) -> Result<Self, TransportError> {
        validate_request(request)?;
        let device_id = VIRTIO_PCI_MODERN_DEVICE_BASE
            .checked_add(request.virtio_id)
            .ok_or(TransportError::InvalidRequest)?;
        let function = find_single_function(VIRTIO_PCI_VENDOR_ID, device_id)
            .map_err(|_| TransportError::Multiple)?
            .ok_or(TransportError::NotFound)?;
        let (vendor, device) = function.vendor_device();
        check_device_identity(vendor, device, revision_id(&function), request.virtio_id)
            .map_err(TransportError::Capability)?;

        let bars = without_interrupts(|| Bars::probe(&function));
        let layout = decode_modern_layout(&function, &bars).map_err(TransportError::Capability)?;
        log_layout(function, &bars, &layout);
        for region in [
            Some(layout.common),
            Some(layout.notify),
            Some(layout.isr),
            layout.device,
        ]
        .into_iter()
        .flatten()
        {
            if with_kernel_identity_mmio(region.phys, u64::from(region.length), |_| ()).is_err() {
                kernel_log_fmt(format_args!(
                    "[VIRTIO] modern bar{} region phys={:#x} len={:#x} is not identity-mapped: fail closed\n",
                    region.bar, region.phys, region.length
                ));
                return Err(TransportError::MmioUnmapped);
            }
        }
        function.update_command(PCI_COMMAND_MEMORY_SPACE, 0);

        let msix =
            MsixCapability::probe_checked(function, |index| match bars.0.get(usize::from(index)) {
                Some(BarKind::Memory(bar)) => Some(*bar),
                _ => None,
            })
            .map_err(TransportError::Interrupt)?;
        let irq_mode = if msix.is_some() {
            IrqMode::Msix
        } else {
            IrqMode::Intx
        };
        let mut transport = Self::attach(
            MmioAccess {
                function,
                common: layout.common,
                device: layout.device,
            },
            layout,
            *request,
            irq_mode,
            sink,
            Some(function),
        )?;
        let binding = match route_interrupts(transport.slot, function, msix, layout.isr.phys) {
            Ok(binding) => binding,
            Err(error) => {
                transport.access.set_bus_master(false);
                release_slot(transport.slot);
                return Err(error);
            }
        };
        transport.pci = Some(binding);
        if let Err(error) = transport.initialize() {
            transport.release();
            return Err(error);
        }
        match transport.pci.as_ref().map(|binding| binding.route) {
            Some(InterruptRoute::Msix { vector }) => kernel_log_fmt(format_args!(
                "[VIRTIO] modern id={} slot={} irq=msix vector={:#x}\n",
                request.virtio_id, transport.slot, vector
            )),
            Some(InterruptRoute::Intx { vector, gsi }) => kernel_log_fmt(format_args!(
                "[VIRTIO] modern id={} slot={} irq=intx vector={:#x} gsi={}\n",
                request.virtio_id, transport.slot, vector, gsi
            )),
            None => {}
        }
        Ok(transport)
    }

    pub(crate) fn interrupt_route(&self) -> Option<InterruptRoute> {
        self.pci.as_ref().map(|binding| binding.route)
    }
}

fn log_layout(function: PciFunction, bars: &Bars, layout: &ModernLayout) {
    let mut logged = [false; 6];
    for region in [
        Some(layout.common),
        Some(layout.notify),
        Some(layout.isr),
        layout.device,
    ]
    .into_iter()
    .flatten()
    {
        let index = usize::from(region.bar);
        if logged[index] {
            continue;
        }
        logged[index] = true;
        if let BarKind::Memory(bar) = bars.0[index] {
            kernel_log_fmt(format_args!(
                "[VIRTIO] modern {:02x}:{:02x}.{} bar{} base={:#x} size={:#x} 64bit={}\n",
                function.bus,
                function.device,
                function.function,
                bar.index,
                bar.base,
                bar.size,
                bar.is_64
            ));
        }
    }
}

/// MSI-X when the function has a table (a failing table is an error, not a
/// reason to fall back), otherwise its INTx line, which must not already be
/// routed: the modern path never shares a GSI.
fn route_interrupts(
    slot: usize,
    function: PciFunction,
    msix: Option<MsixCapability>,
    isr_phys: u64,
) -> Result<PciBinding, TransportError> {
    let handler = SLOT_HANDLERS[slot];
    if let Some(msix) = msix {
        let vector = allocate_device_vector(handler).map_err(|_| TransportError::NoVector)?;
        msix.enable_masked();
        if let Err(error) = msix.program_entry(MSIX_QUEUE_ENTRY, msi_message(vector)) {
            let _ = msix.mask_entry(MSIX_QUEUE_ENTRY);
            msix.disable();
            release_device_vector(vector);
            return Err(TransportError::Interrupt(error));
        }
        msix.unmask_function();
        return Ok(PciBinding {
            function,
            route: InterruptRoute::Msix { vector },
            msix: Some(msix),
        });
    }
    let gsi = intx_gsi(function).map_err(TransportError::Interrupt)?;
    if gsi_is_routed(gsi) {
        return Err(TransportError::IrqShared);
    }
    without_interrupts(|| {
        slots_mut()[slot].intx = Some(IntxBinding {
            isr_phys,
            function,
            route: IntxRoute { vector: 0, gsi },
            released: true,
        });
    });
    let route = route_intx(function, handler).map_err(TransportError::Interrupt)?;
    without_interrupts(|| {
        slots_mut()[slot].intx = Some(IntxBinding {
            isr_phys,
            function,
            route,
            released: false,
        });
    });
    Ok(PciBinding {
        function,
        route: InterruptRoute::Intx {
            vector: route.vector,
            gsi: route.gsi,
        },
        msix: None,
    })
}

fn release_interrupts(slot: usize, binding: &PciBinding) {
    match binding.route {
        InterruptRoute::Msix { vector } => {
            if let Some(msix) = binding.msix {
                let _ = msix.mask_entry(MSIX_QUEUE_ENTRY);
                msix.disable();
            }
            release_device_vector(vector);
        }
        InterruptRoute::Intx { .. } => {
            let intx = without_interrupts(|| {
                let shared = &mut slots_mut()[slot];
                let intx = shared.intx.filter(|intx| !intx.released);
                if let Some(bound) = shared.intx.as_mut() {
                    bound.released = true;
                }
                intx
            });
            if let Some(intx) = intx {
                release_intx(binding.function, intx.route);
            }
        }
    }
}

#[cfg(test)]
mod tests;
