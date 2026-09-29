//! Kernel input path (#113): the i8042 driver, its PS/2 decoders, and the one raw-input queue
//! that `READ_BATCH` drains (wire §6.2).
//!
//! Queue state is mutated in IRQ context (interrupts masked) or under `without_interrupts`.
//! A device is published (`QUERY_DEVICES` reports its id) only once its init program finishes;
//! until then it reads as `None` and queues nothing. Until `BIND_WAKE`'s integration stage,
//! [`InputState::signal_input_work`] only counts, and `BIND_WAKE` stays `ENOSYS`, so a
//! consumer drains with `READ_BATCH` without blocking.
//!
//! The driver half (the i8042 modules and the queue's producer side) is compiled only where
//! something runs it: the boot tail, the input self-test and host tests. Host tests use a fake
//! controller, so the hardware bring-up and [`QueueSink`] are left out of them.

#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
mod device_init;
#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
mod i8042;
#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
mod keyboard;
#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
mod mouse;
mod queue;

use clean_slate_capability::HolderId;
use clean_slate_graphics::abi::input::InputDeviceInfo;
use clean_slate_graphics::ids::{InputDeviceId, KEYBOARD_INDEX, MOUSE_INDEX};
use clean_slate_graphics::limits::RAW_INPUT_QUEUE_DEPTH;
#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
use clean_slate_graphics::raw_input::RawInputKind;
use clean_slate_graphics::raw_input::{RawInputRecord, RAW_INPUT_RECORD_BYTES};

use crate::arch::x86_64::cpu::without_interrupts;
#[cfg(clean_slate_boot_tail)]
use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use queue::RawInputQueue;

#[cfg(any(clean_slate_boot_tail, feature = "m10-input-self-test"))]
pub(crate) use i8042::begin_init;

const DEVICE_SLOTS: usize = 2;
/// `InputDeviceId` carries a 24-bit generation; 0 is never issued.
#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
const MAX_DEVICE_GENERATION: u32 = (1 << 24) - 1;

#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
const fn next_generation(generation: u32) -> u32 {
    if generation >= MAX_DEVICE_GENERATION {
        1
    } else {
        generation + 1
    }
}

/// The single `INPUT_CONSUME` consumer binding for seat 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ConsumerSlot {
    holder: Option<HolderId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConsumerBusy;

impl ConsumerSlot {
    const fn new() -> Self {
        Self { holder: None }
    }

    fn bind(&mut self, holder: HolderId) -> Result<(), ConsumerBusy> {
        match self.holder {
            None => {
                self.holder = Some(holder);
                Ok(())
            }
            Some(bound) if bound == holder => Ok(()),
            Some(_) => Err(ConsumerBusy),
        }
    }

    fn release(&mut self, holder: HolderId) -> bool {
        if self.holder != Some(holder) {
            return false;
        }
        self.holder = None;
        true
    }

    #[cfg(any(test, feature = "m10-input-self-test"))]
    fn bindings_for(&self, holder: HolderId) -> usize {
        usize::from(self.holder == Some(holder))
    }
}

struct InputState {
    queue: RawInputQueue<RAW_INPUT_QUEUE_DEPTH>,
    /// Last generation issued per device index.
    generations: [u32; DEVICE_SLOTS],
    present: [bool; DEVICE_SLOTS],
    consumer: ConsumerSlot,
    #[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
    wake_edges: u32,
    #[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
    readiness_changes: u32,
}

impl InputState {
    const fn new() -> Self {
        Self {
            queue: RawInputQueue::new(),
            generations: [0; DEVICE_SLOTS],
            present: [false; DEVICE_SLOTS],
            consumer: ConsumerSlot::new(),
            #[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
            wake_edges: 0,
            #[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
            readiness_changes: 0,
        }
    }

    fn device(&self, index: u8) -> Option<InputDeviceId> {
        let slot = usize::from(index);
        if !*self.present.get(slot)? {
            return None;
        }
        InputDeviceId::new(index, self.generations[slot]).ok()
    }

    fn device_info(&self) -> InputDeviceInfo {
        InputDeviceInfo {
            keyboard: self.device(KEYBOARD_INDEX),
            mouse: self.device(MOUSE_INDEX),
            queue_depth: RAW_INPUT_QUEUE_DEPTH as u16,
            record_bytes: RAW_INPUT_RECORD_BYTES as u16,
        }
    }

    fn release_consumer(&mut self, holder: HolderId) -> usize {
        if !self.consumer.release(holder) {
            return 0;
        }
        self.queue.clear_into_loss();
        1
    }
}

#[cfg(any(test, clean_slate_boot_tail, feature = "m10-input-self-test"))]
impl InputState {
    fn publish(&mut self, index: u8, present: bool) {
        let slot = usize::from(index);
        if present {
            self.generations[slot] = next_generation(self.generations[slot]);
        }
        self.present[slot] = present;
    }

    /// The consumer's input work bit: once `BIND_WAKE` is integrated, its bound work-set bit is
    /// signalled here with `work_set::signal`.
    /// Raised on the queue's empty-to-non-empty edge and on every device readiness change, so
    /// the consumer re-reads or re-queries.
    fn signal_input_work(&mut self) {}

    fn record(&mut self, index: u8, kind: RawInputKind, now_ns: u64) {
        let Some(device) = self.device(index) else {
            return;
        };
        if self.queue.push(device, kind, now_ns).queued_into_empty {
            self.wake_edges = self.wake_edges.saturating_add(1);
            self.signal_input_work();
        }
    }

    fn loss(&mut self, index: u8) {
        let Some(device) = self.device(index) else {
            return;
        };
        if self.queue.record_loss(device) {
            self.wake_edges = self.wake_edges.saturating_add(1);
            self.signal_input_work();
        }
    }

    fn device_ready(&mut self, index: u8) {
        self.publish(index, true);
        self.readiness_changes = self.readiness_changes.saturating_add(1);
        self.signal_input_work();
    }

    /// The loss is queued while the old generation is still published, so the consumer drops
    /// that device's held state before the device reads as `None`.
    fn device_lost(&mut self, index: u8) {
        if self.device(index).is_none() {
            return;
        }
        self.loss(index);
        self.publish(index, false);
        self.readiness_changes = self.readiness_changes.saturating_add(1);
        self.signal_input_work();
    }
}

static INPUT: GlobalCell<InputState> = GlobalCell::new(InputState::new());

fn input_mut() -> &'static mut InputState {
    // SAFETY: single CPU, and every caller runs in IRQ context or under `without_interrupts`
    // and drops the reference before interrupts are re-enabled, so no two borrows overlap.
    unsafe { &mut *INPUT.get() }
}

/// Queue time source. Nothing is queued before init, which requires the calibrated TSC; a
/// `READ_BATCH` in an uncalibrated build must not reach the fatal `monotonic_ns` path.
fn now_ns() -> u64 {
    if crate::time::tsc_hz().is_some() {
        crate::time::monotonic_ns()
    } else {
        0
    }
}

/// IRQ-context sink for the driver: interrupts are already masked.
#[cfg(any(clean_slate_boot_tail, feature = "m10-input-self-test"))]
struct QueueSink;

#[cfg(any(clean_slate_boot_tail, feature = "m10-input-self-test"))]
impl i8042::InputSink for QueueSink {
    fn record(&mut self, device_index: u8, kind: RawInputKind) {
        input_mut().record(device_index, kind, now_ns());
    }

    fn loss(&mut self, device_index: u8) {
        input_mut().loss(device_index);
    }

    fn device_lost(&mut self, device_index: u8) {
        input_mut().device_lost(device_index);
    }

    fn device_ready(&mut self, device_index: u8) {
        input_mut().device_ready(device_index);
    }
}

/// Boot-tail bring-up: returns once the device init programs are started; the devices appear
/// later, from IRQ context. A missing or failed controller leaves the seat without devices;
/// input is never boot-fatal.
#[cfg(clean_slate_boot_tail)]
pub(crate) fn begin_init_and_log() {
    let port = |started: bool| if started { "init" } else { "absent" };
    match begin_init() {
        Ok(ports) => kernel_log_fmt(format_args!(
            "[INPT] i8042 keyboard={} mouse={}\n",
            port(ports.keyboard),
            port(ports.aux)
        )),
        Err(error) => kernel_log_fmt(format_args!(
            "[INPT] i8042 unavailable reason={}\n",
            error.name()
        )),
    }
}

pub(crate) fn device_info() -> InputDeviceInfo {
    without_interrupts(|| input_mut().device_info())
}

/// Binds `holder` as the seat's consumer, or confirms it already is.
pub(crate) fn bind_consumer(holder: HolderId) -> Result<(), ConsumerBusy> {
    without_interrupts(|| input_mut().consumer.bind(holder))
}

/// Pops one record for `READ_BATCH`, materialising a pending `Overflow` once the queue is empty.
pub(crate) fn read_one() -> Option<RawInputRecord> {
    let now = now_ns();
    without_interrupts(|| input_mut().queue.pop(now))
}

/// Teardown slot 3 of the shared hook block (after the port and presenter, before
/// `revoke_for_holder`). Unread records become one pending `Overflow`, so the next consumer
/// resets its seat instead of seeing a dead holder's stale presses.
pub(crate) fn release_consumer_for_holder(holder: HolderId) -> usize {
    without_interrupts(|| input_mut().release_consumer(holder))
}

#[cfg(any(test, feature = "m10-input-self-test"))]
pub(crate) fn consumer_bindings_for(holder: HolderId) -> usize {
    without_interrupts(|| input_mut().consumer.bindings_for(holder))
}

#[cfg(feature = "m10-input-self-test")]
pub(crate) use device_init::InitStatus;
#[cfg(feature = "m10-input-self-test")]
pub(crate) use i8042::{init_status, inject, port_accesses, stats as driver_stats};
#[cfg(feature = "m10-input-self-test")]
pub(crate) use mouse::MouseProtocol;

#[cfg(feature = "m10-input-self-test")]
pub(crate) struct QueueStats {
    pub(crate) len: usize,
    pub(crate) pending_dropped: u32,
    pub(crate) wake_edges: u32,
    pub(crate) readiness_changes: u32,
}

#[cfg(feature = "m10-input-self-test")]
pub(crate) fn queue_stats() -> QueueStats {
    without_interrupts(|| {
        let state = input_mut();
        QueueStats {
            len: state.queue.len(),
            pending_dropped: state.queue.pending_dropped(),
            wake_edges: state.wake_edges,
            readiness_changes: state.readiness_changes,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_graphics::input::{KeyState, KeyUsage};

    fn key() -> RawInputKind {
        RawInputKind::Key {
            usage: KeyUsage(0x04),
            state: KeyState::Pressed,
        }
    }

    fn state_with_devices() -> InputState {
        let mut state = InputState::new();
        state.publish(KEYBOARD_INDEX, true);
        state.publish(MOUSE_INDEX, true);
        state
    }

    #[test]
    fn device_generations_start_at_one_bump_on_ready_again_and_skip_zero() {
        let mut state = state_with_devices();
        assert_eq!(
            state.device(KEYBOARD_INDEX).map(|d| d.generation()),
            Some(1)
        );
        state.device_lost(KEYBOARD_INDEX);
        state.device_ready(KEYBOARD_INDEX);
        assert_eq!(
            state.device(KEYBOARD_INDEX).map(|d| d.generation()),
            Some(2)
        );
        assert_eq!(state.device(MOUSE_INDEX).map(|d| d.generation()), Some(1));
        assert_eq!(next_generation(MAX_DEVICE_GENERATION), 1);
        assert_eq!(next_generation(0), 1);
    }

    #[test]
    fn a_lost_device_queues_its_loss_then_reads_none_until_ready() {
        let mut state = state_with_devices();
        state.device_lost(KEYBOARD_INDEX);
        assert_eq!(state.readiness_changes, 1);
        assert_eq!(state.wake_edges, 1);
        assert_eq!(state.device_info().keyboard, None);
        assert!(state.device_info().mouse.is_some());
        state.record(KEYBOARD_INDEX, key(), 10);
        assert_eq!(state.queue.len(), 0);

        let overflow = state
            .queue
            .pop(11)
            .expect("the reset is reported as a loss");
        assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 1 });
        assert_eq!(overflow.device.generation(), 1);

        state.device_lost(KEYBOARD_INDEX);
        assert_eq!(state.readiness_changes, 1);
    }

    #[test]
    fn absent_devices_report_none_and_queue_nothing() {
        let mut state = InputState::new();
        state.publish(KEYBOARD_INDEX, false);
        state.record(KEYBOARD_INDEX, key(), 10);
        state.loss(KEYBOARD_INDEX);
        state.device_lost(KEYBOARD_INDEX);
        let info = state.device_info();
        assert_eq!((info.keyboard, info.mouse), (None, None));
        assert_eq!((info.queue_depth, info.record_bytes), (128, 32));
        assert!(state.queue.is_empty_including_pending());
        assert_eq!(state.wake_edges, 0);
    }

    #[test]
    fn devices_read_as_none_and_queue_nothing_until_ready() {
        let mut state = InputState::new();
        state.record(KEYBOARD_INDEX, key(), 10);
        assert_eq!(state.device_info().keyboard, None);
        assert!(state.queue.is_empty_including_pending());

        state.device_ready(KEYBOARD_INDEX);
        assert_eq!(state.readiness_changes, 1);
        let info = state.device_info();
        assert_eq!(info.keyboard.map(|d| d.generation()), Some(1));
        assert_eq!(info.mouse, None);
        state.record(KEYBOARD_INDEX, key(), 11);
        assert_eq!(state.queue.len(), 1);

        state.device_ready(MOUSE_INDEX);
        assert_eq!(state.readiness_changes, 2);
        assert!(state.device_info().mouse.is_some());
    }

    #[test]
    fn wake_edge_fires_only_on_empty_to_non_empty() {
        let mut state = state_with_devices();
        state.record(KEYBOARD_INDEX, key(), 10);
        state.record(KEYBOARD_INDEX, key(), 11);
        assert_eq!(state.wake_edges, 1);
        state.queue.pop(12);
        state.queue.pop(12);
        state.loss(KEYBOARD_INDEX);
        assert_eq!(state.wake_edges, 2);
        state.record(KEYBOARD_INDEX, key(), 13);
        assert_eq!(state.wake_edges, 2);
    }

    #[test]
    fn consumer_binding_is_exclusive_and_idempotent() {
        let mut slot = ConsumerSlot::new();
        assert_eq!(slot.bind(HolderId(7)), Ok(()));
        assert_eq!(slot.bind(HolderId(7)), Ok(()));
        assert_eq!(slot.bind(HolderId(8)), Err(ConsumerBusy));
        assert_eq!(slot.bindings_for(HolderId(7)), 1);
        assert_eq!(slot.bindings_for(HolderId(8)), 0);
    }

    #[test]
    fn release_returns_one_then_zero_and_lets_another_holder_bind() {
        let mut state = state_with_devices();
        state.consumer.bind(HolderId(7)).expect("bind");
        assert_eq!(state.release_consumer(HolderId(8)), 0);
        assert_eq!(state.release_consumer(HolderId(7)), 1);
        assert_eq!(state.release_consumer(HolderId(7)), 0);
        assert_eq!(state.consumer.bindings_for(HolderId(7)), 0);
        assert_eq!(state.consumer.bind(HolderId(8)), Ok(()));
    }

    #[test]
    fn release_turns_unread_records_into_an_overflow_for_the_next_consumer() {
        let mut state = state_with_devices();
        state.consumer.bind(HolderId(7)).expect("bind");
        state.record(KEYBOARD_INDEX, key(), 10);
        state.record(KEYBOARD_INDEX, key(), 11);
        assert_eq!(state.release_consumer(HolderId(7)), 1);
        let overflow = state.queue.pop(20).expect("overflow");
        assert_eq!(overflow.kind, RawInputKind::Overflow { dropped: 2 });
        assert_eq!(overflow.seq, 3);
        assert_eq!(state.queue.pop(20), None);
    }

    #[test]
    fn release_of_a_non_consumer_keeps_the_queue() {
        let mut state = state_with_devices();
        state.consumer.bind(HolderId(7)).expect("bind");
        state.record(KEYBOARD_INDEX, key(), 10);
        assert_eq!(state.release_consumer(HolderId(9)), 0);
        assert_eq!(state.queue.len(), 1);
    }
}
