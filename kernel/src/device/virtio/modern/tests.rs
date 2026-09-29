use core::cell::Cell;
use std::boxed::Box;
use std::vec::Vec;

use super::caps::{CapError, CapKind, ModernLayout, Region};
use super::fake::FakeDevice;
use super::features::VERSION_1;
use super::regs::{
    Width, Window, DEVICE_STATUS, NO_VECTOR, QUEUE_DESC, STATUS_ACKNOWLEDGE, STATUS_DRIVER,
    STATUS_FAILED,
};
use super::*;
use crate::device::virtio::dma::DmaSegment;
use crate::sched::timeout::{self as registry, MAX_TIMEOUTS};

const BAR4: u64 = 0x0000_0080_0000_0000;
const NOTIFY_PHYS: u64 = BAR4 + 0x3000;

static ONE_QUEUE: [QueueRequest; 1] = [QueueRequest {
    index: 0,
    max_size: 16,
}];
static TWO_QUEUES: [QueueRequest; 2] = [
    QueueRequest {
        index: 0,
        max_size: 16,
    },
    QueueRequest {
        index: 1,
        max_size: 8,
    },
];

std::thread_local! {
    static SINK_CALLS: Cell<u32> = const { Cell::new(0) };
}

fn count_sink() {
    SINK_CALLS.with(|calls| calls.set(calls.get() + 1));
}

fn sink_calls() -> u32 {
    SINK_CALLS.with(Cell::get)
}

fn region(offset: u32) -> Region {
    Region {
        bar: 4,
        offset,
        length: 0x1000,
        phys: BAR4 + u64::from(offset),
    }
}

fn layout() -> ModernLayout {
    ModernLayout {
        common: region(0),
        notify: region(0x3000),
        notify_off_multiplier: 4,
        isr: region(0x1000),
        device: Some(region(0x2000)),
        ignored: 1,
        duplicates: 0,
    }
}

fn blk_request() -> DeviceRequest {
    DeviceRequest {
        virtio_id: 2,
        required_features: 0,
        optional_features: 0,
        queues: &ONE_QUEUE,
        min_device_cfg_len: 8,
    }
}

type Transport = ModernTransport<FakeDevice>;

fn attach_with(
    device: FakeDevice,
    layout: ModernLayout,
    request: DeviceRequest,
    irq_mode: IrqMode,
) -> Result<Transport, (TransportError, Option<Box<FakeDevice>>)> {
    let mut transport =
        ModernTransport::attach(device, layout, request, irq_mode, count_sink, None)
            .map_err(|error| (error, None))?;
    match transport.initialize() {
        Ok(()) => Ok(transport),
        Err(error) => {
            let ModernTransport { access, slot, .. } = transport;
            release_slot(slot);
            Err((error, Some(Box::new(access))))
        }
    }
}

fn attach(device: FakeDevice, irq_mode: IrqMode) -> Result<Transport, TransportError> {
    attach_with(device, layout(), blk_request(), irq_mode).map_err(|(error, _)| error)
}

fn ready(irq_mode: IrqMode) -> Transport {
    attach(FakeDevice::new(0), irq_mode).expect("bring-up")
}

fn failed_attach(device: FakeDevice) -> (TransportError, FakeDevice) {
    match attach_with(device, layout(), blk_request(), IrqMode::Msix) {
        Ok(_) => panic!("bring-up unexpectedly succeeded"),
        Err((error, device)) => (error, *device.expect("device returned")),
    }
}

/// Header (device-readable), data and status (device-writable): a block read.
fn block_read() -> [DmaSegment; 3] {
    [
        DmaSegment::fake(0x10_0000, 16, false),
        DmaSegment::fake(0x10_1000, 512, true),
        DmaSegment::fake(0x10_2000, 1, true),
    ]
}

fn at(ns: u64) -> Deadline {
    Deadline::MonotonicNs(ns)
}

fn noop_timeout(_context: u64) {}

#[test]
fn bring_up_writes_status_sequence_0_1_3_11_15() {
    let mut transport = ready(IrqMode::Msix);
    assert_eq!(transport.access.status_writes, [0, 1, 3, 11, 15]);
    assert_eq!(transport.negotiated_features(), VERSION_1);
    assert_eq!(transport.access.driver_features, VERSION_1);
    assert!(transport.access.bus_master);
    assert_eq!(transport.state(), TransportState::Ready);
    assert_eq!(transport.generation(), 1);
}

#[test]
fn features_ok_veto_writes_failed_and_errors() {
    let mut device = FakeDevice::new(0);
    device.veto_features_ok = true;
    let (error, device) = failed_attach(device);
    assert_eq!(error, TransportError::FeaturesRejected);
    assert_eq!(
        device.status_writes.last(),
        Some(&(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FAILED))
    );
    assert!(!device.bus_master);
    ready(IrqMode::Msix);
    ready(IrqMode::Msix);
}

#[test]
fn missing_required_feature_fails_closed() {
    let request = DeviceRequest {
        required_features: 1 << 5,
        ..blk_request()
    };
    let Err((error, Some(device))) =
        attach_with(FakeDevice::new(1 << 6), layout(), request, IrqMode::Msix)
    else {
        panic!("bring-up without a required feature succeeded");
    };
    assert_eq!(error, TransportError::FeatureRequired(1 << 5));
    assert!(device
        .status_writes
        .last()
        .is_some_and(|status| status & STATUS_FAILED != 0));
    assert!(!device.common_writes_to(DEVICE_STATUS).contains(&11));
}

#[test]
fn optional_features_are_accepted_only_when_offered() {
    let request = DeviceRequest {
        optional_features: (1 << 1) | (1 << 2),
        ..blk_request()
    };
    let transport = attach_with(FakeDevice::new(1 << 2), layout(), request, IrqMode::Msix)
        .map_err(|(error, _)| error)
        .expect("bring-up");
    assert_eq!(transport.negotiated_features(), VERSION_1 | (1 << 2));
}

/// Status reads after the last status-0 write that still saw the device running.
fn stale_reset_reads(device: &FakeDevice) -> usize {
    let last_reset = device
        .log
        .iter()
        .rposition(|access| access.write && access.offset == DEVICE_STATUS && access.value == 0)
        .expect("a reset write");
    device.log[last_reset + 1..]
        .iter()
        .take_while(|access| !access.write && access.offset == DEVICE_STATUS && access.value != 0)
        .count()
}

#[test]
fn reset_readback_stuck_poisons_after_4_reads() {
    let mut transport = ready(IrqMode::Msix);
    transport.access.reset_latency_reads = MAX_RESET_READS as u32;
    assert_eq!(transport.reset(), Err(TransportError::Poisoned));
    assert_eq!(stale_reset_reads(&transport.access), MAX_RESET_READS);
    assert_eq!(
        transport.state(),
        TransportState::Poisoned(PoisonReason::ResetStuck)
    );
    assert!(!transport.access.bus_master);

    // Firmware left the device running and it never acknowledges the reset.
    let mut device = FakeDevice::new(0);
    device
        .write(Window::Common, DEVICE_STATUS, Width::U8, 15)
        .expect("firmware status");
    device.reset_latency_reads = u32::MAX;
    let (error, device) = failed_attach(device);
    assert_eq!(error, TransportError::ResetStuck);
    assert_eq!(stale_reset_reads(&device), MAX_RESET_READS);
    assert!(!device.bus_master);
}

#[test]
fn reset_readback_settles_within_the_bound() {
    let mut transport = ready(IrqMode::Msix);
    transport.access.reset_latency_reads = MAX_RESET_READS as u32 - 1;
    assert_eq!(transport.reset(), Ok(()));
    assert_eq!(transport.state(), TransportState::Ready);
}

#[test]
fn queue_size_zero_unavailable() {
    let mut device = FakeDevice::new(0);
    device.queues[0].max_size = 0;
    assert_eq!(failed_attach(device).0, TransportError::QueueUnavailable);
}

#[test]
fn queue_size_non_power_of_two_unavailable() {
    let mut device = FakeDevice::new(0);
    device.queues[0].max_size = 48;
    assert_eq!(failed_attach(device).0, TransportError::QueueUnavailable);
}

#[test]
fn queue_index_beyond_num_queues_unavailable() {
    let mut device = FakeDevice::new(0);
    device.num_queues = 0;
    assert_eq!(failed_attach(device).0, TransportError::QueueUnavailable);
}

#[test]
fn driver_shrinks_queue_size() {
    let transport = ready(IrqMode::Msix);
    assert_eq!(transport.access.queues[0].size, 16);
    assert_eq!(transport.queue_size(0), Some(16));

    let mut device = FakeDevice::new(0);
    device.queues[0].max_size = 8;
    let transport = attach(device, IrqMode::Msix).expect("bring-up");
    assert_eq!(transport.queue_size(0), Some(8));
}

#[test]
fn queue_enable_set_after_reset_is_stale() {
    let mut device = FakeDevice::new(0);
    device.stale_queue_enable = true;
    assert_eq!(failed_attach(device).0, TransportError::StaleQueueEnable);
}

#[test]
fn queue_addresses_written_lo_then_hi_u64() {
    let transport = ready(IrqMode::Msix);
    let [desc, driver, device] = transport.queues[0].area_pointers();
    let queue = transport.access.queues[0];
    assert_eq!(
        (queue.desc, queue.driver, queue.device),
        (desc as u64, driver as u64, device as u64)
    );
    assert_eq!(queue.enable, 1);
    let desc_writes: Vec<(u32, Width)> = transport
        .access
        .log
        .iter()
        .filter(|access| access.write && (QUEUE_DESC..QUEUE_DESC + 8).contains(&access.offset))
        .map(|access| (access.offset, access.width))
        .collect();
    assert_eq!(
        desc_writes,
        [(QUEUE_DESC, Width::U32), (QUEUE_DESC + 4, Width::U32)]
    );
}

#[test]
fn msix_mode_programs_queue_entry_0_and_no_config_vector() {
    let transport = ready(IrqMode::Msix);
    assert_eq!(transport.access.queues[0].msix_vector, 0);
    assert_eq!(transport.access.config_msix_vector, NO_VECTOR);
}

#[test]
fn msix_vector_readback_mismatch_fails() {
    let mut device = FakeDevice::new(0);
    device.reject_msix_vector = true;
    assert_eq!(failed_attach(device).0, TransportError::MsixVectorRejected);
}

#[test]
fn intx_mode_leaves_vectors_no_vector() {
    let transport = ready(IrqMode::Intx);
    assert_eq!(transport.access.queues[0].msix_vector, NO_VECTOR);
    assert_eq!(transport.access.config_msix_vector, NO_VECTOR);
}

#[test]
fn needs_reset_after_driver_ok_fails_bring_up() {
    let mut device = FakeDevice::new(0);
    device.needs_reset_after_driver_ok = true;
    assert_eq!(failed_attach(device).0, TransportError::DeviceNeedsReset);
}

#[test]
fn device_config_required_by_the_request() {
    let without_device = ModernLayout {
        device: None,
        ..layout()
    };
    let Err((error, None)) = attach_with(
        FakeDevice::new(0),
        without_device,
        blk_request(),
        IrqMode::Msix,
    ) else {
        panic!("attach without device config succeeded");
    };
    assert_eq!(
        error,
        TransportError::Capability(CapError::Missing(CapKind::Device))
    );
}

#[test]
fn config_generation_stable_one_attempt() {
    let mut transport = ready(IrqMode::Msix);
    assert_eq!(
        transport.read_device_config(|config| config.read_u64(0)),
        Ok((2048, 1))
    );
}

#[test]
fn config_generation_changes_once_retries() {
    let mut transport = ready(IrqMode::Msix);
    transport.access.config_changes = 1;
    assert_eq!(
        transport.read_device_config(|config| config.read_u64(0)),
        Ok((2048, 2))
    );
}

#[test]
fn config_generation_unstable_after_4_is_reset_required() {
    let mut transport = ready(IrqMode::Msix);
    transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.access.config_changes = u32::MAX;
    assert_eq!(
        transport.read_device_config(|config| config.read_u32(0)),
        Err(TransportError::ConfigUnstable)
    );
    assert_eq!(registry::armed_count(), 0);
    assert_eq!(registry::expire_due(u64::MAX), 0);
    let generation_reads = transport
        .access
        .log
        .iter()
        .filter(|access| !access.write && access.offset == regs::CONFIG_GENERATION)
        .count();
    assert_eq!(
        generation_reads,
        2 * usize::from(MAX_CONFIG_GENERATION_ATTEMPTS)
    );
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::ConfigUnstable)
    );
    assert_eq!(
        transport.submit(0, &block_read(), at(10)),
        Err(TransportError::ResetRequired)
    );
    transport.access.config_changes = 0;
    assert_eq!(transport.reset(), Ok(()));
    assert_eq!(
        transport.read_device_config(|config| config.read_u64(0)),
        Ok((2048, 1))
    );
}

#[test]
fn config_reads_use_natural_widths() {
    let mut transport = ready(IrqMode::Msix);
    let before = transport.access.log.len();
    transport
        .read_device_config(|config| {
            config.read_u64(0)?;
            config.read_u16(2)?;
            config.read_u8(1)
        })
        .expect("config read");
    let device_reads: Vec<(u32, Width)> = transport.access.log[before..]
        .iter()
        .filter(|access| access.window == Window::Device)
        .map(|access| (access.offset, access.width))
        .collect();
    assert_eq!(
        device_reads,
        [
            (0, Width::U32),
            (4, Width::U32),
            (2, Width::U16),
            (1, Width::U8)
        ]
    );
}

#[test]
fn device_cfg_read_out_of_bounds_fails() {
    let mut transport = ready(IrqMode::Msix);
    assert_eq!(
        transport.read_device_config(|config| config.read_u32(0x1000)),
        Err(TransportError::InvalidAccess)
    );
    assert_eq!(
        transport.read_device_config(|config| config.read_u32(2)),
        Err(TransportError::InvalidAccess)
    );
    assert_eq!(
        transport.write_device_config_u32(0x0ffe, 0),
        Err(TransportError::InvalidAccess)
    );
    assert_eq!(transport.state(), TransportState::Ready);
}

#[test]
fn submit_notify_complete_roundtrip() {
    let mut transport = ready(IrqMode::Msix);
    let token = transport
        .submit(0, &block_read(), at(1_000))
        .expect("submit");
    assert_eq!(registry::armed_count(), 1);
    transport.notify(0).expect("notify");
    assert_eq!(transport.access.notifies, [(NOTIFY_PHYS, 0)]);
    assert_eq!(transport.take_completion(0), Ok(None));
    transport.queues[0].device_complete(0, 513);
    let completion = transport.take_completion(0).expect("valid").expect("done");
    assert_eq!(completion.token, token);
    assert_eq!(completion.written_len, 513);
    assert_eq!(transport.token_in_flight(token), Ok(false));
    assert_eq!(registry::armed_count(), 0);
}

#[test]
fn notify_address_follows_queue_notify_off() {
    let mut device = FakeDevice::new(0);
    device.num_queues = 2;
    let request = DeviceRequest {
        queues: &TWO_QUEUES,
        ..blk_request()
    };
    let mut transport = attach_with(device, layout(), request, IrqMode::Msix)
        .map_err(|(error, _)| error)
        .expect("bring-up");
    assert_eq!(transport.queue_size(1), Some(8));
    transport.notify(1).expect("notify");
    transport.notify(0).expect("notify");
    assert_eq!(
        transport.access.notifies,
        [(NOTIFY_PHYS + 4, 1), (NOTIFY_PHYS, 0)]
    );
    assert_eq!(transport.notify(2), Err(TransportError::InvalidRequest));
}

#[test]
fn w3_timeout_moves_device_to_reset_required() {
    let mut transport = ready(IrqMode::Msix);
    transport
        .submit(0, &block_read(), at(1_000))
        .expect("submit");
    assert_eq!(registry::expire_due(999), 0);
    assert_eq!(sink_calls(), 0);
    assert_eq!(registry::expire_due(1_000), 1);
    assert_eq!(sink_calls(), 1, "the timeout notifies the consumer");
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::Timeout)
    );
    assert_eq!(
        transport.submit(0, &block_read(), at(2_000)),
        Err(TransportError::ResetRequired)
    );
    assert_eq!(transport.notify(0), Err(TransportError::ResetRequired));
    assert_eq!(
        transport.take_completion(0),
        Err(TransportError::ResetRequired)
    );
    assert_eq!(registry::armed_count(), 0);
    assert!(transport.access.notifies.is_empty());
}

#[test]
fn completion_before_deadline_cancels_the_timeout() {
    let mut transport = ready(IrqMode::Msix);
    transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.queues[0].device_complete(0, 1);
    transport.take_completion(0).expect("valid").expect("done");
    assert_eq!(registry::armed_count(), 0);
    assert_eq!(registry::expire_due(u64::MAX), 0);
    assert_eq!(transport.state(), TransportState::Ready);
}

#[test]
fn expiry_racing_completion_expiry_first_wins() {
    let mut transport = ready(IrqMode::Msix);
    transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.queues[0].device_complete(0, 1);
    assert_eq!(registry::expire_due(100), 1);
    assert_eq!(
        transport.take_completion(0),
        Err(TransportError::ResetRequired)
    );
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::Timeout)
    );
}

#[test]
fn expiry_racing_completion_between_harvest_and_cancel() {
    let mut transport = ready(IrqMode::Msix);
    transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.queues[0].device_complete(0, 1);
    // The handler ran after `observe` but before the cancel: the registry says so.
    let (handle, _) = transport.timeout.expect("armed");
    registry::expire_due(100);
    without_interrupts(|| slots_mut()[transport.slot].timed_out = false);
    assert_eq!(registry::cancel(handle), CancelOutcome::NotArmed);
    assert_eq!(
        transport.take_completion(0),
        Err(TransportError::ResetRequired)
    );
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::Timeout)
    );
}

#[test]
fn timeout_follows_the_earliest_in_flight_deadline() {
    let mut transport = ready(IrqMode::Msix);
    transport
        .submit(0, &[DmaSegment::fake(0, 4, true)], at(500))
        .expect("late");
    transport
        .submit(0, &[DmaSegment::fake(0, 4, true)], at(100))
        .expect("early");
    assert_eq!(registry::armed_count(), 1, "one registry entry per device");
    assert_eq!(transport.earliest_deadline(), Some(at(100)));
    transport.queues[0].device_complete(1, 4);
    transport
        .take_completion(0)
        .expect("valid")
        .expect("early done");
    assert_eq!(registry::expire_due(499), 0);
    assert_eq!(transport.state(), TransportState::Ready);
    assert_eq!(registry::expire_due(500), 1);
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::Timeout)
    );
}

#[test]
fn timeout_exhaustion_fails_submit_without_publishing() {
    let mut transport = ready(IrqMode::Msix);
    for _ in 0..MAX_TIMEOUTS {
        registry::arm(at(u64::MAX), noop_timeout, 0).expect("fill");
    }
    assert_eq!(
        transport.submit(0, &block_read(), at(10)),
        Err(TransportError::TimeoutsExhausted)
    );
    assert_eq!(transport.queues[0].in_flight(), 0);
    assert_eq!(transport.queues[0].device_avail_idx(), 0);
    assert_eq!(transport.state(), TransportState::Ready);
}

#[test]
fn stale_timeout_after_reset_is_ignored() {
    let mut transport = ready(IrqMode::Msix);
    let before_reset = timeout_context(transport.slot, transport.generation());
    transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.reset().expect("reset");
    assert_eq!(
        registry::armed_count(),
        0,
        "reset cancels the device timeout"
    );
    on_request_timeout(before_reset);
    assert_eq!(sink_calls(), 0);
    assert_eq!(transport.state(), TransportState::Ready);
}

#[test]
fn reset_bumps_generation_and_reprograms() {
    let mut transport = ready(IrqMode::Msix);
    let token = transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.access.status_writes.clear();
    transport.reset().expect("reset");
    assert_eq!(transport.generation(), 2);
    assert_eq!(transport.access.status_writes, [0, 1, 3, 11, 15]);
    assert_eq!(transport.access.queues[0].enable, 1);
    assert_eq!(transport.access.queues[0].msix_vector, 0);
    assert_eq!(
        transport.token_in_flight(token),
        Err(TransportError::StaleToken)
    );
    assert_eq!(transport.queues[0].in_flight(), 0);
    let fresh = transport.submit(0, &block_read(), at(100)).expect("submit");
    assert_eq!(fresh.generation, 2);
    assert_eq!(transport.token_in_flight(fresh), Ok(true));
}

#[test]
fn reset_at_u32_max_poisons() {
    let mut transport = ready(IrqMode::Msix);
    transport.generation = u32::MAX;
    assert_eq!(transport.reset(), Err(TransportError::Poisoned));
    assert_eq!(
        transport.state(),
        TransportState::Poisoned(PoisonReason::GenerationExhausted)
    );
}

#[test]
fn failed_reset_poisons_and_writes_failed() {
    let mut transport = ready(IrqMode::Msix);
    transport.access.veto_features_ok = true;
    assert_eq!(transport.reset(), Err(TransportError::Poisoned));
    assert_eq!(
        transport.state(),
        TransportState::Poisoned(PoisonReason::BringUpFailed(
            TransportError::FeaturesRejected
        ))
    );
    assert!(transport
        .access
        .status_writes
        .last()
        .is_some_and(|status| status & STATUS_FAILED != 0));
    assert!(!transport.access.bus_master);
    assert_eq!(
        transport.submit(0, &block_read(), at(10)),
        Err(TransportError::Poisoned)
    );
    assert_eq!(transport.take_completion(0), Err(TransportError::Poisoned));
    transport.access.veto_features_ok = false;
    assert_eq!(
        transport.reset(),
        Err(TransportError::Poisoned),
        "poison is permanent"
    );
}

#[test]
fn protocol_violation_requires_reset_then_recovers() {
    let mut transport = ready(IrqMode::Msix);
    transport.submit(0, &block_read(), at(100)).expect("submit");
    assert_eq!(registry::armed_count(), 1);
    transport.queues[0].device_push_used(9, 0);
    assert_eq!(
        transport.take_completion(0),
        Err(TransportError::ResetRequired)
    );
    assert_eq!(registry::armed_count(), 0);
    assert_eq!(registry::expire_due(u64::MAX), 0);
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::ProtocolViolation)
    );
    transport.reset().expect("reset");
    let token = transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.queues[0].device_complete(0, 1);
    assert_eq!(
        transport
            .take_completion(0)
            .expect("valid")
            .map(|done| done.token),
        Some(token)
    );
}

#[test]
fn device_needs_reset_is_detected_at_submit() {
    let mut transport = ready(IrqMode::Msix);
    transport.submit(0, &block_read(), at(100)).expect("submit");
    transport.access.raise_needs_reset();
    assert_eq!(
        transport.submit(0, &block_read(), at(10)),
        Err(TransportError::ResetRequired)
    );
    assert_eq!(
        transport.state(),
        TransportState::ResetRequired(ResetReason::DeviceNeedsReset)
    );
    assert_eq!(registry::armed_count(), 0);
}

#[test]
fn lost_interrupt_poisons_the_device() {
    let mut transport = ready(IrqMode::Intx);
    without_interrupts(|| slots_mut()[transport.slot].interrupt_lost = true);
    assert_eq!(
        transport.state(),
        TransportState::Poisoned(PoisonReason::InterruptLost)
    );
    assert!(!transport.access.bus_master);
    assert_eq!(transport.reset(), Err(TransportError::Poisoned));
}

#[test]
fn chain_errors_do_not_arm_a_timeout() {
    let mut transport = ready(IrqMode::Msix);
    assert_eq!(
        transport.submit(0, &[], at(10)),
        Err(TransportError::InvalidChain)
    );
    assert_eq!(
        transport.submit(3, &block_read(), at(10)),
        Err(TransportError::InvalidRequest)
    );
    assert_eq!(registry::armed_count(), 0);
}

#[test]
fn step_completion_waits_for_the_interrupt() {
    let mut transport = ready(IrqMode::Msix);
    assert_eq!(step_completion(&mut transport, 0), Ok(WaitStep::Idle));
    let token = transport
        .submit(0, &block_read(), at(5_000))
        .expect("submit");
    transport.notify(0).expect("notify");
    assert_eq!(
        step_completion(&mut transport, 0),
        Ok(WaitStep::Wait(at(5_000)))
    );
    count_sink();
    assert_eq!(
        step_completion(&mut transport, 0),
        Ok(WaitStep::Wait(at(5_000))),
        "a wake without a used entry waits again"
    );
    transport.queues[0].device_complete(0, 513);
    let Ok(WaitStep::Complete(completion)) = step_completion(&mut transport, 0) else {
        panic!("completion not harvested");
    };
    assert_eq!(completion.token, token);
    assert_eq!(step_completion(&mut transport, 0), Ok(WaitStep::Idle));
}

#[test]
fn step_completion_past_the_deadline_is_reset_required() {
    let mut transport = ready(IrqMode::Msix);
    transport
        .submit(0, &block_read(), at(5_000))
        .expect("submit");
    registry::expire_due(5_000);
    assert_eq!(
        step_completion(&mut transport, 0),
        Err(TransportError::ResetRequired)
    );
}

#[test]
fn slots_are_bounded_and_reusable() {
    let first = ready(IrqMode::Msix);
    let _second = ready(IrqMode::Msix);
    assert_eq!(
        attach(FakeDevice::new(0), IrqMode::Msix).err(),
        Some(TransportError::SlotsExhausted)
    );
    let (slot, generation) = (first.slot, first.generation());
    assert!(first.release().device_reset);
    let third = ready(IrqMode::Msix);
    assert_eq!(third.slot, slot);
    assert_eq!(third.generation(), generation + 1);
}

#[test]
fn release_cancels_the_timeout_and_strands_tokens() {
    let mut first = ready(IrqMode::Msix);
    let token = first.submit(0, &block_read(), at(100)).expect("submit");
    first.release();
    assert_eq!(registry::armed_count(), 0);
    let second = ready(IrqMode::Msix);
    assert_eq!(
        second.token_in_flight(token),
        Err(TransportError::StaleToken)
    );
}

/// The #114 init shape (W4): each command is submitted when the previous one's
/// completion is harvested, every command runs under the device timeout, and
/// nothing blocks. `advance` is what the consumer runs after its sink fires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Init {
    Start,
    Awaiting { command: u8, token: Token },
    Done,
}

const INIT_COMMANDS: u8 = 3;
const COMMAND_TIMEOUT_NS: u64 = 1_000;

fn advance<T: VirtqueueTransport>(
    init: Init,
    transport: &mut T,
    now_ns: u64,
) -> Result<Init, TransportError> {
    let submit = |transport: &mut T, command: u8| -> Result<Init, TransportError> {
        let chain = [
            DmaSegment::fake(0x20_0000, 24, false),
            DmaSegment::fake(0x20_1000, 24, true),
        ];
        let token = transport.submit(0, &chain, at(now_ns + COMMAND_TIMEOUT_NS))?;
        transport.notify(0)?;
        Ok(Init::Awaiting { command, token })
    };
    match init {
        Init::Start => submit(transport, 0),
        Init::Awaiting { command, token } => match transport.take_completion(0)? {
            None => Ok(init),
            Some(completion) if completion.token != token => Err(TransportError::StaleToken),
            Some(_) if command + 1 == INIT_COMMANDS => Ok(Init::Done),
            Some(_) => submit(transport, command + 1),
        },
        Init::Done => Ok(Init::Done),
    }
}

#[test]
fn interrupt_driven_multi_step_init_under_timeouts() {
    let mut transport = ready(IrqMode::Msix);
    let mut init = advance(Init::Start, &mut transport, 0).expect("first command");
    for (position, now) in [(0, 10), (1, 20)] {
        transport.queues[0].device_complete(position, 24);
        init = advance(init, &mut transport, now).expect("next command");
    }
    assert!(matches!(init, Init::Awaiting { command: 2, .. }));
    assert_eq!(registry::armed_count(), 1);

    // The third command never completes: its timeout fires from the timer path.
    assert_eq!(registry::expire_due(20 + COMMAND_TIMEOUT_NS), 1);
    assert_eq!(
        advance(init, &mut transport, 2_000),
        Err(TransportError::ResetRequired)
    );

    transport.reset().expect("reset");
    let mut init = advance(Init::Start, &mut transport, 3_000).expect("restart");
    for position in 0..u16::from(INIT_COMMANDS) {
        assert_eq!(
            advance(init, &mut transport, 3_100),
            Ok(init),
            "no completion yet"
        );
        transport.queues[0].device_complete(position, 24);
        init = advance(init, &mut transport, 3_200).expect("advance");
    }
    assert_eq!(init, Init::Done);
    assert_eq!(
        registry::armed_count(),
        0,
        "nothing armed once init is idle"
    );
}
