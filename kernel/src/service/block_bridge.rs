//! Kernel side of the storage service's block transport.
//!
//! One request is in flight on the device at a time. A syscall submits it and
//! blocks on [`BLOCK_COMPLETION_KEY`] with a real-time deadline; the device's
//! queue interrupt wakes the key, and the restarted syscall harvests the
//! completion. A request still in flight at its deadline is abandoned, which
//! poisons the queue (the device may still own the descriptors), so it and
//! every later request fail closed as reset-required.

use crate::device::virtio::block::{VirtioBlockDevice, BLOCK_COMPLETION_TIMEOUT_NS};
use crate::diagnostics::log::kernel_log_fmt;
use crate::sched::wait::{wake_all, WaitKey};
use crate::sync::global_cell::GlobalCell;
use crate::time::{monotonic_ns, tsc_hz};
use clean_slate_block::{BlockDeviceId, BlockGeometry, BlockIoError};
use clean_slate_service_fixtures::{
    block_io_status, block_response, classify_block_request, BlockRequestAction, BlockTransportOp,
    BlockTransportRequest, BlockTransportResponse, BlockTransportStatus, STORAGE_BLOCK_DEVICE_ID,
};
use clean_slate_service_lifecycle::InstanceGeneration;

const KERNEL_BLOCK_SIZE: u32 = 512;
const KERNEL_BLOCK_COUNT: u64 = 8;
const KERNEL_MAX_TRANSFER_BLOCKS: u32 = 4;

/// Woken by the virtio-block queue interrupt.
pub(crate) const BLOCK_COMPLETION_KEY: WaitKey = WaitKey(0x48_u64 << 56);

/// Process instance that submitted a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BlockCaller {
    pub(crate) pid: u64,
    pub(crate) generation: InstanceGeneration,
}

/// What the syscall does next with a block request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockRequestStep {
    /// Write this response to the caller; the request is finished.
    Complete(BlockTransportResponse),
    /// Block on [`BLOCK_COMPLETION_KEY`] until this monotonic deadline, then retry.
    Wait { deadline_ns: u64 },
}

/// Device operations the request state machine drives.
trait BlockQueue {
    fn geometry(&self) -> BlockGeometry;
    fn submit_read(&mut self, lba: u64, blocks: u32, len: usize) -> Result<(), BlockIoError>;
    fn submit_write(&mut self, lba: u64, blocks: u32, data: &[u8]) -> Result<(), BlockIoError>;
    fn submit_flush(&mut self) -> Result<(), BlockIoError>;
    fn take_completion(&mut self, read_into: Option<&mut [u8]>)
        -> Option<Result<(), BlockIoError>>;
    fn abandon_in_flight(&mut self);
}

impl BlockQueue for VirtioBlockDevice {
    fn geometry(&self) -> BlockGeometry {
        VirtioBlockDevice::geometry(self)
    }

    fn submit_read(&mut self, lba: u64, blocks: u32, len: usize) -> Result<(), BlockIoError> {
        VirtioBlockDevice::submit_read(self, lba, blocks, len)
    }

    fn submit_write(&mut self, lba: u64, blocks: u32, data: &[u8]) -> Result<(), BlockIoError> {
        VirtioBlockDevice::submit_write(self, lba, blocks, data)
    }

    fn submit_flush(&mut self) -> Result<(), BlockIoError> {
        VirtioBlockDevice::submit_flush(self)
    }

    fn take_completion(
        &mut self,
        read_into: Option<&mut [u8]>,
    ) -> Option<Result<(), BlockIoError>> {
        VirtioBlockDevice::take_completion(self, read_into)
    }

    fn abandon_in_flight(&mut self) {
        VirtioBlockDevice::abandon_in_flight(self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlightRequest {
    owner: BlockCaller,
    request: BlockTransportRequest,
    deadline_ns: u64,
}

struct KernelBlockBackend {
    transport_initialized: bool,
    virtio: Option<VirtioBlockDevice>,
    in_flight: Option<InFlightRequest>,
    reported_uncalibrated_clock: bool,
}

impl KernelBlockBackend {
    const fn new() -> Self {
        Self {
            transport_initialized: false,
            virtio: None,
            in_flight: None,
            reported_uncalibrated_clock: false,
        }
    }

    fn ensure_transport(&mut self) {
        if self.transport_initialized {
            return;
        }
        self.transport_initialized = true;
        match VirtioBlockDevice::discover(wake_block_completion) {
            Ok(device) => {
                let geometry = device.geometry();
                kernel_log_fmt(format_args!(
                    "[BLK ] virtio-block ready blocks={} block-size={}\n",
                    geometry.block_count(),
                    geometry.logical_block_size()
                ));
                self.virtio = Some(device);
            }
            Err(message) => {
                kernel_log_fmt(format_args!(
                    "[FAIL] virtio block discovery failed: {message}\n"
                ));
            }
        }
    }
}

static BLOCK_BACKEND: GlobalCell<KernelBlockBackend> = GlobalCell::new(KernelBlockBackend::new());

/// Interrupt context: only wakes the waiter; the harvest runs in its syscall.
fn wake_block_completion() {
    wake_all(BLOCK_COMPLETION_KEY);
}

/// Advance `request` for `caller` by one syscall entry. `payload` is the
/// caller's buffer: the source of a write, the destination of a read.
///
/// Runs with interrupts masked (syscall context), so a completion interrupt
/// cannot slip between the harvest check here and the caller's block.
pub(crate) fn step_kernel_block_request(
    caller: BlockCaller,
    request: &BlockTransportRequest,
    payload: &mut [u8],
) -> BlockRequestStep {
    let backend = unsafe { &mut *BLOCK_BACKEND.get() };
    // Logged on every entry except a resume of the caller's own in-flight request.
    let resuming = matches!(backend.in_flight, Some(current) if current.owner == caller && current.request == *request);
    if !resuming {
        kernel_log_fmt(format_args!(
            "[BLK ] request op={} id={}\n",
            block_op_name(request.operation),
            request.request_id
        ));
    }
    backend.ensure_transport();
    let Some(device) = backend.virtio.as_mut() else {
        return BlockRequestStep::Complete(transport_fault_response(request));
    };
    if tsc_hz().is_none() {
        if !backend.reported_uncalibrated_clock {
            backend.reported_uncalibrated_clock = true;
            kernel_log_fmt(format_args!(
                "[FAIL] block completion deadlines require a calibrated TSC\n"
            ));
        }
        let geometry = publish_contract_geometry(device.geometry());
        return BlockRequestStep::Complete(block_response(
            request,
            geometry,
            BlockTransportStatus::DeviceFault,
        ));
    }
    step_request(
        &mut backend.in_flight,
        device,
        caller,
        request,
        payload,
        monotonic_ns(),
        |owner| crate::process::live_instance_generation(owner.pid) == Some(owner.generation),
    )
}

fn step_request<Q: BlockQueue>(
    in_flight: &mut Option<InFlightRequest>,
    queue: &mut Q,
    caller: BlockCaller,
    request: &BlockTransportRequest,
    payload: &mut [u8],
    now_ns: u64,
    owner_is_live: impl Fn(BlockCaller) -> bool,
) -> BlockRequestStep {
    let geometry = publish_contract_geometry(queue.geometry());
    if let Some(current) = *in_flight {
        let resuming = current.owner == caller && current.request == *request;
        // The caller moved on (or its instance died): nobody will harvest the
        // request, so drain it here instead of waiting for its owner.
        let orphaned = current.owner == caller || !owner_is_live(current.owner);
        if resuming || orphaned {
            let read_into =
                (resuming && request.operation == BlockTransportOp::Read).then_some(&mut *payload);
            match queue.take_completion(read_into) {
                Some(result) => {
                    *in_flight = None;
                    if resuming {
                        return BlockRequestStep::Complete(block_response(
                            request,
                            geometry,
                            completion_status(result),
                        ));
                    }
                }
                None if now_ns >= current.deadline_ns => {
                    abandon(in_flight, queue, current);
                    if resuming {
                        return BlockRequestStep::Complete(block_response(
                            request,
                            geometry,
                            BlockTransportStatus::ResetRequired,
                        ));
                    }
                }
                None => {
                    return BlockRequestStep::Wait {
                        deadline_ns: current.deadline_ns,
                    }
                }
            }
        } else if now_ns >= current.deadline_ns {
            abandon(in_flight, queue, current);
        } else {
            return BlockRequestStep::Wait {
                deadline_ns: current.deadline_ns,
            };
        }
    }
    start_request(in_flight, queue, geometry, caller, request, payload, now_ns)
}

fn start_request<Q: BlockQueue>(
    in_flight: &mut Option<InFlightRequest>,
    queue: &mut Q,
    geometry: BlockGeometry,
    caller: BlockCaller,
    request: &BlockTransportRequest,
    payload: &mut [u8],
    now_ns: u64,
) -> BlockRequestStep {
    let submitted = match classify_block_request(request, geometry, payload.len()) {
        BlockRequestAction::Respond(status) => {
            return BlockRequestStep::Complete(block_response(request, geometry, status));
        }
        BlockRequestAction::Read => queue.submit_read(request.lba, request.blocks, payload.len()),
        BlockRequestAction::Write => queue.submit_write(request.lba, request.blocks, payload),
        BlockRequestAction::Flush => queue.submit_flush(),
    };
    if let Err(error) = submitted {
        return BlockRequestStep::Complete(block_response(
            request,
            geometry,
            block_io_status(error),
        ));
    }
    let deadline_ns = now_ns.saturating_add(BLOCK_COMPLETION_TIMEOUT_NS);
    *in_flight = Some(InFlightRequest {
        owner: caller,
        request: *request,
        deadline_ns,
    });
    BlockRequestStep::Wait { deadline_ns }
}

fn abandon<Q: BlockQueue>(
    in_flight: &mut Option<InFlightRequest>,
    queue: &mut Q,
    current: InFlightRequest,
) {
    queue.abandon_in_flight();
    *in_flight = None;
    kernel_log_fmt(format_args!(
        "[BLK ] request id={} timed out; device requires reset\n",
        current.request.request_id
    ));
}

fn completion_status(result: Result<(), BlockIoError>) -> BlockTransportStatus {
    match result {
        Ok(()) => BlockTransportStatus::Ok,
        Err(error) => block_io_status(error),
    }
}

fn block_op_name(op: BlockTransportOp) -> &'static str {
    match op {
        BlockTransportOp::Geometry => "geometry",
        BlockTransportOp::Read => "read",
        BlockTransportOp::Write => "write",
        BlockTransportOp::Flush => "flush",
    }
}

fn transport_fault_response(request: &BlockTransportRequest) -> BlockTransportResponse {
    block_response(
        request,
        contract_geometry_fallback(),
        BlockTransportStatus::DeviceFault,
    )
}

fn contract_geometry_fallback() -> BlockGeometry {
    BlockGeometry::new(
        BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
        KERNEL_BLOCK_SIZE,
        KERNEL_BLOCK_COUNT,
        KERNEL_MAX_TRANSFER_BLOCKS,
        false,
    )
    .expect("fallback geometry must be valid")
}

fn publish_contract_geometry(transport_geometry: BlockGeometry) -> BlockGeometry {
    BlockGeometry::new(
        BlockDeviceId::new(STORAGE_BLOCK_DEVICE_ID),
        transport_geometry.logical_block_size(),
        transport_geometry.block_count(),
        transport_geometry.max_transfer_blocks(),
        transport_geometry.is_read_only(),
    )
    .expect("virtio geometry should stay valid when published with contract device id")
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_block::BlockTransportError;

    const TEST_BLOCK_BYTES: usize = 512;
    const TEST_BLOCK_COUNT: usize = 8;

    const OWNER: BlockCaller = BlockCaller {
        pid: 4,
        generation: InstanceGeneration(1),
    };
    const OTHER: BlockCaller = BlockCaller {
        pid: 5,
        generation: InstanceGeneration(1),
    };

    /// Completes a submitted request only once `complete` is set, like a device
    /// whose interrupt has not fired yet.
    struct DeferredQueue {
        geometry: BlockGeometry,
        disk: [u8; TEST_BLOCK_BYTES * TEST_BLOCK_COUNT],
        submitted: Option<BlockTransportOp>,
        lba: u64,
        blocks: u32,
        complete: bool,
        abandoned: bool,
    }

    impl DeferredQueue {
        fn new() -> Self {
            Self {
                geometry: BlockGeometry::new(BlockDeviceId::new(77), 512, 8, 4, false).unwrap(),
                disk: [0; TEST_BLOCK_BYTES * TEST_BLOCK_COUNT],
                submitted: None,
                lba: 0,
                blocks: 0,
                complete: false,
                abandoned: false,
            }
        }

        fn fill_block(&mut self, lba: usize, value: u8) {
            self.disk[lba * TEST_BLOCK_BYTES..(lba + 1) * TEST_BLOCK_BYTES].fill(value);
        }
    }

    impl BlockQueue for DeferredQueue {
        fn geometry(&self) -> BlockGeometry {
            self.geometry
        }

        fn submit_read(&mut self, lba: u64, blocks: u32, len: usize) -> Result<(), BlockIoError> {
            self.geometry.validate_read(lba, blocks, len)?;
            self.submitted = Some(BlockTransportOp::Read);
            (self.lba, self.blocks) = (lba, blocks);
            Ok(())
        }

        fn submit_write(&mut self, lba: u64, blocks: u32, data: &[u8]) -> Result<(), BlockIoError> {
            self.geometry.validate_write(lba, blocks, data.len())?;
            let start = lba as usize * TEST_BLOCK_BYTES;
            self.disk[start..start + data.len()].copy_from_slice(data);
            self.submitted = Some(BlockTransportOp::Write);
            Ok(())
        }

        fn submit_flush(&mut self) -> Result<(), BlockIoError> {
            self.submitted = Some(BlockTransportOp::Flush);
            Ok(())
        }

        fn take_completion(
            &mut self,
            read_into: Option<&mut [u8]>,
        ) -> Option<Result<(), BlockIoError>> {
            if !self.complete {
                return None;
            }
            let operation = self.submitted.take()?;
            self.complete = false;
            if let (BlockTransportOp::Read, Some(target)) = (operation, read_into) {
                let start = self.lba as usize * TEST_BLOCK_BYTES;
                let len = self.blocks as usize * TEST_BLOCK_BYTES;
                target.copy_from_slice(&self.disk[start..start + len]);
            }
            Some(Ok(()))
        }

        fn abandon_in_flight(&mut self) {
            self.submitted = None;
            self.abandoned = true;
        }
    }

    fn read_request(request_id: u64) -> BlockTransportRequest {
        BlockTransportRequest {
            request_id,
            device_id: STORAGE_BLOCK_DEVICE_ID,
            operation: BlockTransportOp::Read,
            lba: 2,
            blocks: 1,
            buffer_len: 512,
        }
    }

    fn step(
        in_flight: &mut Option<InFlightRequest>,
        queue: &mut DeferredQueue,
        caller: BlockCaller,
        request: &BlockTransportRequest,
        payload: &mut [u8],
        now_ns: u64,
    ) -> BlockRequestStep {
        step_request(in_flight, queue, caller, request, payload, now_ns, |_| true)
    }

    fn completed_status(step: BlockRequestStep) -> BlockTransportStatus {
        match step {
            BlockRequestStep::Complete(response) => response.status,
            BlockRequestStep::Wait { .. } => panic!("expected a completed request"),
        }
    }

    #[test]
    fn read_waits_for_interrupt_then_harvests_into_payload() {
        let mut queue = DeferredQueue::new();
        queue.fill_block(2, 0x5a);
        let mut in_flight = None;
        let request = read_request(3);
        let mut payload = [0u8; 512];

        let first = step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &request,
            &mut payload,
            10,
        );
        assert_eq!(
            first,
            BlockRequestStep::Wait {
                deadline_ns: 10 + BLOCK_COMPLETION_TIMEOUT_NS
            }
        );
        let spurious = step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &request,
            &mut payload,
            20,
        );
        assert!(matches!(spurious, BlockRequestStep::Wait { .. }));

        queue.complete = true;
        let done = step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &request,
            &mut payload,
            30,
        );
        assert_eq!(completed_status(done), BlockTransportStatus::Ok);
        assert_eq!(payload, [0x5a; 512]);
        assert!(in_flight.is_none());
    }

    #[test]
    fn deadline_abandons_request_and_fails_closed() {
        let mut queue = DeferredQueue::new();
        let mut in_flight = None;
        let request = read_request(4);
        let mut payload = [0u8; 512];

        step(&mut in_flight, &mut queue, OWNER, &request, &mut payload, 0);
        let expired = step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &request,
            &mut payload,
            BLOCK_COMPLETION_TIMEOUT_NS,
        );
        assert_eq!(
            completed_status(expired),
            BlockTransportStatus::ResetRequired
        );
        assert!(queue.abandoned);
        assert!(in_flight.is_none());
    }

    #[test]
    fn second_caller_waits_behind_live_owner_until_deadline() {
        let mut queue = DeferredQueue::new();
        let mut in_flight = None;
        let mut payload = [0u8; 512];
        step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &read_request(5),
            &mut payload,
            0,
        );

        let mut other_payload = [0u8; 512];
        let blocked = step(
            &mut in_flight,
            &mut queue,
            OTHER,
            &read_request(6),
            &mut other_payload,
            1,
        );
        assert_eq!(
            blocked,
            BlockRequestStep::Wait {
                deadline_ns: BLOCK_COMPLETION_TIMEOUT_NS
            }
        );
        assert_eq!(in_flight.map(|f| f.owner), Some(OWNER));

        let after_deadline = step(
            &mut in_flight,
            &mut queue,
            OTHER,
            &read_request(6),
            &mut other_payload,
            BLOCK_COMPLETION_TIMEOUT_NS,
        );
        assert!(
            queue.abandoned,
            "stuck request is abandoned at its deadline"
        );
        assert!(matches!(after_deadline, BlockRequestStep::Wait { .. }));
        assert_eq!(in_flight.map(|f| f.owner), Some(OTHER));
    }

    #[test]
    fn dead_owner_completion_is_drained_without_touching_new_payload() {
        let mut queue = DeferredQueue::new();
        queue.fill_block(2, 0x11);
        let mut in_flight = None;
        let mut payload = [0u8; 512];
        step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &read_request(7),
            &mut payload,
            0,
        );
        queue.complete = true;

        let mut other_payload = [0u8; 512];
        let started = step_request(
            &mut in_flight,
            &mut queue,
            OTHER,
            &read_request(8),
            &mut other_payload,
            1,
            |owner| owner != OWNER,
        );
        assert!(matches!(started, BlockRequestStep::Wait { .. }));
        assert_eq!(other_payload, [0u8; 512]);
        assert_eq!(in_flight.map(|f| f.request.request_id), Some(8));
    }

    #[test]
    fn geometry_and_invalid_requests_complete_without_submission() {
        let mut queue = DeferredQueue::new();
        let mut in_flight = None;
        let geometry = BlockTransportRequest::geometry(1, STORAGE_BLOCK_DEVICE_ID);
        let done = step(&mut in_flight, &mut queue, OWNER, &geometry, &mut [], 0);
        let BlockRequestStep::Complete(response) = done else {
            panic!("geometry completes immediately");
        };
        assert_eq!(response.status, BlockTransportStatus::Ok);
        assert_eq!(response.device_id, STORAGE_BLOCK_DEVICE_ID);
        assert_eq!(response.block_count, 8);

        let mut out_of_range = read_request(2);
        out_of_range.lba = 8;
        let mut payload = [0u8; 512];
        let rejected = step(
            &mut in_flight,
            &mut queue,
            OWNER,
            &out_of_range,
            &mut payload,
            0,
        );
        assert_eq!(
            completed_status(rejected),
            BlockTransportStatus::InvalidRequest
        );
        assert!(queue.submitted.is_none());
        assert!(in_flight.is_none());
    }

    #[test]
    fn device_error_maps_to_transport_status() {
        assert_eq!(
            completion_status(Err(BlockIoError::Transport(
                BlockTransportError::DeviceFault
            ))),
            BlockTransportStatus::DeviceFault
        );
    }

    #[test]
    fn transport_fault_response_marks_device_fault() {
        let request = BlockTransportRequest::geometry(7, STORAGE_BLOCK_DEVICE_ID);
        let response = transport_fault_response(&request);
        assert_eq!(response.request_id, 7);
        assert_eq!(response.device_id, STORAGE_BLOCK_DEVICE_ID);
        assert_eq!(response.operation, BlockTransportOp::Geometry);
        assert_eq!(response.status, BlockTransportStatus::DeviceFault);
    }
}
