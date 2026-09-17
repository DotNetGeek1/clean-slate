//! M5.7 integration self-test: launch storage + unrelated userspace processes,
//! validate authority boundaries, and exercise format/mount/write/commit/read
//! over the real block transport through the shared contract.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::service::block_bridge::handle_kernel_block_request;
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_block::{
    BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError, BlockRequestError,
    BlockTransportError, BlockUnsupportedError,
};
use clean_slate_service_fixtures::{
    BlockTransportOp, BlockTransportRequest, BlockTransportResponse, BlockTransportStatus,
    BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES, BLOCK_TRANSPORT_REQUEST_BYTES, STORAGE_BLOCK_DEVICE_ID,
    STORAGE_SERVICE_ID, STORAGE_UNAUTHORIZED_SERVICE_ID,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};
use clean_slate_store::{IncompatibleFormatError, ObjectStore, StoreError};

const SUPERVISOR_TEST_PID: u64 = 50;
const OBJECT_ALPHA_ID: u64 = 1;
const OBJECT_BETA_ID: u64 = 2;
const OBJECT_ALPHA_NAME: &str = "alpha";
const OBJECT_BETA_NAME: &str = "beta";
const OBJECT_ALPHA_V1: &[u8] = b"alpha-v1";
const OBJECT_ALPHA_V2: &[u8] = b"alpha-v2";
const OBJECT_BETA_V1: &[u8] = b"beta-stable";

pub(crate) const M5_STORAGE_UNAUTHORIZED_DENIED_MARKER: &str = "[BLK ] unauthorized denied pid=";
pub(crate) const M5_STORAGE_PASS_MARKER: &str = "[M5.7] PASS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M5StorageSelfTestState {
    authorized_pid: u64,
    unauthorized_pid: u64,
    authorized_done: bool,
    unauthorized_done: bool,
}

static M5_STORAGE_SELF_TEST_STATE: GlobalCell<Option<M5StorageSelfTestState>> =
    GlobalCell::new(None);

pub(crate) fn start_m5_storage_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    install_service_lifecycle_syscall_allocator(allocator);
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root, kernel_stack_top);
    controller
        .declare_service(STORAGE_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    controller
        .declare_service(STORAGE_UNAUTHORIZED_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("storage self-test allocator was missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    start_service(controller, allocator, capability, STORAGE_SERVICE_ID);
    start_service(
        controller,
        allocator,
        capability,
        STORAGE_UNAUTHORIZED_SERVICE_ID,
    );
    let authorized_pid = controller
        .live_pid(STORAGE_SERVICE_ID)
        .unwrap_or_else(|| fatal_kernel_error("storage service did not become live"));
    let unauthorized_pid = controller
        .live_pid(STORAGE_UNAUTHORIZED_SERVICE_ID)
        .unwrap_or_else(|| fatal_kernel_error("unauthorized probe service did not become live"));
    kernel_log_fmt(format_args!(
        "[STOR] service started pid={authorized_pid}\n"
    ));
    unsafe {
        *M5_STORAGE_SELF_TEST_STATE.get() = Some(M5StorageSelfTestState {
            authorized_pid,
            unauthorized_pid,
            authorized_done: false,
            unauthorized_done: false,
        });
    }
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn start_service(
    controller: &mut crate::service::control::ServiceLifecycleController,
    allocator: &mut PageAllocator,
    capability: u64,
    service: ServiceId,
) {
    controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                service,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("storage self-test service launch failed"));
}

fn current_userspace_pid() -> Result<u64, &'static str> {
    without_interrupts(|| unsafe { scheduler_mut().current_userspace_process_id() })
}

pub(crate) fn handle_userspace_storage_entry() -> u64 {
    let pid = current_userspace_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let state = unsafe {
        (&mut *M5_STORAGE_SELF_TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m5 storage self-test state was not initialized"))
    };
    if pid == state.authorized_pid {
        run_store_integration().unwrap_or_else(|message| fatal_kernel_error(message));
        state.authorized_done = true;
    } else if pid == state.unauthorized_pid {
        state.unauthorized_done = true;
        kernel_log_fmt(format_args!(
            "{M5_STORAGE_UNAUTHORIZED_DENIED_MARKER}{pid}\n"
        ));
    } else {
        fatal_kernel_error("unexpected process reached m5 storage entry trap");
    }
    let complete = state.authorized_done && state.unauthorized_done;
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("service lifecycle allocator was unavailable"));
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if complete {
        unsafe {
            *M5_STORAGE_SELF_TEST_STATE.get() = None;
        }
        kernel_log_line(M5_STORAGE_PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
    teardown
        .next_stack_pointer
        .unwrap_or_else(|| fatal_kernel_error("no runnable thread remained during m5 self-test"))
}

fn run_store_integration() -> Result<(), &'static str> {
    let mut store = match ObjectStore::mount(KernelStorageBlockAdapter::attach()?) {
        Ok(store) => {
            kernel_log_fmt(format_args!(
                "[STOR] mounted generation={}\n",
                store.committed_generation()
            ));
            store
        }
        Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic)) => {
            let store = ObjectStore::format(KernelStorageBlockAdapter::attach()?)
                .map_err(map_store_error)?;
            kernel_log_fmt(format_args!(
                "[STOR] format generation={}\n",
                store.committed_generation()
            ));
            store
        }
        Err(error) => return Err(map_store_error(error)),
    };

    store
        .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, OBJECT_ALPHA_V1)
        .map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] write object={} bytes={}\n",
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_V1.len()
    ));
    store
        .write_object(OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)
        .map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] write object={} bytes={}\n",
        OBJECT_BETA_ID,
        OBJECT_BETA_V1.len()
    ));
    store.commit().map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] commit generation={}\n",
        store.committed_generation()
    ));

    let alpha_v1 = store
        .read_object_by_id(OBJECT_ALPHA_ID)
        .map_err(map_store_error)?;
    let beta_v1 = store
        .read_object_by_id(OBJECT_BETA_ID)
        .map_err(map_store_error)?;
    log_match(
        OBJECT_ALPHA_ID,
        alpha_v1.len(),
        alpha_v1.as_slice() == OBJECT_ALPHA_V1,
    );
    log_match(
        OBJECT_BETA_ID,
        beta_v1.len(),
        beta_v1.as_slice() == OBJECT_BETA_V1,
    );
    if alpha_v1.as_slice() != OBJECT_ALPHA_V1 || beta_v1.as_slice() != OBJECT_BETA_V1 {
        return Err("initial object readback mismatch");
    }

    let mut remounted =
        ObjectStore::mount(KernelStorageBlockAdapter::attach()?).map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] mounted generation={}\n",
        remounted.committed_generation()
    ));
    remounted
        .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, OBJECT_ALPHA_V2)
        .map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] write object={} bytes={}\n",
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_V2.len()
    ));
    remounted.commit().map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] commit generation={}\n",
        remounted.committed_generation()
    ));

    let final_store =
        ObjectStore::mount(KernelStorageBlockAdapter::attach()?).map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] mounted generation={}\n",
        final_store.committed_generation()
    ));
    let alpha_v2 = final_store
        .read_object_by_id(OBJECT_ALPHA_ID)
        .map_err(map_store_error)?;
    let beta_preserved = final_store
        .read_object_by_id(OBJECT_BETA_ID)
        .map_err(map_store_error)?;
    log_match(
        OBJECT_ALPHA_ID,
        alpha_v2.len(),
        alpha_v2.as_slice() == OBJECT_ALPHA_V2,
    );
    log_match(
        OBJECT_BETA_ID,
        beta_preserved.len(),
        beta_preserved.as_slice() == OBJECT_BETA_V1,
    );
    if alpha_v2.as_slice() != OBJECT_ALPHA_V2 || beta_preserved.as_slice() != OBJECT_BETA_V1 {
        return Err("overwrite changed unrelated object");
    }

    assert_malformed_media_rejected()?;
    Ok(())
}

fn assert_malformed_media_rejected() -> Result<(), &'static str> {
    let mut device = KernelStorageBlockAdapter::attach()?;
    let block_size = usize::try_from(device.geometry().logical_block_size())
        .map_err(|_| "logical block size overflow")?;
    if block_size > BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES {
        return Err("logical block size exceeds transport payload bound");
    }
    let mut corrupted = [0u8; BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES];
    corrupted[..block_size].fill(0xA5);
    device
        .write_blocks(0, 1, &corrupted[..block_size])
        .map_err(map_block_error)?;
    device
        .write_blocks(1, 1, &corrupted[..block_size])
        .map_err(map_block_error)?;
    device.flush().map_err(map_block_error)?;

    match ObjectStore::mount(KernelStorageBlockAdapter::attach()?) {
        Err(StoreError::Incompatible(_) | StoreError::Corrupt(_)) => {
            kernel_log_line("[STOR] malformed media rejected");
            Ok(())
        }
        Ok(_) => Err("malformed media unexpectedly mounted"),
        Err(error) => Err(map_store_error(error)),
    }
}

fn log_match(id: u64, bytes: usize, ok: bool) {
    kernel_log_fmt(format_args!(
        "[STOR] read object={id} bytes={bytes} match={}\n",
        if ok { "yes" } else { "no" }
    ));
}

fn map_store_error(error: StoreError) -> &'static str {
    match error {
        StoreError::Block(error) => map_block_error(error),
        StoreError::UnsupportedGeometry { .. } => "store geometry unsupported",
        StoreError::InvalidObjectName => "store object name invalid",
        StoreError::ObjectNameTooLong { .. } => "store object name too long",
        StoreError::ObjectTooLarge { .. } => "store object too large",
        StoreError::ObjectTableFull { .. } => "store object table full",
        StoreError::StorageFull { .. } => "store storage full",
        StoreError::NotFound => "store object missing",
        StoreError::IdentityConflict => "store identity conflict",
        StoreError::GenerationExhausted => "store generation exhausted",
        StoreError::Incompatible(_) => "store media incompatible",
        StoreError::Corrupt(_) => "store media corrupt",
    }
}

fn map_block_error(error: BlockIoError) -> &'static str {
    match error {
        BlockIoError::InvalidRequest(_) => "block request invalid",
        BlockIoError::Unsupported(_) => "block request unsupported",
        BlockIoError::Transport(BlockTransportError::DeviceFault) => "block device fault",
        BlockIoError::Transport(BlockTransportError::Timeout) => "block request timed out",
        BlockIoError::Transport(BlockTransportError::ResetRequired) => "block reset required",
    }
}

struct KernelStorageBlockAdapter {
    geometry: BlockGeometry,
    next_request_id: u64,
}

impl KernelStorageBlockAdapter {
    fn attach() -> Result<Self, &'static str> {
        let mut payload: [u8; 0] = [];
        let response = issue_block_request(
            BlockTransportRequest::geometry(1, STORAGE_BLOCK_DEVICE_ID),
            &mut payload,
        )
        .map_err(map_block_error)?;
        let geometry = BlockGeometry::new(
            BlockDeviceId::new(response.device_id),
            response.logical_block_size,
            response.block_count,
            response.max_transfer_blocks,
            false,
        )
        .map_err(|_| "kernel returned invalid block geometry")?;
        Ok(Self {
            geometry,
            next_request_id: 2,
        })
    }

    fn dispatch(
        &mut self,
        operation: BlockTransportOp,
        lba: u64,
        blocks: u32,
        payload: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let buffer_len = u32::try_from(payload.len())
            .map_err(|_| BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow))?;
        let request = BlockTransportRequest {
            request_id: self.next_request_id,
            device_id: self.geometry.device_id().get(),
            operation,
            lba,
            blocks,
            buffer_len,
        };
        self.next_request_id = self.next_request_id.saturating_add(1);
        let response = issue_block_request(request, payload)?;
        map_transport_status(response.status)
    }
}

impl BlockDevice for KernelStorageBlockAdapter {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        self.geometry.validate_read(lba, blocks, buffer.len())?;
        self.dispatch(BlockTransportOp::Read, lba, blocks, buffer)
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        self.geometry.validate_write(lba, blocks, buffer.len())?;
        let mut payload = [0u8; BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES];
        payload[..buffer.len()].copy_from_slice(buffer);
        self.dispatch(
            BlockTransportOp::Write,
            lba,
            blocks,
            &mut payload[..buffer.len()],
        )
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        let mut payload: [u8; 0] = [];
        self.dispatch(BlockTransportOp::Flush, 0, 0, &mut payload)
    }
}

fn issue_block_request(
    request: BlockTransportRequest,
    payload: &mut [u8],
) -> Result<BlockTransportResponse, BlockIoError> {
    let wire: [u8; BLOCK_TRANSPORT_REQUEST_BYTES] = request.encode();
    let response_wire = handle_kernel_block_request(&wire, payload);
    BlockTransportResponse::decode(&response_wire)
        .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))
}

fn map_transport_status(status: BlockTransportStatus) -> Result<(), BlockIoError> {
    match status {
        BlockTransportStatus::Ok => Ok(()),
        BlockTransportStatus::InvalidProtocol => {
            Err(BlockIoError::Transport(BlockTransportError::ResetRequired))
        }
        BlockTransportStatus::InvalidRequest => {
            Err(BlockIoError::InvalidRequest(BlockRequestError::ZeroBlocks))
        }
        BlockTransportStatus::Unsupported => Err(BlockIoError::Unsupported(
            BlockUnsupportedError::FlushUnsupported,
        )),
        BlockTransportStatus::DeviceFault => {
            Err(BlockIoError::Transport(BlockTransportError::DeviceFault))
        }
        BlockTransportStatus::Timeout => Err(BlockIoError::Transport(BlockTransportError::Timeout)),
        BlockTransportStatus::ResetRequired => {
            Err(BlockIoError::Transport(BlockTransportError::ResetRequired))
        }
    }
}
