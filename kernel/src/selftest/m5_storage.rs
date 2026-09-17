//! M5 storage self-tests over the production block bridge and VirtIO backend.
//!
//! The existing M5.7 lane validates the storage-service authority seam and
//! single-boot store integration. The newer M5 milestone lanes reuse the same
//! `KernelStorageBlockAdapter` path for deterministic reboot persistence and
//! abrupt-stop crash recovery on the persistent QEMU disk.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::halt_loop;
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
const PERSISTENCE_ALPHA_V1: [u8; 1300] = [0x11; 1300];
const PERSISTENCE_ALPHA_V2: [u8; 900] = [0x22; 900];
const PERSISTENCE_ALPHA_V3: [u8; 700] = [0x33; 700];
const CRASH_AFTER_WRITE: u64 = 1;

pub(crate) const M5_STORAGE_UNAUTHORIZED_DENIED_MARKER: &str = "[BLK ] unauthorized denied pid=";
pub(crate) const M5_STORAGE_PASS_MARKER: &str = "[M5.7] PASS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum M5StorageSelfTestMode {
    Integration,
    Persistence,
    CrashRecovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M5StorageSelfTestState {
    mode: M5StorageSelfTestMode,
    authorized_pid: u64,
    unauthorized_pid: Option<u64>,
    authorized_done: bool,
    unauthorized_done: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M5CrashPlan {
    after_write: u64,
    writes_seen: u64,
}

static M5_STORAGE_SELF_TEST_STATE: GlobalCell<Option<M5StorageSelfTestState>> =
    GlobalCell::new(None);
static M5_CRASH_PLAN: GlobalCell<Option<M5CrashPlan>> = GlobalCell::new(None);

pub(crate) fn start_m5_storage_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
        *M5_CRASH_PLAN.get() = None;
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
    let mode = active_self_test_mode();
    if mode == M5StorageSelfTestMode::Integration {
        controller
            .declare_service(STORAGE_UNAUTHORIZED_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
    }
    let capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("storage self-test allocator was missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    start_service(controller, allocator, capability, STORAGE_SERVICE_ID);
    if mode == M5StorageSelfTestMode::Integration {
        start_service(
            controller,
            allocator,
            capability,
            STORAGE_UNAUTHORIZED_SERVICE_ID,
        );
    }
    let authorized_pid = controller
        .live_pid(STORAGE_SERVICE_ID)
        .unwrap_or_else(|| fatal_kernel_error("storage service did not become live"));
    let unauthorized_pid = if mode == M5StorageSelfTestMode::Integration {
        Some(
            controller
                .live_pid(STORAGE_UNAUTHORIZED_SERVICE_ID)
                .unwrap_or_else(|| {
                    fatal_kernel_error("unauthorized probe service did not become live")
                }),
        )
    } else {
        None
    };
    kernel_log_fmt(format_args!(
        "[STOR] service started pid={authorized_pid}\n"
    ));
    unsafe {
        *M5_STORAGE_SELF_TEST_STATE.get() = Some(M5StorageSelfTestState {
            mode,
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

fn active_self_test_mode() -> M5StorageSelfTestMode {
    if cfg!(feature = "m5-storage-self-test") {
        M5StorageSelfTestMode::Integration
    } else if cfg!(feature = "m5-persistence-self-test") {
        M5StorageSelfTestMode::Persistence
    } else if cfg!(feature = "m5-crash-recovery-self-test") {
        M5StorageSelfTestMode::CrashRecovery
    } else {
        fatal_kernel_error("no M5 storage self-test mode was enabled")
    }
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
        match state.mode {
            M5StorageSelfTestMode::Integration => {
                run_store_integration().unwrap_or_else(|message| fatal_kernel_error(message));
            }
            M5StorageSelfTestMode::Persistence => {
                run_persistence_flow().unwrap_or_else(|message| fatal_kernel_error(message));
            }
            M5StorageSelfTestMode::CrashRecovery => {
                run_crash_recovery_flow().unwrap_or_else(|message| fatal_kernel_error(message));
            }
        }
        state.authorized_done = true;
    } else if Some(pid) == state.unauthorized_pid {
        state.unauthorized_done = true;
    } else {
        fatal_kernel_error("unexpected process reached m5 storage entry trap");
    }
    let complete =
        state.authorized_done && (state.unauthorized_pid.is_none() || state.unauthorized_done);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("service lifecycle allocator was unavailable"));
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if complete {
        if let Some(unauthorized_pid) = state.unauthorized_pid {
            kernel_log_fmt(format_args!(
                "{M5_STORAGE_UNAUTHORIZED_DENIED_MARKER}{unauthorized_pid}\n{M5_STORAGE_PASS_MARKER}\n"
            ));
        }
        unsafe {
            *M5_STORAGE_SELF_TEST_STATE.get() = None;
            *M5_CRASH_PLAN.get() = None;
        }
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

fn run_persistence_flow() -> Result<(), &'static str> {
    match ObjectStore::mount(KernelStorageBlockAdapter::attach()?) {
        Ok(mut store) => match store.committed_generation() {
            1 => run_persistence_recovery_boot(&mut store),
            2 => run_interrupted_commit_boot(&mut store),
            generation => {
                kernel_log_fmt(format_args!("[STOR] recovered generation={generation}\n"));
                Err("unexpected committed generation for persistence self-test")
            }
        },
        Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic)) => {
            run_persistence_write_boot()
        }
        Err(error) => Err(map_store_error(error)),
    }
}

fn run_persistence_write_boot() -> Result<(), &'static str> {
    let mut store =
        ObjectStore::format(KernelStorageBlockAdapter::attach()?).map_err(map_store_error)?;
    kernel_log_line("[STOR] mounted generation=fresh");
    write_named_object(
        &mut store,
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_NAME,
        &PERSISTENCE_ALPHA_V1,
    )?;
    write_named_object(&mut store, OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)?;
    store.commit().map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] commit generation={}\n",
        store.committed_generation()
    ));
    kernel_log_line("[TEST] persistence phase=write PASS");
    Ok(())
}

fn run_persistence_recovery_boot(
    store: &mut ObjectStore<KernelStorageBlockAdapter>,
) -> Result<(), &'static str> {
    kernel_log_fmt(format_args!(
        "[STOR] recovered generation={}\n",
        store.committed_generation()
    ));
    verify_named_object(
        store,
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_NAME,
        &PERSISTENCE_ALPHA_V1,
    )?;
    verify_named_object(store, OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)?;
    write_named_object(
        store,
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_NAME,
        &PERSISTENCE_ALPHA_V2,
    )?;
    store.commit().map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] commit generation={}\n",
        store.committed_generation()
    ));
    let remounted =
        ObjectStore::mount(KernelStorageBlockAdapter::attach()?).map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] recovered generation={}\n",
        remounted.committed_generation()
    ));
    verify_named_object(
        &remounted,
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_NAME,
        &PERSISTENCE_ALPHA_V2,
    )?;
    verify_named_object(&remounted, OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)?;
    kernel_log_line("[TEST] persistence phase=read PASS");
    Ok(())
}

fn run_interrupted_commit_boot(
    store: &mut ObjectStore<KernelStorageBlockAdapter>,
) -> Result<(), &'static str> {
    kernel_log_fmt(format_args!(
        "[STOR] recovered generation={}\n",
        store.committed_generation()
    ));
    verify_named_object(
        store,
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_NAME,
        &PERSISTENCE_ALPHA_V2,
    )?;
    verify_named_object(store, OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)?;
    arm_crash_after_write(CRASH_AFTER_WRITE);
    kernel_log_fmt(format_args!(
        "[CRSH] armed trigger=after-write={CRASH_AFTER_WRITE}\n"
    ));
    write_named_object(
        store,
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_NAME,
        &PERSISTENCE_ALPHA_V3,
    )?;
    store.commit().map_err(map_store_error)?;
    Err("deterministic crash point did not interrupt commit")
}

fn run_crash_recovery_flow() -> Result<(), &'static str> {
    let store =
        ObjectStore::mount(KernelStorageBlockAdapter::attach()?).map_err(map_store_error)?;
    let generation = store.committed_generation();
    kernel_log_fmt(format_args!("[STOR] recovered generation={generation}\n"));
    match generation {
        2 => {
            verify_named_object(
                &store,
                OBJECT_ALPHA_ID,
                OBJECT_ALPHA_NAME,
                &PERSISTENCE_ALPHA_V2,
            )?;
            verify_named_object(&store, OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)?;
            kernel_log_line("[CRSH] recovery outcome=previous-commit");
        }
        3 => {
            verify_named_object(
                &store,
                OBJECT_ALPHA_ID,
                OBJECT_ALPHA_NAME,
                &PERSISTENCE_ALPHA_V3,
            )?;
            verify_named_object(&store, OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)?;
            kernel_log_line("[CRSH] recovery outcome=new-commit");
        }
        _ => return Err("unexpected recovered generation after crash"),
    }
    kernel_log_line("[TEST] crash recovery PASS");
    Ok(())
}

fn write_named_object(
    store: &mut ObjectStore<KernelStorageBlockAdapter>,
    id: u64,
    name: &str,
    bytes: &[u8],
) -> Result<(), &'static str> {
    store
        .write_object(id, name, bytes)
        .map_err(map_store_error)?;
    kernel_log_fmt(format_args!(
        "[STOR] write object={name} id={id} bytes={} checksum={:08x}\n",
        bytes.len(),
        checksum(bytes)
    ));
    Ok(())
}

fn verify_named_object(
    store: &ObjectStore<KernelStorageBlockAdapter>,
    id: u64,
    name: &str,
    expected: &[u8],
) -> Result<(), &'static str> {
    let actual = store.read_object_by_id(id).map_err(map_store_error)?;
    let ok = actual.as_slice() == expected;
    kernel_log_fmt(format_args!(
        "[STOR] read object={name} id={id} bytes={} checksum={:08x} match={}\n",
        actual.len(),
        checksum(actual.as_slice()),
        if ok { "yes" } else { "no" }
    ));
    if !ok {
        return Err("persistent object contents did not match expected bytes");
    }
    Ok(())
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

fn arm_crash_after_write(after_write: u64) {
    unsafe {
        *M5_CRASH_PLAN.get() = Some(M5CrashPlan {
            after_write,
            writes_seen: 0,
        });
    }
}

fn observe_write_completion(after_write: u64) -> ! {
    kernel_log_fmt(format_args!("[CRSH] inject after-write={after_write}\n"));
    halt_loop()
}

fn observe_block_operation(operation: BlockTransportOp) {
    match operation {
        BlockTransportOp::Write => {
            let plan = unsafe { &mut *M5_CRASH_PLAN.get() };
            let Some(crash_plan) = plan.as_mut() else {
                return;
            };
            crash_plan.writes_seen = crash_plan.writes_seen.saturating_add(1);
            if crash_plan.writes_seen == crash_plan.after_write {
                let after_write = crash_plan.after_write;
                *plan = None;
                observe_write_completion(after_write);
            }
        }
        BlockTransportOp::Flush => kernel_log_line("[BLK ] flush complete"),
        BlockTransportOp::Geometry | BlockTransportOp::Read => {}
    }
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
        map_transport_status(response.status)?;
        observe_block_operation(operation);
        Ok(())
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
