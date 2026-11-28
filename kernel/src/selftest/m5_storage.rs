//! M5 storage self-tests that orchestrate a real CPL3 storage-service runtime.
//!
//! The kernel self-test is limited to launching storage-service processes,
//! granting and revoking block authority, injecting deterministic crash points,
//! and validating the userspace service's reported results. Persistent-store
//! policy itself runs inside the userspace storage service over the production
//! capability-gated block syscall path.
//!
//! Phase handoff uses the production exit path: when a service instance traps
//! back with its report, the next phase is launched into a free scheduler slot
//! *before* the reporting process is torn down, so `teardown_current_process`
//! selects the new thread through the scheduler and prepares its dispatch
//! exactly as it does for any other exiting userspace thread.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::halt_loop;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::initialize_timer;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::user_access::read_user;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::Scheduler;
use crate::service::control::LifecycleControlError;
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_service_fixtures::manifest::{
    validate_manifest, Grant, Liveness, RestartSpec, ServiceImage, ServiceSpec, Start,
    STORAGE_SERVICE_SPEC,
};
use clean_slate_service_fixtures::object_churn::{
    churn_absent_count, churn_expected_fingerprint, churn_live_count, CHURN_ADDED, CHURN_CREATED,
    CHURN_DELETED, CHURN_FINGERPRINT_SEED, CHURN_RECREATED,
};
use clean_slate_service_fixtures::{
    BlockTransportOp, BlockTransportRequest, StorageServiceBootstrap,
    STORAGE_SERVICE_BOOTSTRAP_ADDRESS, STORAGE_SERVICE_ID, STORAGE_SERVICE_MODE_CRASH_ARM_EARLY,
    STORAGE_SERVICE_MODE_CRASH_ARM_LATE, STORAGE_SERVICE_MODE_CRASH_RECOVERY,
    STORAGE_SERVICE_MODE_INTEGRATION_INITIAL, STORAGE_SERVICE_MODE_INTEGRATION_RESTART,
    STORAGE_SERVICE_MODE_OBJECT_CHURN, STORAGE_SERVICE_MODE_PERSISTENCE,
    STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE, STORAGE_SERVICE_RESULT_OK,
    STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED, STORAGE_UNAUTHORIZED_SERVICE_ID,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};

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
const CRASH_AFTER_WRITE_EARLY: u64 = 1;
const CRASH_AFTER_WRITE_LATE: u64 = 4;
const SYSCALL_ESTALE: u64 = u64::MAX - 116;
/// Logical block size of the M5 QEMU disk; the store's superblock is one block.
const SUPERBLOCK_BYTES: usize = 512;
const SUPERBLOCK_SLOT_ONE_LBA: u64 = 1;
/// Start of the superblock's object-table extent: the torn copy carries generation 3's
/// header up to its next epoch, and slot 1's old table extent and table checksum.
const SUPERBLOCK_TEAR_OFFSET: usize = 56;
const PAYLOAD_TEAR_WRITE: u64 = 1;
const PAYLOAD_TEAR_BLOCKS: u32 = 2;

pub(crate) const M5_STORAGE_UNAUTHORIZED_DENIED_MARKER: &str = "[BLK ] unauthorized denied pid=";
pub(crate) const M5_STORAGE_PASS_MARKER: &str = "[M5.7] PASS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum M5StorageSelfTestMode {
    Integration,
    Persistence,
    /// Two boots of the object-churn script (#224 stage F).
    ObjectChurn,
    CrashArmEarly,
    CrashArmLate,
    CrashTornSuperblock,
    CrashTornPayload,
    CrashRecovery,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IntegrationPhase {
    InitialAuthorized,
    UnauthorizedProbe,
    RestartAuthorized,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M5StorageSelfTestState {
    mode: M5StorageSelfTestMode,
    lifecycle_capability: u64,
    phase: IntegrationPhase,
    previous_handle: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M5CrashPlan {
    after_write: u64,
    writes_seen: u64,
    tear: M5Tear,
}

/// How the crash-arm boot tears one write of the generation-3 commit (alpha's two-block
/// payload, beta's payload, the object table, the superblock into slot 1) before it stops
/// after write 4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum M5Tear {
    None,
    /// The superblock write keeps its first `SUPERBLOCK_TEAR_OFFSET` bytes; the rest of
    /// the sector is what slot 1 held, as read from the device when the service mounted
    /// (`M5_STALE_SUPERBLOCK_SLOT`).
    SuperblockSuffix,
    /// Only the first block of alpha's payload write reaches the device, yet the write
    /// reports success, so the payload flush cannot repair it. Beta's payload, the object
    /// table and the superblock then complete, as on a device that loses or misdirects a
    /// write.
    PayloadPrefix {
        torn_lba: Option<u64>,
    },
}

static M5_STORAGE_SELF_TEST_STATE: GlobalCell<Option<M5StorageSelfTestState>> =
    GlobalCell::new(None);
static M5_CRASH_PLAN: GlobalCell<Option<M5CrashPlan>> = GlobalCell::new(None);
static M5_STALE_SUPERBLOCK_SLOT: GlobalCell<Option<[u8; SUPERBLOCK_BYTES]>> = GlobalCell::new(None);

/// M5 runs storage in modes that predate the object service, so the service gets the block device
/// only and the unauthorized probe gets nothing. Each self-test mode and integration phase runs
/// the service in a different bootstrap mode, so each has its own manifest.
const fn m5_storage_row(mode: u64) -> ServiceSpec {
    ServiceSpec {
        mode,
        grants: &[Grant::BlockDevice],
        restart: RestartSpec::Never,
        ..STORAGE_SERVICE_SPEC
    }
}

const M5_UNAUTHORIZED_ROW: ServiceSpec = ServiceSpec {
    id: STORAGE_UNAUTHORIZED_SERVICE_ID,
    image: ServiceImage::Storage,
    mode: STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE,
    grants: &[],
    restart: RestartSpec::Never,
    depends_on: &[],
    slot_allowance: None,
    memory_pages: 0,
    launch_name: None,
    start: Start::AtBoot,
    liveness: Liveness::Off,
};

const M5_PERSISTENCE_SCENARIO: &[ServiceSpec] = &[m5_storage_row(STORAGE_SERVICE_MODE_PERSISTENCE)];
const M5_OBJECT_CHURN_SCENARIO: &[ServiceSpec] =
    &[m5_storage_row(STORAGE_SERVICE_MODE_OBJECT_CHURN)];
const M5_CRASH_ARM_EARLY_SCENARIO: &[ServiceSpec] =
    &[m5_storage_row(STORAGE_SERVICE_MODE_CRASH_ARM_EARLY)];
const M5_CRASH_ARM_LATE_SCENARIO: &[ServiceSpec] =
    &[m5_storage_row(STORAGE_SERVICE_MODE_CRASH_ARM_LATE)];
const M5_CRASH_RECOVERY_SCENARIO: &[ServiceSpec] =
    &[m5_storage_row(STORAGE_SERVICE_MODE_CRASH_RECOVERY)];
const M5_INTEGRATION_INITIAL_SCENARIO: &[ServiceSpec] = &[
    m5_storage_row(STORAGE_SERVICE_MODE_INTEGRATION_INITIAL),
    M5_UNAUTHORIZED_ROW,
];
const M5_INTEGRATION_RESTART_SCENARIO: &[ServiceSpec] = &[
    m5_storage_row(STORAGE_SERVICE_MODE_INTEGRATION_RESTART),
    M5_UNAUTHORIZED_ROW,
];
const _: () = assert!(validate_manifest(M5_PERSISTENCE_SCENARIO).is_ok());
const _: () = assert!(validate_manifest(M5_OBJECT_CHURN_SCENARIO).is_ok());
const _: () = assert!(validate_manifest(M5_CRASH_ARM_EARLY_SCENARIO).is_ok());
const _: () = assert!(validate_manifest(M5_CRASH_ARM_LATE_SCENARIO).is_ok());
const _: () = assert!(validate_manifest(M5_CRASH_RECOVERY_SCENARIO).is_ok());
const _: () = assert!(validate_manifest(M5_INTEGRATION_INITIAL_SCENARIO).is_ok());
const _: () = assert!(validate_manifest(M5_INTEGRATION_RESTART_SCENARIO).is_ok());

/// The manifest whose rows give the instance `launch_phase` starts for `state` its mode.
fn m5_scenario(state: &M5StorageSelfTestState) -> &'static [ServiceSpec] {
    match state.mode {
        M5StorageSelfTestMode::Integration => match state.phase {
            IntegrationPhase::InitialAuthorized | IntegrationPhase::UnauthorizedProbe => {
                M5_INTEGRATION_INITIAL_SCENARIO
            }
            IntegrationPhase::RestartAuthorized => M5_INTEGRATION_RESTART_SCENARIO,
        },
        M5StorageSelfTestMode::Persistence => M5_PERSISTENCE_SCENARIO,
        M5StorageSelfTestMode::ObjectChurn => M5_OBJECT_CHURN_SCENARIO,
        M5StorageSelfTestMode::CrashArmEarly => M5_CRASH_ARM_EARLY_SCENARIO,
        M5StorageSelfTestMode::CrashArmLate
        | M5StorageSelfTestMode::CrashTornSuperblock
        | M5StorageSelfTestMode::CrashTornPayload => M5_CRASH_ARM_LATE_SCENARIO,
        M5StorageSelfTestMode::CrashRecovery => M5_CRASH_RECOVERY_SCENARIO,
    }
}

/// The handle the restarted integration instance resumes from; every other start resumes from
/// nothing.
fn m5_previous_handle(state: &M5StorageSelfTestState) -> u64 {
    match (state.mode, state.phase) {
        (M5StorageSelfTestMode::Integration, IntegrationPhase::RestartAuthorized) => {
            state.previous_handle
        }
        _ => 0,
    }
}

pub(crate) fn start_m5_storage_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
        *M5_CRASH_PLAN.get() = None;
        *M5_STALE_SUPERBLOCK_SLOT.get() = None;
    }
    let kernel_root = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(allocator);
    let mode = active_self_test_mode();
    let capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root);
        controller
            .declare_service(STORAGE_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        if mode == M5StorageSelfTestMode::Integration {
            controller
                .declare_service(STORAGE_UNAUTHORIZED_SERVICE_ID)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        controller
            .grant_lifecycle_control_capability(
                SUPERVISOR_TEST_PID,
                &[STORAGE_SERVICE_ID, STORAGE_UNAUTHORIZED_SERVICE_ID],
            )
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    let initial_state = M5StorageSelfTestState {
        mode,
        lifecycle_capability: capability,
        phase: IntegrationPhase::InitialAuthorized,
        previous_handle: 0,
    };
    set_self_test_state(Some(initial_state));
    match mode {
        M5StorageSelfTestMode::CrashArmEarly => {
            arm_crash_after_write(CRASH_AFTER_WRITE_EARLY, M5Tear::None)
        }
        M5StorageSelfTestMode::CrashArmLate => {
            arm_crash_after_write(CRASH_AFTER_WRITE_LATE, M5Tear::None)
        }
        M5StorageSelfTestMode::CrashTornSuperblock => {
            arm_crash_after_write(CRASH_AFTER_WRITE_LATE, M5Tear::SuperblockSuffix)
        }
        M5StorageSelfTestMode::CrashTornPayload => arm_crash_after_write(
            CRASH_AFTER_WRITE_LATE,
            M5Tear::PayloadPrefix { torn_lba: None },
        ),
        M5StorageSelfTestMode::Integration
        | M5StorageSelfTestMode::Persistence
        | M5StorageSelfTestMode::ObjectChurn
        | M5StorageSelfTestMode::CrashRecovery => {}
    }
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("storage self-test allocator was missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    launch_phase(initial_state, controller, allocator);
    initialize_timer();
    // `m3-entry-self-test` skips calibration inside `initialize_timer`; block
    // completion waits use TSC `MonotonicNs` deadlines, expired by the timer IRQ.
    crate::time::calibration::calibrate_apic_tick();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn active_self_test_mode() -> M5StorageSelfTestMode {
    if cfg!(feature = "m5-storage-self-test") {
        M5StorageSelfTestMode::Integration
    } else if cfg!(feature = "m5-object-churn-self-test") {
        // Implies `m5-persistence-self-test`, so it is tested first.
        M5StorageSelfTestMode::ObjectChurn
    } else if cfg!(feature = "m5-persistence-self-test") {
        M5StorageSelfTestMode::Persistence
    } else if cfg!(feature = "m5-crash-early-self-test") {
        M5StorageSelfTestMode::CrashArmEarly
    } else if cfg!(feature = "m5-crash-torn-superblock-self-test") {
        M5StorageSelfTestMode::CrashTornSuperblock
    } else if cfg!(feature = "m5-crash-torn-payload-self-test") {
        M5StorageSelfTestMode::CrashTornPayload
    } else if cfg!(feature = "m5-crash-late-self-test") {
        M5StorageSelfTestMode::CrashArmLate
    } else if cfg!(feature = "m5-crash-recovery-self-test") {
        M5StorageSelfTestMode::CrashRecovery
    } else {
        fatal_kernel_error("no M5 storage self-test mode was enabled")
    }
}

/// Copies the current self-test state out of its cell. Callers work on the
/// copy so no borrow of the cell is alive while launch or teardown code runs.
fn self_test_state() -> Result<M5StorageSelfTestState, &'static str> {
    unsafe {
        (*M5_STORAGE_SELF_TEST_STATE.get())
            .as_ref()
            .copied()
            .ok_or("m5 storage self-test state was not initialized")
    }
}

fn set_self_test_state(state: Option<M5StorageSelfTestState>) {
    unsafe {
        *M5_STORAGE_SELF_TEST_STATE.get() = state;
    }
}

/// Starts the service for `state.phase` through the lifecycle controller and
/// returns the new instance's pid. The phase's scenario manifest decides the
/// instance's bootstrap mode.
fn launch_phase(
    state: M5StorageSelfTestState,
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
) -> u64 {
    let service = current_service(&state);
    controller.use_scenario_manifest(m5_scenario(&state));
    controller.set_scenario_previous_handle(m5_previous_handle(&state));
    let result = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            state.lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                service,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("storage self-test service launch failed"));
    let pid = result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("storage service launch did not report an instance"));
    kernel_log_fmt(format_args!(
        "[STOR] service started pid={pid} service={} phase={:?}\n",
        service.0, state.phase
    ));
    pid
}

fn current_service(state: &M5StorageSelfTestState) -> ServiceId {
    match state.mode {
        M5StorageSelfTestMode::Integration => match state.phase {
            IntegrationPhase::InitialAuthorized | IntegrationPhase::RestartAuthorized => {
                STORAGE_SERVICE_ID
            }
            IntegrationPhase::UnauthorizedProbe => STORAGE_UNAUTHORIZED_SERVICE_ID,
        },
        M5StorageSelfTestMode::Persistence
        | M5StorageSelfTestMode::ObjectChurn
        | M5StorageSelfTestMode::CrashArmEarly
        | M5StorageSelfTestMode::CrashArmLate
        | M5StorageSelfTestMode::CrashTornSuperblock
        | M5StorageSelfTestMode::CrashTornPayload
        | M5StorageSelfTestMode::CrashRecovery => STORAGE_SERVICE_ID,
    }
}

fn current_userspace_pid() -> Result<u64, &'static str> {
    crate::process::current_process_id()
}

/// `USER_TEST_VECTOR` handler: a storage-service instance has finished its
/// phase and trapped back with its report in the bootstrap page.
///
/// Returns the kernel stack pointer to restore, which is always the freshly
/// launched next-phase thread selected by `teardown_current_process`. When no
/// phase remains the self-test exits QEMU instead of returning.
/// The storage service's bootstrap page, read in its own address space.
fn storage_service_report() -> StorageServiceBootstrap {
    read_user(STORAGE_SERVICE_BOOTSTRAP_ADDRESS)
        .unwrap_or_else(|message| fatal_kernel_error(message))
}

pub(crate) fn handle_userspace_storage_entry() -> u64 {
    let pid = current_userspace_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let report = &storage_service_report();
    crate::service::storage_refusal::log_refusal(report);
    let state = self_test_state().unwrap_or_else(|message| fatal_kernel_error(message));
    let next_state = match state.mode {
        M5StorageSelfTestMode::Integration => handle_integration_phase(state, pid, report),
        M5StorageSelfTestMode::Persistence => {
            validate_persistence(report).unwrap_or_else(|message| fatal_kernel_error(message));
            None
        }
        M5StorageSelfTestMode::ObjectChurn => {
            validate_object_churn(report).unwrap_or_else(|message| fatal_kernel_error(message));
            None
        }
        M5StorageSelfTestMode::CrashArmEarly
        | M5StorageSelfTestMode::CrashArmLate
        | M5StorageSelfTestMode::CrashTornSuperblock
        | M5StorageSelfTestMode::CrashTornPayload => {
            fatal_kernel_error("deterministic crash point did not interrupt commit")
        }
        M5StorageSelfTestMode::CrashRecovery => {
            validate_crash_recovery(report).unwrap_or_else(|message| fatal_kernel_error(message));
            None
        }
    };

    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("service lifecycle allocator was unavailable"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    // Publish the intentional exit first: this clears the live record so the
    // same service can be relaunched below while this process is still the
    // current thread. The teardown below revokes its block authority before
    // the relaunched instance runs.
    controller
        .notify_exited_live_process(pid)
        .unwrap_or_else(|error| match error {
            LifecycleControlError::ServiceNotLive => {
                fatal_kernel_error("storage service exit publication lost the live instance")
            }
            _ => fatal_kernel_error("storage service exit publication failed"),
        });

    let next_pid = next_state.map(|next_state| {
        set_self_test_state(Some(next_state));
        launch_phase(next_state, controller, allocator)
    });

    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    match (next_pid, teardown.next_stack_pointer) {
        (None, None) => {
            if matches!(state.mode, M5StorageSelfTestMode::Integration) {
                kernel_log_line(M5_STORAGE_PASS_MARKER);
            }
            set_self_test_state(None);
            unsafe {
                *M5_CRASH_PLAN.get() = None;
            }
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        (None, Some(_)) => fatal_kernel_error(
            "storage self-test teardown found a runnable thread after the final phase",
        ),
        (Some(_), None) => fatal_kernel_error(
            "storage self-test teardown did not select the launched next-phase thread",
        ),
        (Some(_), Some(next_stack_pointer)) => next_stack_pointer,
    }
}

fn handle_integration_phase(
    state: M5StorageSelfTestState,
    pid: u64,
    report: &StorageServiceBootstrap,
) -> Option<M5StorageSelfTestState> {
    match state.phase {
        IntegrationPhase::InitialAuthorized => {
            if current_service(&state) != STORAGE_SERVICE_ID {
                fatal_kernel_error("expected authorized storage service phase")
            }
            validate_integration_initial(report)
                .unwrap_or_else(|message| fatal_kernel_error(message));
            Some(M5StorageSelfTestState {
                phase: IntegrationPhase::UnauthorizedProbe,
                previous_handle: report.capability_handle,
                ..state
            })
        }
        IntegrationPhase::UnauthorizedProbe => {
            if current_service(&state) != STORAGE_UNAUTHORIZED_SERVICE_ID {
                fatal_kernel_error("expected unauthorized probe phase")
            }
            validate_unauthorized_probe(report)
                .unwrap_or_else(|message| fatal_kernel_error(message));
            kernel_log_fmt(format_args!(
                "{M5_STORAGE_UNAUTHORIZED_DENIED_MARKER}{pid}\n"
            ));
            Some(M5StorageSelfTestState {
                phase: IntegrationPhase::RestartAuthorized,
                ..state
            })
        }
        IntegrationPhase::RestartAuthorized => {
            validate_integration_restart(pid, report)
                .unwrap_or_else(|message| fatal_kernel_error(message));
            None
        }
    }
}

/// Called after the device completed `operation` for the storage service, still inside
/// its block syscall, so the service's address space (and its report page) is current.
/// `payload` holds the bytes the device returned for a read.
pub(crate) fn observe_userspace_block_operation(request: &BlockTransportRequest, payload: &[u8]) {
    let lba = request.lba;
    match request.operation {
        BlockTransportOp::Write => {
            let plan = unsafe { &mut *M5_CRASH_PLAN.get() };
            let Some(crash_plan) = plan.as_mut() else {
                return;
            };
            crash_plan.writes_seen = crash_plan.writes_seen.saturating_add(1);
            if let M5Tear::PayloadPrefix {
                torn_lba: Some(torn_lba),
            } = crash_plan.tear
            {
                if crash_plan.writes_seen == PAYLOAD_TEAR_WRITE {
                    kernel_log_fmt(format_args!(
                        "[CRSH] torn payload write={PAYLOAD_TEAR_WRITE} lba={torn_lba} blocks-written={} of={PAYLOAD_TEAR_BLOCKS}\n",
                        request.blocks
                    ));
                }
            }
            if crash_plan.writes_seen == crash_plan.after_write {
                let after_write = crash_plan.writes_seen;
                let tear = crash_plan.tear;
                *plan = None;
                log_pre_crash_report();
                if tear == M5Tear::SuperblockSuffix {
                    kernel_log_fmt(format_args!(
                        "[CRSH] torn superblock write={after_write} lba={lba} new-bytes={SUPERBLOCK_TEAR_OFFSET} stale-bytes={}\n",
                        SUPERBLOCK_BYTES - SUPERBLOCK_TEAR_OFFSET
                    ));
                }
                kernel_log_fmt(format_args!(
                    "[CRSH] inject after-write={after_write} lba={lba}\n"
                ));
                halt_loop();
            }
        }
        BlockTransportOp::Read => {
            let plan = unsafe { &*M5_CRASH_PLAN.get() };
            let tears_superblock =
                matches!(plan, Some(plan) if plan.tear == M5Tear::SuperblockSuffix);
            if tears_superblock && lba == SUPERBLOCK_SLOT_ONE_LBA && request.blocks == 1 {
                let bytes: [u8; SUPERBLOCK_BYTES] = payload.try_into().unwrap_or_else(|_| {
                    fatal_kernel_error("superblock read was not one 512-byte block")
                });
                unsafe {
                    *M5_STALE_SUPERBLOCK_SLOT.get() = Some(bytes);
                }
            }
        }
        BlockTransportOp::Flush => kernel_log_line("[BLK ] flush complete"),
        BlockTransportOp::Geometry => {}
    }
}

/// Called before a storage-service block request reaches the device. For the write the
/// armed plan tears, returns the request and payload the device is given instead. A
/// syscall resumed while its request is in flight gets the same answer again, so the
/// bridge recognises its own request.
#[cfg(feature = "m5-crash-late-self-test")]
pub(crate) fn tear_userspace_block_write(
    request: BlockTransportRequest,
    payload: &mut [u8],
) -> (BlockTransportRequest, &mut [u8]) {
    if request.operation != BlockTransportOp::Write {
        return (request, payload);
    }
    let plan = unsafe { &mut *M5_CRASH_PLAN.get() };
    let Some(crash_plan) = plan.as_mut() else {
        return (request, payload);
    };
    let write_index = crash_plan.writes_seen.saturating_add(1);
    match &mut crash_plan.tear {
        M5Tear::None => (request, payload),
        M5Tear::SuperblockSuffix => {
            if write_index != crash_plan.after_write {
                return (request, payload);
            }
            if request.lba != SUPERBLOCK_SLOT_ONE_LBA
                || request.blocks != 1
                || payload.len() != SUPERBLOCK_BYTES
            {
                fatal_kernel_error("torn-superblock write was not slot 1's single block");
            }
            let stale = unsafe { *M5_STALE_SUPERBLOCK_SLOT.get() }.unwrap_or_else(|| {
                fatal_kernel_error("superblock slot 1 was not read before the torn write")
            });
            payload[SUPERBLOCK_TEAR_OFFSET..].copy_from_slice(&stale[SUPERBLOCK_TEAR_OFFSET..]);
            (request, payload)
        }
        M5Tear::PayloadPrefix { torn_lba } => {
            if write_index != PAYLOAD_TEAR_WRITE {
                return (request, payload);
            }
            if request.blocks != PAYLOAD_TEAR_BLOCKS {
                fatal_kernel_error("torn-payload write was not alpha's two-block payload");
            }
            let block_bytes = payload.len() / PAYLOAD_TEAR_BLOCKS as usize;
            *torn_lba = Some(request.lba);
            let torn = BlockTransportRequest {
                blocks: 1,
                buffer_len: block_bytes as u32,
                ..request
            };
            (torn, &mut payload[..block_bytes])
        }
    }
}

fn arm_crash_after_write(after_write: u64, tear: M5Tear) {
    unsafe {
        *M5_CRASH_PLAN.get() = Some(M5CrashPlan {
            after_write,
            writes_seen: 0,
            tear,
        });
    }
    let tear_name = match tear {
        M5Tear::None => "none",
        M5Tear::SuperblockSuffix => "superblock-suffix",
        M5Tear::PayloadPrefix { .. } => "payload-prefix",
    };
    kernel_log_fmt(format_args!(
        "[CRSH] armed trigger=after-write={after_write} tear={tear_name}\n"
    ));
}

/// What the crash-arm service reported before the injected stop: the generation it
/// mounted, the objects it read back, and the write it was committing.
fn log_pre_crash_report() {
    let report = &storage_service_report();
    kernel_log_fmt(format_args!(
        "[STOR] recovered generation={}\n",
        report.mounted_generation
    ));
    log_reported_reads(report, &PERSISTENCE_ALPHA_V2, OBJECT_BETA_V1);
    kernel_log_fmt(format_args!(
        "[STOR] write object={} id={} bytes={} checksum={:08x}\n",
        object_name(report.pending_object_id),
        report.pending_object_id,
        report.pending_len,
        report.pending_checksum
    ));
}

fn object_name(id: u64) -> &'static str {
    match id {
        OBJECT_ALPHA_ID => OBJECT_ALPHA_NAME,
        OBJECT_BETA_ID => OBJECT_BETA_NAME,
        _ => "none",
    }
}

fn validate_integration_initial(report: &StorageServiceBootstrap) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_INTEGRATION_INITIAL,
        STORAGE_SERVICE_RESULT_OK,
    )?;
    if report.formatted != 1
        || report.mounted_generation != 0
        || report.committed_generation != 1
        || report.capability_handle == 0
    {
        return Err("integration initial report contained unexpected generation state");
    }
    ensure_object(report.alpha_len, report.alpha_checksum, OBJECT_ALPHA_V1)?;
    ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
    kernel_log_fmt(format_args!(
        "[STOR] format generation={}\n",
        report.mounted_generation
    ));
    kernel_log_fmt(format_args!(
        "[STOR] write object={OBJECT_ALPHA_ID} bytes={}\n",
        report.alpha_len
    ));
    kernel_log_fmt(format_args!(
        "[STOR] write object={OBJECT_BETA_ID} bytes={}\n",
        report.beta_len
    ));
    kernel_log_fmt(format_args!(
        "[STOR] commit generation={}\n",
        report.committed_generation
    ));
    Ok(())
}

fn validate_unauthorized_probe(report: &StorageServiceBootstrap) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE,
        STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED,
    )
}

fn validate_integration_restart(
    pid: u64,
    report: &StorageServiceBootstrap,
) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_INTEGRATION_RESTART,
        STORAGE_SERVICE_RESULT_OK,
    )?;
    if report.aux_status != SYSCALL_ESTALE {
        return Err("restarted storage service did not observe ESTALE on the stale handle");
    }
    if report.mounted_generation != 1
        || report.committed_generation != 2
        || report.remounted_generation != 2
    {
        return Err("restarted storage service reported unexpected generations");
    }
    ensure_object(
        report.mounted_alpha_len,
        report.mounted_alpha_checksum,
        OBJECT_ALPHA_V1,
    )?;
    ensure_object(
        report.mounted_beta_len,
        report.mounted_beta_checksum,
        OBJECT_BETA_V1,
    )?;
    ensure_object(report.alpha_len, report.alpha_checksum, OBJECT_ALPHA_V2)?;
    ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
    if report.malformed_mount_error == 0 {
        return Err("restarted storage service did not report the malformed-media mount error");
    }
    kernel_log_fmt(format_args!("[BLK ] stale handle denied pid={pid}\n"));
    kernel_log_fmt(format_args!(
        "[STOR] mounted generation={}\n",
        report.mounted_generation
    ));
    kernel_log_fmt(format_args!(
        "[STOR] write object={OBJECT_ALPHA_ID} bytes={}\n",
        report.alpha_len
    ));
    kernel_log_fmt(format_args!(
        "[STOR] commit generation={}\n",
        report.committed_generation
    ));
    kernel_log_fmt(format_args!(
        "[STOR] malformed media rejected error={}\n",
        report.malformed_mount_error
    ));
    Ok(())
}

fn validate_persistence(report: &StorageServiceBootstrap) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_PERSISTENCE,
        STORAGE_SERVICE_RESULT_OK,
    )?;
    match (
        report.mounted_generation,
        report.committed_generation,
        report.remounted_generation,
    ) {
        (0, 1, 0) if report.formatted == 1 => {
            ensure_object(
                report.alpha_len,
                report.alpha_checksum,
                &PERSISTENCE_ALPHA_V1,
            )?;
            ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
            kernel_log_fmt(format_args!(
                "[STOR] mounted generation=fresh formatted={}\n",
                report.formatted
            ));
            log_write_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                report.alpha_len,
                report.alpha_checksum,
            );
            log_write_marker(
                OBJECT_BETA_NAME,
                OBJECT_BETA_ID,
                report.beta_len,
                report.beta_checksum,
            );
            kernel_log_fmt(format_args!(
                "[STOR] commit generation={}\n",
                report.committed_generation
            ));
            kernel_log_line("[TEST] persistence phase=write PASS");
            Ok(())
        }
        (1, 2, 2) => {
            ensure_object(
                report.mounted_alpha_len,
                report.mounted_alpha_checksum,
                &PERSISTENCE_ALPHA_V1,
            )?;
            ensure_object(
                report.mounted_beta_len,
                report.mounted_beta_checksum,
                OBJECT_BETA_V1,
            )?;
            ensure_object(
                report.alpha_len,
                report.alpha_checksum,
                &PERSISTENCE_ALPHA_V2,
            )?;
            ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
            kernel_log_fmt(format_args!(
                "[STOR] recovered generation={}\n",
                report.mounted_generation
            ));
            log_object_reads(
                (report.mounted_alpha_len, report.mounted_alpha_checksum),
                (report.mounted_beta_len, report.mounted_beta_checksum),
                &PERSISTENCE_ALPHA_V1,
                OBJECT_BETA_V1,
            );
            log_write_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                report.alpha_len,
                report.alpha_checksum,
            );
            kernel_log_fmt(format_args!(
                "[STOR] commit generation={}\n",
                report.committed_generation
            ));
            kernel_log_fmt(format_args!(
                "[STOR] recovered generation={}\n",
                report.remounted_generation
            ));
            log_reported_reads(report, &PERSISTENCE_ALPHA_V2, OBJECT_BETA_V1);
            kernel_log_line("[TEST] persistence phase=read PASS");
            Ok(())
        }
        _ => Err("persistence service reported an unexpected generation sequence"),
    }
}

fn validate_crash_recovery(report: &StorageServiceBootstrap) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_CRASH_RECOVERY,
        STORAGE_SERVICE_RESULT_OK,
    )?;
    kernel_log_fmt(format_args!(
        "[STOR] recovered generation={}\n",
        report.mounted_generation
    ));
    let (expected_alpha, outcome): (&[u8], &str) = match report.mounted_generation {
        2 => (&PERSISTENCE_ALPHA_V2, "previous-commit"),
        3 => (&PERSISTENCE_ALPHA_V3, "new-commit"),
        _ => return Err("unexpected recovered generation after crash"),
    };
    ensure_object(report.alpha_len, report.alpha_checksum, expected_alpha)?;
    ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
    log_reported_reads(report, expected_alpha, OBJECT_BETA_V1);
    kernel_log_fmt(format_args!("[CRSH] recovery outcome={outcome}\n"));
    kernel_log_line("[TEST] crash recovery PASS");
    Ok(())
}

/// Checks one boot of the object-churn script against `object_churn`'s expected contents.
fn validate_object_churn(report: &StorageServiceBootstrap) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_OBJECT_CHURN,
        STORAGE_SERVICE_RESULT_OK,
    )?;
    let live = churn_live_count();
    let fingerprint = churn_expected_fingerprint();
    if report.pending_len < 128 {
        return Err("object churn: the store's object limit is below 128");
    }
    if report.beta_len != churn_absent_count() {
        return Err("object churn: a deleted object is still present");
    }
    if report.beta_checksum != 1 {
        return Err("object churn: a re-created object did not get a newer epoch");
    }
    match (
        report.formatted,
        report.mounted_generation,
        report.committed_generation,
        report.remounted_generation,
    ) {
        (1, 0, 3, 3) => {
            if (report.alpha_len, report.alpha_checksum) != (live, fingerprint) {
                return Err("object churn: the remounted objects are not what the script wrote");
            }
            kernel_log_fmt(format_args!(
                "[STOR] churn created={CHURN_CREATED} deleted={CHURN_DELETED} \
                 recreated={CHURN_RECREATED} added={CHURN_ADDED} generation={} live={} \
                 limit={} fingerprint={:016x}\n",
                report.remounted_generation,
                report.alpha_len,
                report.pending_len,
                report.alpha_checksum,
            ));
            kernel_log_fmt(format_args!(
                "[STOR] churn absent={} recreated-epochs=newer\n",
                report.beta_len
            ));
            kernel_log_line("[TEST] object churn phase=write PASS");
            Ok(())
        }
        (0, 3, 4, 4) => {
            if (report.mounted_alpha_len, report.mounted_alpha_checksum) != (live, fingerprint) {
                return Err("object churn: the mounted objects are not what the first boot wrote");
            }
            if (report.alpha_len, report.alpha_checksum) != (0, CHURN_FINGERPRINT_SEED) {
                return Err("object churn: objects survived deleting every object");
            }
            kernel_log_fmt(format_args!(
                "[STOR] churn recovered generation={} live={} fingerprint={:016x}\n",
                report.mounted_generation, report.mounted_alpha_len, report.mounted_alpha_checksum,
            ));
            kernel_log_fmt(format_args!(
                "[STOR] churn absent={} recreated-epochs=newer\n",
                report.beta_len
            ));
            kernel_log_fmt(format_args!(
                "[STOR] churn deleted all generation={} live={}\n",
                report.remounted_generation, report.alpha_len
            ));
            kernel_log_line("[TEST] object churn phase=read PASS");
            Ok(())
        }
        _ => Err("object churn service reported an unexpected generation sequence"),
    }
}

fn ensure_result(
    report: &StorageServiceBootstrap,
    expected_mode: u64,
    expected_result: u64,
) -> Result<(), &'static str> {
    if report.mode != expected_mode {
        return Err("storage service reported an unexpected mode");
    }
    if report.result_code != expected_result {
        return Err("storage service reported failure");
    }
    Ok(())
}

fn ensure_object(
    actual_len: u64,
    actual_checksum: u64,
    expected: &[u8],
) -> Result<(), &'static str> {
    if actual_len != expected.len() as u64 || actual_checksum != checksum(expected) as u64 {
        return Err("storage service object evidence did not match the expected bytes");
    }
    Ok(())
}

fn log_write_marker(name: &str, id: u64, bytes: u64, checksum: u64) {
    kernel_log_fmt(format_args!(
        "[STOR] write object={name} id={id} bytes={bytes} checksum={checksum:08x}\n"
    ));
}

/// Read lines carrying the object lengths and checksums the service put in its report,
/// with `match` comparing them against the bytes that generation should hold.
fn log_reported_reads(report: &StorageServiceBootstrap, alpha: &[u8], beta: &[u8]) {
    log_object_reads(
        (report.alpha_len, report.alpha_checksum),
        (report.beta_len, report.beta_checksum),
        alpha,
        beta,
    );
}

/// `alpha` and `beta` are reported `(length, checksum)` pairs.
fn log_object_reads(
    alpha: (u64, u64),
    beta: (u64, u64),
    expected_alpha: &[u8],
    expected_beta: &[u8],
) {
    for (name, id, (len, checksum), expected) in [
        (OBJECT_ALPHA_NAME, OBJECT_ALPHA_ID, alpha, expected_alpha),
        (OBJECT_BETA_NAME, OBJECT_BETA_ID, beta, expected_beta),
    ] {
        let matched = if ensure_object(len, checksum, expected).is_ok() {
            "yes"
        } else {
            "no"
        };
        kernel_log_fmt(format_args!(
            "[STOR] read object={name} id={id} bytes={len} checksum={checksum:08x} match={matched}\n"
        ));
    }
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}
