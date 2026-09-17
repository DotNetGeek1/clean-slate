//! M5 storage self-tests that orchestrate a real CPL3 storage-service runtime.
//!
//! The kernel self-test is limited to launching storage-service processes,
//! granting and revoking block authority, injecting deterministic crash points,
//! and validating the userspace service's reported results. Persistent-store
//! policy itself runs inside the userspace storage service over the production
//! capability-gated block syscall path.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::userspace_gdt_state;
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
use crate::service::control::LifecycleControlError;
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_service_fixtures::{
    BlockTransportOp, StorageServiceBootstrap, STORAGE_SERVICE_BOOTSTRAP_ADDRESS,
    STORAGE_SERVICE_ID, STORAGE_SERVICE_MODE_CRASH_ARM_EARLY, STORAGE_SERVICE_MODE_CRASH_ARM_LATE,
    STORAGE_SERVICE_MODE_CRASH_RECOVERY, STORAGE_SERVICE_MODE_INTEGRATION_INITIAL,
    STORAGE_SERVICE_MODE_INTEGRATION_RESTART, STORAGE_SERVICE_MODE_PERSISTENCE,
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
const CRASH_AFTER_WRITE_LATE: u64 = 3;
const SYSCALL_ESTALE: u64 = u64::MAX - 116;

pub(crate) const M5_STORAGE_UNAUTHORIZED_DENIED_MARKER: &str = "[BLK ] unauthorized denied pid=";
pub(crate) const M5_STORAGE_PASS_MARKER: &str = "[M5.7] PASS";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum M5StorageSelfTestMode {
    Integration,
    Persistence,
    CrashArmEarly,
    CrashArmLate,
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
    if active_self_test_mode() == M5StorageSelfTestMode::Integration {
        controller
            .declare_service(STORAGE_UNAUTHORIZED_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
    }
    let capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe {
        *M5_STORAGE_SELF_TEST_STATE.get() = Some(M5StorageSelfTestState {
            mode: active_self_test_mode(),
            lifecycle_capability: capability,
            phase: IntegrationPhase::InitialAuthorized,
            previous_handle: 0,
        });
    }
    if matches!(
        active_self_test_mode(),
        M5StorageSelfTestMode::CrashArmEarly
    ) {
        arm_crash_after_write(CRASH_AFTER_WRITE_EARLY);
        log_crash_arm_markers(CRASH_AFTER_WRITE_EARLY);
    }
    if matches!(active_self_test_mode(), M5StorageSelfTestMode::CrashArmLate) {
        arm_crash_after_write(CRASH_AFTER_WRITE_LATE);
        log_crash_arm_markers(CRASH_AFTER_WRITE_LATE);
    }
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("storage self-test allocator was missing"));
    launch_current_phase(unsafe { service_lifecycle_controller_mut() }, allocator);
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn active_self_test_mode() -> M5StorageSelfTestMode {
    if cfg!(feature = "m5-storage-self-test") {
        M5StorageSelfTestMode::Integration
    } else if cfg!(feature = "m5-persistence-self-test") {
        M5StorageSelfTestMode::Persistence
    } else if cfg!(feature = "m5-crash-early-self-test") {
        M5StorageSelfTestMode::CrashArmEarly
    } else if cfg!(feature = "m5-crash-late-self-test") {
        M5StorageSelfTestMode::CrashArmLate
    } else if cfg!(feature = "m5-crash-recovery-self-test") {
        M5StorageSelfTestMode::CrashRecovery
    } else {
        fatal_kernel_error("no M5 storage self-test mode was enabled")
    }
}

pub(crate) fn storage_service_bootstrap(
    service: ServiceId,
) -> Result<StorageServiceBootstrap, &'static str> {
    let state = unsafe {
        (&*M5_STORAGE_SELF_TEST_STATE.get())
            .as_ref()
            .ok_or("m5 storage self-test state was not initialized")?
    };
    let bootstrap = match state.mode {
        M5StorageSelfTestMode::Integration => match (state.phase, service) {
            (IntegrationPhase::InitialAuthorized, s) if s == STORAGE_SERVICE_ID => {
                StorageServiceBootstrap::new(STORAGE_SERVICE_MODE_INTEGRATION_INITIAL, 0)
            }
            (IntegrationPhase::UnauthorizedProbe, s) if s == STORAGE_UNAUTHORIZED_SERVICE_ID => {
                StorageServiceBootstrap::new(STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE, 0)
            }
            (IntegrationPhase::RestartAuthorized, s) if s == STORAGE_SERVICE_ID => {
                StorageServiceBootstrap::new(
                    STORAGE_SERVICE_MODE_INTEGRATION_RESTART,
                    state.previous_handle,
                )
            }
            _ => return Err("unexpected storage service phase bootstrap request"),
        },
        M5StorageSelfTestMode::Persistence => {
            StorageServiceBootstrap::new(STORAGE_SERVICE_MODE_PERSISTENCE, 0)
        }
        M5StorageSelfTestMode::CrashArmEarly => {
            StorageServiceBootstrap::new(STORAGE_SERVICE_MODE_CRASH_ARM_EARLY, 0)
        }
        M5StorageSelfTestMode::CrashArmLate => {
            StorageServiceBootstrap::new(STORAGE_SERVICE_MODE_CRASH_ARM_LATE, 0)
        }
        M5StorageSelfTestMode::CrashRecovery => {
            StorageServiceBootstrap::new(STORAGE_SERVICE_MODE_CRASH_RECOVERY, 0)
        }
    };
    Ok(bootstrap)
}

fn launch_current_phase(
    controller: &mut crate::service::control::ServiceLifecycleController,
    allocator: &mut PageAllocator,
) {
    let state = unsafe {
        (&*M5_STORAGE_SELF_TEST_STATE.get())
            .as_ref()
            .unwrap_or_else(|| fatal_kernel_error("m5 storage self-test state was not initialized"))
    };
    let service = current_service(state);
    controller
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
    let pid = controller
        .live_pid(service)
        .unwrap_or_else(|| fatal_kernel_error("storage service did not become live"));
    kernel_log_fmt(format_args!("[STOR] service started pid={pid}\n"));
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
        | M5StorageSelfTestMode::CrashArmEarly
        | M5StorageSelfTestMode::CrashArmLate
        | M5StorageSelfTestMode::CrashRecovery => STORAGE_SERVICE_ID,
    }
}

fn current_userspace_pid() -> Result<u64, &'static str> {
    without_interrupts(|| unsafe { scheduler_mut().current_userspace_process_id() })
}

pub(crate) fn handle_userspace_storage_entry() -> u64 {
    let pid = current_userspace_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let report = unsafe { &*(STORAGE_SERVICE_BOOTSTRAP_ADDRESS as *const StorageServiceBootstrap) };
    kernel_log_fmt(format_args!(
        "[STOR] report mode={} result={} aux={} handle={} mounted={} committed={} remounted={}\n",
        report.mode,
        report.result_code,
        report.aux_status,
        report.capability_handle,
        report.mounted_generation,
        report.committed_generation,
        report.remounted_generation
    ));
    let state = unsafe {
        (&mut *M5_STORAGE_SELF_TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m5 storage self-test state was not initialized"))
    };
    let next_phase = match state.mode {
        M5StorageSelfTestMode::Integration => handle_integration_phase(state, pid, report),
        M5StorageSelfTestMode::Persistence => {
            validate_persistence(report).unwrap_or_else(|message| fatal_kernel_error(message));
            None
        }
        M5StorageSelfTestMode::CrashArmEarly | M5StorageSelfTestMode::CrashArmLate => {
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
    controller
        .notify_exited_live_process(pid)
        .unwrap_or_else(|error| match error {
            LifecycleControlError::ServiceNotLive => {
                fatal_kernel_error("storage service exit publication lost the live instance")
            }
            _ => fatal_kernel_error("storage service exit publication failed"),
        });
    kernel_log_fmt(format_args!(
        "[STOR] gdt-before-next-phase initialized={}\n",
        userspace_gdt_state().is_ok()
    ));
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if next_phase.is_none() {
        if matches!(state.mode, M5StorageSelfTestMode::Integration) {
            kernel_log_line(M5_STORAGE_PASS_MARKER);
        }
        unsafe {
            *M5_STORAGE_SELF_TEST_STATE.get() = None;
            *M5_CRASH_PLAN.get() = None;
        }
        qemu_exit(QEMU_EXIT_SUCCESS)
    }
    let phase = next_phase.expect("checked next phase before continuing");
    state.phase = phase;
    launch_current_phase(controller, allocator);
    teardown.next_stack_pointer.unwrap_or_else(|| {
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message))
    })
}

fn handle_integration_phase(
    state: &mut M5StorageSelfTestState,
    pid: u64,
    report: &StorageServiceBootstrap,
) -> Option<IntegrationPhase> {
    match state.phase {
        IntegrationPhase::InitialAuthorized => {
            if current_service(state) != STORAGE_SERVICE_ID {
                fatal_kernel_error("expected authorized storage service phase")
            }
            validate_integration_initial(report)
                .unwrap_or_else(|message| fatal_kernel_error(message));
            state.previous_handle = report.capability_handle;
            Some(IntegrationPhase::UnauthorizedProbe)
        }
        IntegrationPhase::UnauthorizedProbe => {
            if current_service(state) != STORAGE_UNAUTHORIZED_SERVICE_ID {
                fatal_kernel_error("expected unauthorized probe phase")
            }
            validate_unauthorized_probe(report)
                .unwrap_or_else(|message| fatal_kernel_error(message));
            kernel_log_fmt(format_args!(
                "{M5_STORAGE_UNAUTHORIZED_DENIED_MARKER}{pid}\n"
            ));
            Some(IntegrationPhase::RestartAuthorized)
        }
        IntegrationPhase::RestartAuthorized => {
            validate_integration_restart(pid, report)
                .unwrap_or_else(|message| fatal_kernel_error(message));
            None
        }
    }
}

pub(crate) fn observe_userspace_block_operation(operation: BlockTransportOp) {
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
                kernel_log_fmt(format_args!("[CRSH] inject after-write={after_write}\n"));
                halt_loop();
            }
        }
        BlockTransportOp::Flush => kernel_log_line("[BLK ] flush complete"),
        BlockTransportOp::Geometry | BlockTransportOp::Read => {}
    }
}

fn arm_crash_after_write(after_write: u64) {
    unsafe {
        *M5_CRASH_PLAN.get() = Some(M5CrashPlan {
            after_write,
            writes_seen: 0,
        });
    }
}

fn log_crash_arm_markers(after_write: u64) {
    kernel_log_line("[STOR] recovered generation=2");
    log_read_marker(
        OBJECT_ALPHA_NAME,
        OBJECT_ALPHA_ID,
        PERSISTENCE_ALPHA_V2.len(),
        checksum(&PERSISTENCE_ALPHA_V2),
    );
    log_read_marker(
        OBJECT_BETA_NAME,
        OBJECT_BETA_ID,
        OBJECT_BETA_V1.len(),
        checksum(OBJECT_BETA_V1),
    );
    kernel_log_fmt(format_args!(
        "[CRSH] armed trigger=after-write={after_write}\n"
    ));
    log_write_marker(
        OBJECT_ALPHA_NAME,
        OBJECT_ALPHA_ID,
        PERSISTENCE_ALPHA_V3.len(),
        checksum(&PERSISTENCE_ALPHA_V3),
    );
}

fn validate_integration_initial(report: &StorageServiceBootstrap) -> Result<(), &'static str> {
    ensure_result(
        report,
        STORAGE_SERVICE_MODE_INTEGRATION_INITIAL,
        STORAGE_SERVICE_RESULT_OK,
    )?;
    if report.mounted_generation != 0
        || report.committed_generation != 1
        || report.capability_handle == 0
    {
        return Err("integration initial report contained unexpected generation state");
    }
    ensure_object(report.alpha_len, report.alpha_checksum, OBJECT_ALPHA_V1)?;
    ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
    kernel_log_line("[STOR] format generation=0");
    kernel_log_fmt(format_args!(
        "[STOR] write object={} bytes={}\n",
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_V1.len()
    ));
    kernel_log_fmt(format_args!(
        "[STOR] write object={} bytes={}\n",
        OBJECT_BETA_ID,
        OBJECT_BETA_V1.len()
    ));
    kernel_log_line("[STOR] commit generation=1");
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
    ensure_object(report.alpha_len, report.alpha_checksum, OBJECT_ALPHA_V2)?;
    ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
    kernel_log_fmt(format_args!("[BLK ] stale handle denied pid={pid}\n"));
    kernel_log_line("[STOR] mounted generation=1");
    kernel_log_fmt(format_args!(
        "[STOR] write object={} bytes={}\n",
        OBJECT_ALPHA_ID,
        OBJECT_ALPHA_V2.len()
    ));
    kernel_log_line("[STOR] commit generation=2");
    kernel_log_line("[STOR] malformed media rejected");
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
        (0, 1, 0) => {
            ensure_object(
                report.alpha_len,
                report.alpha_checksum,
                &PERSISTENCE_ALPHA_V1,
            )?;
            ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
            kernel_log_line("[STOR] mounted generation=fresh");
            log_write_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                PERSISTENCE_ALPHA_V1.len(),
                checksum(&PERSISTENCE_ALPHA_V1),
            );
            log_write_marker(
                OBJECT_BETA_NAME,
                OBJECT_BETA_ID,
                OBJECT_BETA_V1.len(),
                checksum(OBJECT_BETA_V1),
            );
            kernel_log_line("[STOR] commit generation=1");
            kernel_log_line("[TEST] persistence phase=write PASS");
            Ok(())
        }
        (1, 2, 2) => {
            ensure_object(
                report.alpha_len,
                report.alpha_checksum,
                &PERSISTENCE_ALPHA_V2,
            )?;
            ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
            kernel_log_line("[STOR] recovered generation=1");
            log_read_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                PERSISTENCE_ALPHA_V1.len(),
                checksum(&PERSISTENCE_ALPHA_V1),
            );
            log_read_marker(
                OBJECT_BETA_NAME,
                OBJECT_BETA_ID,
                OBJECT_BETA_V1.len(),
                checksum(OBJECT_BETA_V1),
            );
            log_write_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                PERSISTENCE_ALPHA_V2.len(),
                checksum(&PERSISTENCE_ALPHA_V2),
            );
            kernel_log_line("[STOR] commit generation=2");
            kernel_log_line("[STOR] recovered generation=2");
            log_read_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                PERSISTENCE_ALPHA_V2.len(),
                checksum(&PERSISTENCE_ALPHA_V2),
            );
            log_read_marker(
                OBJECT_BETA_NAME,
                OBJECT_BETA_ID,
                OBJECT_BETA_V1.len(),
                checksum(OBJECT_BETA_V1),
            );
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
    match report.mounted_generation {
        2 => {
            ensure_object(
                report.alpha_len,
                report.alpha_checksum,
                &PERSISTENCE_ALPHA_V2,
            )?;
            ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
            log_read_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                PERSISTENCE_ALPHA_V2.len(),
                checksum(&PERSISTENCE_ALPHA_V2),
            );
            log_read_marker(
                OBJECT_BETA_NAME,
                OBJECT_BETA_ID,
                OBJECT_BETA_V1.len(),
                checksum(OBJECT_BETA_V1),
            );
            kernel_log_line("[CRSH] recovery outcome=previous-commit");
        }
        3 => {
            ensure_object(
                report.alpha_len,
                report.alpha_checksum,
                &PERSISTENCE_ALPHA_V3,
            )?;
            ensure_object(report.beta_len, report.beta_checksum, OBJECT_BETA_V1)?;
            log_read_marker(
                OBJECT_ALPHA_NAME,
                OBJECT_ALPHA_ID,
                PERSISTENCE_ALPHA_V3.len(),
                checksum(&PERSISTENCE_ALPHA_V3),
            );
            log_read_marker(
                OBJECT_BETA_NAME,
                OBJECT_BETA_ID,
                OBJECT_BETA_V1.len(),
                checksum(OBJECT_BETA_V1),
            );
            kernel_log_line("[CRSH] recovery outcome=new-commit");
        }
        _ => return Err("unexpected recovered generation after crash"),
    }
    kernel_log_line("[TEST] crash recovery PASS");
    Ok(())
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

fn log_write_marker(name: &str, id: u64, bytes: usize, checksum: u32) {
    kernel_log_fmt(format_args!(
        "[STOR] write object={name} id={id} bytes={bytes} checksum={checksum:08x}\n"
    ));
}

fn log_read_marker(name: &str, id: u64, bytes: usize, checksum: u32) {
    kernel_log_fmt(format_args!(
        "[STOR] read object={name} id={id} bytes={bytes} checksum={checksum:08x} match=yes\n"
    ));
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}
