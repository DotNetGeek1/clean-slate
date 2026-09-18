//! M7.7 network capability broker QEMU constituent.

use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::capability_space_mut;
use crate::capability::network::{
    authorize_network_op, clear_network_sessions_for_test, grant_network_authority, on_holder_exit,
    on_revoked, register_network_session, set_network_audit_serial_echo, NetworkGrantPolicy,
    NetworkOp, NETWORK_SERVICE_ID,
};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::domain::teardown_process_by_id;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::selftest::m6_fixture::{fixture_service, spawn_fixture};
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::{delegate, HolderId, Rights};
use clean_slate_network::error::DenialReason;
use clean_slate_network::session::{SessionGeneration, SessionId};
use clean_slate_service_fixtures::m6_fixture::{M6FixtureBootstrap, M6FixtureStep};

const PASS_MARKER: &str = "[M7.7] PASS";
const FIXTURE_HOLDER: u64 = 0;
const FIXTURE_UNRELATED: u64 = 1;
const PREDICTED_HOLDER_PID: u64 = 1;
const PREDICTED_UNRELATED_PID: u64 = 2;

fn build_spin_fixture() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(0)).unwrap();
    program
}

fn bump_network_service_generation() {
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller
        .test_advance_authoritative_generation(NETWORK_SERVICE_ID)
        .unwrap_or_else(|_| fatal_kernel_error("network service generation bump failed"));
}

pub(crate) fn start_m7_net_caps_self_test(allocator: PageAllocator) -> ! {
    set_network_audit_serial_echo(true);
    clear_network_sessions_for_test();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .expect("m7.7 allocator missing");
    {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root, 0);
        controller
            .declare_service(NETWORK_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
    }

    let stacks = unsafe { task_stacks_mut() };
    let holder_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[0]),
        0,
        fixture_service(FIXTURE_HOLDER),
        &build_spin_fixture(),
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let unrelated_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[1]),
        1,
        fixture_service(FIXTURE_UNRELATED),
        &build_spin_fixture(),
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    if holder_spawned.pid != PREDICTED_HOLDER_PID
        || unrelated_spawned.pid != PREDICTED_UNRELATED_PID
    {
        fatal_kernel_error("m7.7 fixture pid allocation mismatch");
    }

    let holder = HolderId(holder_spawned.pid);
    let unrelated = HolderId(unrelated_spawned.pid);

    let app_rights = Rights::NET_RESOLVE
        .union(Rights::NET_CONNECT)
        .union(Rights::NET_SEND)
        .union(Rights::NET_RECEIVE)
        .union(Rights::DELEGATE);
    let handle = grant_network_authority(holder, app_rights, NetworkGrantPolicy::Application, None)
        .unwrap_or_else(|_| fatal_kernel_error("network grant failed"));
    if grant_network_authority(
        unrelated,
        Rights::NET_RAW_DEVICE,
        NetworkGrantPolicy::Application,
        None,
    )
    .is_ok()
    {
        fatal_kernel_error("application raw-device grant should fail");
    }
    let raw_handle = grant_network_authority(
        holder,
        Rights::NET_RAW_DEVICE,
        NetworkGrantPolicy::NetworkService,
        None,
    )
    .unwrap_or_else(|_| fatal_kernel_error("service raw-device grant failed"));
    authorize_network_op(holder, raw_handle.encode(), NetworkOp::RawDevice, None)
        .unwrap_or_else(|_| fatal_kernel_error("raw-device op should be allowed"));

    authorize_network_op(holder, handle.encode(), NetworkOp::Connect, None)
        .unwrap_or_else(|_| fatal_kernel_error("connect should be allowed"));
    if authorize_network_op(unrelated, 0, NetworkOp::Connect, None)
        != Err(DenialReason::NoCapability)
    {
        fatal_kernel_error("unrelated without capability should be denied");
    }

    let receive_only = delegate(
        unsafe { capability_space_mut() },
        holder,
        handle,
        unrelated,
        Rights::NET_RECEIVE,
    )
    .unwrap_or_else(|_| fatal_kernel_error("delegate receive failed"));
    if authorize_network_op(unrelated, receive_only.encode(), NetworkOp::Connect, None)
        != Err(DenialReason::MissingRight)
    {
        fatal_kernel_error("receive-only delegate must not connect");
    }

    let session = SessionId::new(SessionGeneration::new(0), 1);
    register_network_session(holder, session, handle)
        .unwrap_or_else(|_| fatal_kernel_error("session register failed"));
    let _ = on_revoked(handle);
    if authorize_network_op(holder, handle.encode(), NetworkOp::Send, None)
        != Err(DenialReason::Revoked)
    {
        fatal_kernel_error("revoked handle must deny");
    }

    bump_network_service_generation();
    let stale_session = SessionGeneration::new(0);
    if authorize_network_op(holder, 0, NetworkOp::Receive, Some(stale_session))
        != Err(DenialReason::StaleGeneration)
    {
        fatal_kernel_error("stale session generation must deny");
    }
    let replacement =
        grant_network_authority(holder, app_rights, NetworkGrantPolicy::Application, None)
            .unwrap_or_else(|_| fatal_kernel_error("replacement grant failed"));
    authorize_network_op(holder, replacement.encode(), NetworkOp::Resolve, None)
        .unwrap_or_else(|_| fatal_kernel_error("resolve on fresh generation failed"));

    let released = on_holder_exit(holder);
    if released == 0 {
        fatal_kernel_error("holder exit should report released network authority");
    }
    teardown_process_by_id(allocator, kernel_root, holder.0, 0, false)
        .unwrap_or_else(|_| fatal_kernel_error("holder teardown failed"));

    kernel_log_fmt(format_args!("{}\n", PASS_MARKER));
    qemu_exit(QEMU_EXIT_SUCCESS);
}
