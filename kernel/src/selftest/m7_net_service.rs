//! M7.3 network service constituent self-test.

use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::scheduler_mut;
use crate::sched::Scheduler;
use crate::service::net_bridge::{net_bridge_mut, shutdown_net_service_instance};
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use clean_slate_network::error::NetworkError;
use clean_slate_network::limits::MAX_SESSIONS;
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};
use clean_slate_network::session::SocketKind;
use clean_slate_service_fixtures::NETWORK_SERVICE_ID;

const PASS_MARKER: &str = "[M7.3] PASS";
const SERVICE_PID: u64 = 70;
const CLIENT_PID: u64 = 71;
const UNAUTHORIZED_PID: u64 = 72;
const CLIENT_GENERATION: u64 = 1;

pub(crate) fn start_m7_net_service_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    let kernel_stack_top = 0;
    install_service_lifecycle_syscall_allocator(allocator);
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root, kernel_stack_top);
    controller
        .declare_service(NETWORK_SERVICE_ID)
        .unwrap_or_else(|message| fatal_kernel_error(message));

    run_scenario();

    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}

fn run_scenario() {
    let gen1 = net_bridge_mut().attach_service_instance(SERVICE_PID, 1, 1);
    kernel_log_fmt(format_args!(
        "[NET ] service started pid={SERVICE_PID} generation={}\n",
        gen1.get()
    ));

    let session = client_open_session(CLIENT_PID, gen1);
    kernel_log_fmt(format_args!("[NET ] session open id={}\n", session.raw()));

    let echo_payload = b"m7-echo-payload";
    client_send(CLIENT_PID, session, echo_payload);
    let mut recv_buf = [0u8; 512];
    let received_len = client_receive(CLIENT_PID, session, &mut recv_buf);
    if &recv_buf[..received_len] != echo_payload {
        fatal_kernel_error("echo payload mismatch");
    }
    kernel_log_fmt(format_args!("[NET ] echo ok len={received_len}\n"));

    probe_unauthorized_raw(UNAUTHORIZED_PID);
    probe_unauthorized_session(UNAUTHORIZED_PID, session);
    kernel_log_fmt(format_args!(
        "[NET ] denied pid={UNAUTHORIZED_PID} reason=no-authority\n"
    ));

    let (reclaimed_sessions, reclaimed_pending) =
        net_bridge_mut().on_holder_exit(CLIENT_PID, CLIENT_GENERATION);
    kernel_log_fmt(format_args!(
        "[NET ] holder exit reclaimed sessions={reclaimed_sessions} pending={reclaimed_pending}\n"
    ));

    let inflight = shutdown_net_service_instance();
    kernel_log_fmt(format_args!("[NET ] inflight failed count={inflight}\n"));

    let gen2 = net_bridge_mut().attach_service_instance(SERVICE_PID + 10, 1, 2);
    kernel_log_fmt(format_args!(
        "[NET ] service restarted pid={} generation={}\n",
        SERVICE_PID + 10,
        gen2.get()
    ));

    let close = NetworkRequest::Close { session }.encode();
    let id = net_bridge_mut()
        .submit(CLIENT_PID, CLIENT_GENERATION, &close, &[])
        .expect("submit stale close");
    drain_service();
    let mut out = [0u8; 64];
    let response = net_bridge_mut()
        .poll(CLIENT_PID, CLIENT_GENERATION, id, &mut out)
        .expect("poll stale close");
    match response {
        NetworkResponse::Error { code }
            if code
                == NetworkError::Denied(
                    clean_slate_network::error::DenialReason::StaleGeneration,
                )
                .code() =>
        {
            kernel_log_fmt(format_args!(
                "[NET ] stale-session denied generation={}\n",
                gen1.get()
            ));
        }
        _ => fatal_kernel_error("expected stale-session denial"),
    }

    capacity_baseline_loop(gen2);
    kernel_log_line("[NET ] capacity baseline ok");
}

fn drain_service() {
    while net_bridge_mut().process_one_pending() {}
}

fn client_open_session(
    pid: u64,
    service_generation: clean_slate_network::session::SessionGeneration,
) -> clean_slate_network::session::SessionId {
    let open = NetworkRequest::Open {
        kind: SocketKind::Udp,
    }
    .encode();
    let id = net_bridge_mut()
        .submit(pid, CLIENT_GENERATION, &open, &[])
        .expect("submit open");
    drain_service();
    let mut out = [0u8; 512];
    let response = net_bridge_mut()
        .poll(pid, CLIENT_GENERATION, id, &mut out)
        .expect("poll open");
    match response {
        NetworkResponse::Open { session } => {
            if !session.matches_generation(service_generation) {
                fatal_kernel_error("session generation mismatch");
            }
            session
        }
        _ => fatal_kernel_error("client open failed"),
    }
}

fn client_send(pid: u64, session: clean_slate_network::session::SessionId, payload: &[u8]) {
    let send = NetworkRequest::Send {
        session,
        payload_len: payload.len() as u32,
    }
    .encode();
    let id = net_bridge_mut()
        .submit(pid, CLIENT_GENERATION, &send, payload)
        .expect("submit send");
    drain_service();
    let mut out = [0u8; 512];
    let response = net_bridge_mut()
        .poll(pid, CLIENT_GENERATION, id, &mut out)
        .expect("poll send");
    if !matches!(response, NetworkResponse::Send { .. }) {
        fatal_kernel_error("client send failed");
    }
}

fn client_receive(
    pid: u64,
    session: clean_slate_network::session::SessionId,
    out: &mut [u8],
) -> usize {
    let recv = NetworkRequest::Receive {
        session,
        max_len: out.len() as u32,
    }
    .encode();
    let id = net_bridge_mut()
        .submit(pid, CLIENT_GENERATION, &recv, &[])
        .expect("submit receive");
    drain_service();
    let response = net_bridge_mut()
        .poll(pid, CLIENT_GENERATION, id, out)
        .expect("poll receive");
    match response {
        NetworkResponse::Receive { payload_len } => payload_len as usize,
        _ => fatal_kernel_error("client receive failed"),
    }
}

fn probe_unauthorized_raw(pid: u64) {
    if crate::service::net_bridge::authorize_raw_device_access(pid, SERVICE_PID) {
        fatal_kernel_error("unauthorized raw access should fail");
    }
}

fn probe_unauthorized_session(pid: u64, session: clean_slate_network::session::SessionId) {
    let close = NetworkRequest::Close { session }.encode();
    let id = net_bridge_mut()
        .submit(pid, CLIENT_GENERATION, &close, &[])
        .expect("submit unauthorized");
    drain_service();
    let mut out = [0u8; 64];
    let response = net_bridge_mut()
        .poll(pid, CLIENT_GENERATION, id, &mut out)
        .expect("poll unauthorized");
    if !matches!(
        response,
        NetworkResponse::Error {
            code: c
        } if c == NetworkError::Denied(clean_slate_network::error::DenialReason::NoCapability).code()
    ) {
        fatal_kernel_error("expected unauthorized session denial");
    }
}

fn capacity_baseline_loop(generation: clean_slate_network::session::SessionGeneration) {
    for _ in 0..=(MAX_SESSIONS * 4) {
        let session = client_open_session(CLIENT_PID, generation);
        client_send(CLIENT_PID, session, b"x");
        let mut buf = [0u8; 64];
        let _ = client_receive(CLIENT_PID, session, &mut buf);
        let close = NetworkRequest::Close { session }.encode();
        let id = net_bridge_mut()
            .submit(CLIENT_PID, CLIENT_GENERATION, &close, &[])
            .expect("close");
        drain_service();
        let mut out = [0u8; 64];
        let _ = net_bridge_mut()
            .poll(CLIENT_PID, CLIENT_GENERATION, id, &mut out)
            .expect("poll close");
        net_bridge_mut().on_holder_exit(CLIENT_PID, CLIENT_GENERATION);
    }
}
