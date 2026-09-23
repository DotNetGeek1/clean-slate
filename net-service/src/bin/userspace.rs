#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::boxed::Box;
use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_ESTALE, SYSCALL_NR_NETWORK_CAPABILITY, SYSCALL_NR_NETWORK_REQUEST,
};
use clean_slate_network::addr::{BoundedHostname, Ipv4Addr, SocketAddrV4};
use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use clean_slate_network::dns::{DnsResolver, ResolveOutcome, DNS_QUERY_TIMEOUT_TICKS};
use clean_slate_network::error::{DenialReason, NetworkError};
use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS,
    FIXTURE_HOSTNAME, GUEST_IPV4, PEER_MAC, TLS_PORT, TLS_SERVER_NAME,
};
use clean_slate_network::limits::MAX_SESSIONS;
use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};
use clean_slate_network::session::{SessionGeneration, SessionId, SocketKind};
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::{TcpState, TcpTransport, TCP_CONNECT_TIMEOUT_TICKS};
use clean_slate_network::tls::{
    TlsConfig, TlsError, TlsSession, TLS_RECORD_BUFFER_BYTES, VALIDATION_TIME_UNIX,
};
use clean_slate_service_fixtures::{
    AllowAllAuthorizer, NetworkService, NetworkServiceBootstrap, NETWORK_CAPABILITY_VERSION,
    NETWORK_CLIENT_DEVICE_ID, NETWORK_DEVICE_ID, NETWORK_MAX_PAYLOAD_BYTES,
    NETWORK_SERVICE_BOOTSTRAP_ADDRESS, NETWORK_SERVICE_MODE_ACCEPTANCE,
    NETWORK_SERVICE_MODE_CAPACITY_LOOP, NETWORK_SERVICE_MODE_CLIENT,
    NETWORK_SERVICE_MODE_CONVERGED_CLIENT, NETWORK_SERVICE_MODE_INFLIGHT_ARM,
    NETWORK_SERVICE_MODE_STALE_CLOSE, NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE,
    NETWORK_SERVICE_NEXT_METADATA_BYTES, NETWORK_SERVICE_NEXT_WIRE_BYTES,
    NETWORK_SERVICE_RESULT_ERROR, NETWORK_SERVICE_RESULT_OK, NETWORK_STATUS_PENDING,
    NET_SUBOP_ACK_HOLDER_EXIT, NET_SUBOP_MONOTONIC_TICKS, NET_SUBOP_POLL,
    NET_SUBOP_POP_HOLDER_EXIT, NET_SUBOP_RAW_GEOMETRY, NET_SUBOP_RAW_RECEIVE,
    NET_SUBOP_RAW_TRANSMIT, NET_SUBOP_SERVICE_COMPLETE, NET_SUBOP_SERVICE_NEXT, NET_SUBOP_SUBMIT,
};
use core::alloc::{GlobalAlloc, Layout};
use core::arch::x86_64::{__cpuid, _rdrand64_step};
use core::hint::spin_loop;
use core::mem::{size_of, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rand_core::{CryptoRng, RngCore};

const SYSCALL_NR_VERSION: u64 = 0;
const ARP_TTL_TICKS: u64 = 50_000;
const DNS_POLL_LIMIT: usize = 5_000_000;
const TLS_POLL_LIMIT: usize = 10_000_000;
const TLS_IO_TIMEOUT_TICKS: u64 = 2_000;
const TLS_CLOSE_TIMEOUT_TICKS: u64 = 100;

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static NEXT_HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
const PHASE_HEAP_MARGIN_BYTES: usize = 16 * 1024;
const DNS_PHASE_HEAP_REQUIRED_BYTES: usize =
    size_of::<DnsResolver<SyscallRawLink>>() + PHASE_HEAP_MARGIN_BYTES;
const HEAP_BYTES: usize = DNS_PHASE_HEAP_REQUIRED_BYTES;
static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];
static TLS_SCRATCH_ACTIVE: AtomicBool = AtomicBool::new(false);
static TLS_HEAP_CHECKPOINT: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let mut current = NEXT_HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = current.saturating_add(align_mask) & !align_mask;
            let next = match aligned.checked_add(layout.size()) {
                Some(next) => next,
                None => return ptr::null_mut(),
            };
            if next > HEAP_BYTES {
                return ptr::null_mut();
            }
            match NEXT_HEAP_OFFSET.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    let heap = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                    return unsafe { heap.add(aligned) };
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    bootstrap_mut().result_code = NETWORK_SERVICE_RESULT_ERROR;
    finish()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    bootstrap_mut().result_code = NETWORK_SERVICE_RESULT_ERROR;
    finish()
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let bootstrap = bootstrap_mut();
    bootstrap.result_code = NETWORK_SERVICE_RESULT_ERROR;
    bootstrap.aux_status = 0;
    bootstrap.net_role_handle = 0;
    bootstrap.session_id_raw = 0;
    bootstrap.echo_len = 0;
    bootstrap.reclaimed_sessions = 0;
    bootstrap.reclaimed_pending = 0;
    bootstrap.inflight_failed = 0;
    bootstrap.tls_transactions = 0;
    bootstrap.tls_heap_checkpoint = 0;
    bootstrap.tls_heap_after_last = 0;

    bootstrap.result_code = match run(bootstrap) {
        Ok(code) => code,
        Err(code) => {
            bootstrap.aux_status = code;
            NETWORK_SERVICE_RESULT_ERROR
        }
    };
    finish()
}

fn bootstrap_mut() -> &'static mut NetworkServiceBootstrap {
    unsafe { &mut *(NETWORK_SERVICE_BOOTSTRAP_ADDRESS as *mut NetworkServiceBootstrap) }
}

fn finish() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

fn wait_fixture_phase_gate() {
    while bootstrap_mut().aux_status == 0 {
        let _ = raw_syscall(SYSCALL_NR_VERSION, [0, 0, 0, 0, 0, 0]);
    }
}

fn run(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    match bootstrap.mode {
        NETWORK_SERVICE_MODE_ACCEPTANCE => {
            run_service_loop(bootstrap);
        }
        NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE => {
            wait_fixture_phase_gate();
            run_unauthorized_probe()
        }
        NETWORK_SERVICE_MODE_CLIENT => run_client_echo(bootstrap),
        NETWORK_SERVICE_MODE_CONVERGED_CLIENT => run_converged_client(bootstrap),
        NETWORK_SERVICE_MODE_INFLIGHT_ARM => {
            wait_fixture_phase_gate();
            run_inflight_arm(bootstrap)
        }
        NETWORK_SERVICE_MODE_STALE_CLOSE => {
            wait_fixture_phase_gate();
            run_stale_close(bootstrap)
        }
        NETWORK_SERVICE_MODE_CAPACITY_LOOP => {
            wait_fixture_phase_gate();
            run_capacity_loop(bootstrap)
        }
        _ => Err(0),
    }
}

fn raw_syscall(nr: u64, args: [u64; 6]) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rax") result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn yield_cpu() {
    let _ = raw_syscall(SYSCALL_NR_VERSION, [0, 0, 0, 0, 0, 0]);
}

fn monotonic_ticks() -> Result<u64, u64> {
    let ticks = net_request([NET_SUBOP_MONOTONIC_TICKS, 0, 0, 0, 0, 0]);
    if ticks >= u64::MAX - 4095 {
        return Err(ticks);
    }
    Ok(ticks)
}

fn network_capability(device_id: u64) -> Result<u64, u64> {
    let raw = raw_syscall(
        SYSCALL_NR_NETWORK_CAPABILITY,
        [device_id, u64::from(NETWORK_CAPABILITY_VERSION), 0, 0, 0, 0],
    );
    if raw >= u64::MAX - 4095 {
        return Err(raw);
    }
    Ok(raw)
}

fn net_request(args: [u64; 6]) -> u64 {
    raw_syscall(SYSCALL_NR_NETWORK_REQUEST, args)
}

fn run_unauthorized_probe() -> Result<u64, u64> {
    match network_capability(NETWORK_CLIENT_DEVICE_ID) {
        Err(SYSCALL_EACCES) => {}
        Ok(_) => return Err(1),
        Err(other) => return Err(other),
    }
    // Without a granted handle, a bridge submit must also be refused by the capability
    // broker (audited as `op=connect outcome=deny`), not just the handle lookup above.
    let open = NetworkRequest::Open {
        kind: SocketKind::Udp,
    }
    .encode();
    match client_submit(0, &open, &[]) {
        Err(SYSCALL_EACCES) => Ok(NETWORK_SERVICE_RESULT_OK),
        Ok(_) => Err(2),
        Err(other) => Err(other),
    }
}

struct SyscallRawLink {
    handle: u64,
}

impl SyscallRawLink {
    fn attach(handle: u64) -> Self {
        Self { handle }
    }

    fn geometry(&self) -> LinkProperties {
        let mut mac = [0u8; 6];
        let status = net_request([
            NET_SUBOP_RAW_GEOMETRY,
            self.handle,
            mac.as_mut_ptr() as u64,
            0,
            0,
            0,
        ]);
        if status >= u64::MAX - 4095 {
            return LinkProperties::new(clean_slate_network::addr::MacAddr([0; 6]), false);
        }
        LinkProperties::new(clean_slate_network::addr::MacAddr(mac), status != 0)
    }
}

impl NetworkLink for SyscallRawLink {
    fn link(&self) -> LinkProperties {
        self.geometry()
    }

    fn state(&self) -> DeviceState {
        DeviceState::Ready
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        let bytes = frame.as_slice();
        let status = net_request([
            NET_SUBOP_RAW_TRANSMIT,
            self.handle,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
        ]);
        if status != 0 {
            return Err((NetworkDeviceError::NotReady, frame));
        }
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        let mut buf = [0u8; clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES];
        let status = net_request([
            NET_SUBOP_RAW_RECEIVE,
            self.handle,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
            0,
        ]);
        if status == u64::MAX {
            return Ok(None);
        }
        if status >= u64::MAX - 4095 {
            return Err(NetworkDeviceError::NotReady);
        }
        let len = status as usize;
        FrameBuf::from_slice(&buf[..len])
            .map(Some)
            .map_err(|_| NetworkDeviceError::Malformed)
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        Ok(())
    }
}

type ServiceState = NetworkService<SyscallRawLink, AllowAllAuthorizer>;

static mut SERVICE_STATE: Option<ServiceState> = None;
static mut SERVICE_DNS_RESOLVER: Option<Box<DnsResolver<SyscallRawLink>>> = None;
static mut SERVICE_TLS_TRANSPORT: MaybeUninit<TcpTransport<SyscallRawLink>> = MaybeUninit::uninit();
static mut SERVICE_PLAIN_TCP_TRANSPORT: Option<Box<TcpTransport<SyscallRawLink>>> = None;
static mut PLAIN_TCP_BY_SESSION: [Option<SessionId>; MAX_SESSIONS as usize] =
    [None; MAX_SESSIONS as usize];
static mut UDP_ENDPOINT_BY_SESSION: [Option<SessionId>; MAX_SESSIONS as usize] =
    [None; MAX_SESSIONS as usize];
static mut SERVICE_TLS_READ_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];
static mut SERVICE_TLS_WRITE_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];
static mut SERVICE_REQUEST_BUF: [u8; NETWORK_REQUEST_BYTES] = [0; NETWORK_REQUEST_BYTES];
static mut SERVICE_PAYLOAD_BUF: [u8; NETWORK_SERVICE_NEXT_WIRE_BYTES] =
    [0; NETWORK_SERVICE_NEXT_WIRE_BYTES];
static mut SERVICE_RESPONSE_BUF: [u8; NETWORK_RESPONSE_BYTES] = [0; NETWORK_RESPONSE_BYTES];
static mut SERVICE_RESPONSE_PAYLOAD: [u8; NETWORK_MAX_PAYLOAD_BYTES] =
    [0; NETWORK_MAX_PAYLOAD_BYTES];

/// Single-threaded service loop; use raw pointers to satisfy `static_mut_refs` under `-D warnings`.
unsafe fn service_state_slot() -> *mut Option<ServiceState> {
    core::ptr::addr_of_mut!(SERVICE_STATE)
}

unsafe fn service_dns_resolver_slot() -> *mut Option<Box<DnsResolver<SyscallRawLink>>> {
    core::ptr::addr_of_mut!(SERVICE_DNS_RESOLVER)
}

unsafe fn service_request_buf_ptr() -> *mut [u8; NETWORK_REQUEST_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_REQUEST_BUF)
}

unsafe fn service_tls_transport_ptr() -> *mut TcpTransport<SyscallRawLink> {
    core::ptr::addr_of_mut!(SERVICE_TLS_TRANSPORT) as *mut TcpTransport<SyscallRawLink>
}

unsafe fn service_plain_tcp_transport_slot(
) -> *mut Option<Box<TcpTransport<SyscallRawLink>>> {
    core::ptr::addr_of_mut!(SERVICE_PLAIN_TCP_TRANSPORT)
}

fn ensure_plain_tcp_transport(
    raw_handle: u64,
    generation: SessionGeneration,
) -> Result<&'static mut TcpTransport<SyscallRawLink>, NetworkResponse> {
    unsafe {
        let slot = &mut *service_plain_tcp_transport_slot();
        if slot.is_none() {
            let raw_mac = SyscallRawLink::attach(raw_handle).link().mac;
            *slot = Some(Box::new(TcpTransport::new(
                L3Stack::new(
                    SyscallRawLink::attach(raw_handle),
                    raw_mac,
                    GUEST_IPV4,
                    ARP_TTL_TICKS,
                ),
                generation,
            )));
        }
        Ok(slot
            .as_mut()
            .expect("plain tcp transport")
            .as_mut())
    }
}

unsafe fn service_tls_read_buf_ptr() -> *mut [u8; TLS_RECORD_BUFFER_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_TLS_READ_BUF)
}

unsafe fn service_tls_write_buf_ptr() -> *mut [u8; TLS_RECORD_BUFFER_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_TLS_WRITE_BUF)
}

unsafe fn service_payload_buf_ptr() -> *mut [u8; NETWORK_SERVICE_NEXT_WIRE_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_PAYLOAD_BUF)
}

unsafe fn service_response_buf_ptr() -> *mut [u8; NETWORK_RESPONSE_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_RESPONSE_BUF)
}

unsafe fn service_response_payload_ptr() -> *mut [u8; NETWORK_MAX_PAYLOAD_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_RESPONSE_PAYLOAD)
}

fn run_service_loop(bootstrap: &mut NetworkServiceBootstrap) -> ! {
    let raw_handle = match network_capability(NETWORK_DEVICE_ID) {
        Ok(handle) => handle,
        Err(_) => finish(),
    };
    bootstrap.net_role_handle = raw_handle;
    let generation = SessionGeneration::new(bootstrap.service_generation);
    let raw_mac = SyscallRawLink::attach(raw_handle).link().mac;
    unsafe {
        *service_state_slot() = Some(NetworkService::new(generation, AllowAllAuthorizer));
        if let Some(service) = (*service_state_slot()).as_mut() {
            service.attach_backend(SyscallRawLink::attach(raw_handle));
        }
        *service_dns_resolver_slot() = Some(DnsResolver::alloc_boxed(
            L3Stack::new(
                SyscallRawLink::attach(raw_handle),
                raw_mac,
                GUEST_IPV4,
                ARP_TTL_TICKS,
            ),
            generation,
            DNS_SERVER_ADDR,
            DnsResolver::<SyscallRawLink>::DEFAULT_TICKS_PER_SEC,
        ));
        TcpTransport::init_in_place(
            service_tls_transport_ptr(),
            L3Stack::new(
                SyscallRawLink::attach(raw_handle),
                raw_mac,
                GUEST_IPV4,
                ARP_TTL_TICKS,
            ),
            generation,
        );
        let heap_checkpoint = current_heap_offset();
        TLS_HEAP_CHECKPOINT.store(heap_checkpoint, Ordering::SeqCst);
        bootstrap.tls_heap_checkpoint = heap_checkpoint as u64;
        bootstrap.tls_heap_after_last = heap_checkpoint as u64;
    }
    loop {
        let service = unsafe {
            match (*service_state_slot()).as_mut() {
                Some(service) => service,
                None => continue,
            }
        };
        let request_buf = unsafe { &mut *service_request_buf_ptr() };
        let payload_buf = unsafe { &mut *service_payload_buf_ptr() };
        let response_buf = unsafe { &mut *service_response_buf_ptr() };
        let response_payload = unsafe { &mut *service_response_payload_ptr() };
        drain_holder_exits(service);
        let found = match service_next(raw_handle, request_buf, payload_buf) {
            Ok(id) => id,
            Err(_) => {
                let _ = raw_syscall(SYSCALL_NR_VERSION, [0, 0, 0, 0, 0, 0]);
                continue;
            }
        };
        if found == 0 {
            let _ = raw_syscall(SYSCALL_NR_VERSION, [0, 0, 0, 0, 0, 0]);
            continue;
        }
        let request_id = found;
        let request = match NetworkRequest::decode(request_buf) {
            Ok(request) => request,
            Err(_) => {
                abort_dequeued_request(raw_handle, request_id);
                continue;
            }
        };
        let Ok(pid_bytes) = payload_buf[0..8].try_into() else {
            abort_dequeued_request(raw_handle, request_id);
            continue;
        };
        let Ok(domain_bytes) = payload_buf[8..16].try_into() else {
            abort_dequeued_request(raw_handle, request_id);
            continue;
        };
        let Ok(gen_bytes) = payload_buf[16..24].try_into() else {
            abort_dequeued_request(raw_handle, request_id);
            continue;
        };
        let Ok(len_bytes) = payload_buf[24..28].try_into() else {
            abort_dequeued_request(raw_handle, request_id);
            continue;
        };
        let caller = clean_slate_network::protocol::TrustedCaller::new(
            u64::from_le_bytes(pid_bytes),
            u64::from_le_bytes(domain_bytes),
            u64::from_le_bytes(gen_bytes),
        );
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        if payload_len > NETWORK_MAX_PAYLOAD_BYTES {
            abort_dequeued_request(raw_handle, request_id);
            continue;
        }
        let payload_start = NETWORK_SERVICE_NEXT_METADATA_BYTES;
        let payload_end = payload_start.saturating_add(payload_len);
        if payload_end > payload_buf.len() {
            abort_dequeued_request(raw_handle, request_id);
            continue;
        }
        let payload = &payload_buf[payload_start..payload_end];
        let (response, out_len) = handle_service_request(
            service,
            raw_handle,
            bootstrap.service_generation,
            caller,
            request,
            payload,
            response_payload,
        );
        response_buf.copy_from_slice(&response.encode());
        let _ = service_complete(
            raw_handle,
            request_id,
            response_buf,
            out_len,
            &response_payload[..out_len as usize],
        );
    }
}

fn plain_tcp_slot(session: SessionId) -> Option<&'static mut Option<SessionId>> {
    let index = session.index() as usize;
    if index >= MAX_SESSIONS as usize {
        return None;
    }
    unsafe { Some(&mut *core::ptr::addr_of_mut!(PLAIN_TCP_BY_SESSION[index])) }
}

fn udp_endpoint_slot(session: SessionId) -> Option<&'static mut Option<SessionId>> {
    let index = session.index() as usize;
    if index >= MAX_SESSIONS as usize {
        return None;
    }
    unsafe { Some(&mut *core::ptr::addr_of_mut!(UDP_ENDPOINT_BY_SESSION[index])) }
}

fn ensure_udp_endpoint(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    dest: SocketAddrV4,
    tick: u64,
) -> Result<SessionId, NetworkResponse> {
    if let Some(slot) = udp_endpoint_slot(session) {
        if let Some(id) = *slot {
            return Ok(id);
        }
    }
    let resolver = unsafe {
        (*service_dns_resolver_slot())
            .as_mut()
            .ok_or(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            })?
    };
    let udp = resolver.udp_mut();
    udp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, tick);
    let id = udp
        .table_mut()
        .open(caller, None)
        .map_err(|err| NetworkResponse::Error {
            code: NetworkError::from(err).code(),
        })?;
    udp.table_mut()
        .connect(id, caller, dest)
        .map_err(|err| NetworkResponse::Error {
            code: NetworkError::from(err).code(),
        })?;
    if let Some(slot) = udp_endpoint_slot(session) {
        *slot = Some(id);
    }
    Ok(id)
}

fn handle_service_udp_send(
    service: &mut ServiceState,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    payload: &[u8],
) -> Result<u32, NetworkResponse> {
    let dest = match service.connected_dest(caller, session) {
        Ok(Some(dest)) => dest,
        Ok(None) => {
            return Err(NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            });
        }
        Err(response) => return Err(response),
    };
    let start = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let deadline = start.saturating_add(DNS_QUERY_TIMEOUT_TICKS);
    let resolver = unsafe {
        (*service_dns_resolver_slot())
            .as_mut()
            .ok_or(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            })?
    };
    let udp_sid = ensure_udp_endpoint(caller, session, dest, start)?;
    let udp = resolver.udp_mut();
    for _ in 0..DNS_POLL_LIMIT {
        let now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
            code: NetworkError::Timeout.code(),
        })?;
        match udp.send(now, udp_sid, caller, Some(dest), payload) {
            Ok(sent) => return Ok(sent as u32),
            Err(NetworkError::Unreachable) => {
                let _ = udp.poll(now);
            }
            Err(err) => {
                return Err(NetworkResponse::Error {
                    code: NetworkError::from(err).code(),
                });
            }
        }
        if now >= deadline {
            break;
        }
        yield_cpu();
    }
    Err(NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })
}

fn handle_service_udp_receive(
    service: &mut ServiceState,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
    response_payload: &mut [u8],
) -> (NetworkResponse, u32) {
    let dest = match service.connected_dest(caller, session) {
        Ok(Some(dest)) => dest,
        Ok(None) => {
            return (
                NetworkResponse::Error {
                    code: NetworkError::InvalidRequest.code(),
                },
                0,
            );
        }
        Err(response) => return (response, 0),
    };
    let start = match monotonic_ticks() {
        Ok(tick) => tick,
        Err(_) => {
            return (
                NetworkResponse::Error {
                    code: NetworkError::Timeout.code(),
                },
                0,
            );
        }
    };
    let deadline = start.saturating_add(DNS_QUERY_TIMEOUT_TICKS);
    let resolver = match unsafe { (*service_dns_resolver_slot()).as_mut() } {
        Some(resolver) => resolver,
        None => {
            return (
                NetworkResponse::Error {
                    code: NetworkError::Protocol.code(),
                },
                0,
            );
        }
    };
    let udp_sid = match ensure_udp_endpoint(caller, session, dest, start) {
        Ok(id) => id,
        Err(response) => return (response, 0),
    };
    let want = max_len as usize;
    let want = want.min(response_payload.len());
    let udp = resolver.udp_mut();
    match udp.receive_with_deadline(start, deadline, udp_sid, caller, &mut response_payload[..want])
    {
        Ok((_from, n)) => (NetworkResponse::Receive { payload_len: n as u32 }, n as u32),
        Err(err) => (
            NetworkResponse::Error {
                code: NetworkError::from(err).code(),
            },
            0,
        ),
    }
}

fn poll_plain_tcp_until<F>(
    tcp: &mut TcpTransport<SyscallRawLink>,
    start: u64,
    deadline_ticks: u64,
    mut ready: F,
) -> Result<(), NetworkResponse>
where
    F: FnMut(&mut TcpTransport<SyscallRawLink>, u64) -> Result<bool, NetworkResponse>,
{
    for _ in 0..TLS_POLL_LIMIT {
        let now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
            code: NetworkError::Timeout.code(),
        })?;
        tcp.poll(now)
            .map_err(|err| NetworkResponse::Error { code: err.code() })?;
        if ready(tcp, now)? {
            return Ok(());
        }
        if now.saturating_sub(start) >= deadline_ticks {
            break;
        }
        yield_cpu();
    }
    Err(NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })
}

fn handle_service_plain_tcp_send(
    service: &mut ServiceState,
    raw_handle: u64,
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    payload: &[u8],
) -> Result<u32, NetworkResponse> {
    let dest = match service.connected_dest(caller, session) {
        Ok(Some(dest)) => dest,
        Ok(None) => {
            return Err(NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            });
        }
        Err(response) => return Err(response),
    };
    let tick = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let generation = SessionGeneration::new(service_generation);
    let tcp = ensure_plain_tcp_transport(raw_handle, generation)?;
    tcp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, tick);
    let slot = plain_tcp_slot(session).ok_or(NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    })?;
    let tcp_session = match slot.take() {
        Some(id) => id,
        None => tcp
            .connect(tick, caller, dest)
            .map_err(|err| NetworkResponse::Error { code: err.code() })?,
    };
    poll_plain_tcp_until(tcp, tick, TCP_CONNECT_TIMEOUT_TICKS, |tcp, now| {
        match tcp.state(tcp_session, caller) {
            Ok(TcpState::Established) => Ok(true),
            Ok(TcpState::Reset) | Ok(TcpState::Closed) => Err(NetworkResponse::Error {
                code: NetworkError::Reset.code(),
            }),
            Ok(_) => {
                let _ = tcp.poll(now);
                Ok(false)
            }
            Err(err) => Err(NetworkResponse::Error { code: err.code() }),
        }
    })?;
    if let Some(slot) = plain_tcp_slot(session) {
        *slot = Some(tcp_session);
    }
    let sent = tcp
        .send(tick, tcp_session, caller, payload)
        .map_err(|err| NetworkResponse::Error { code: err.code() })? as u32;
    let _ = tcp.poll(tick);
    Ok(sent)
}

fn handle_service_plain_tcp_receive(
    service: &mut ServiceState,
    raw_handle: u64,
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
    response_payload: &mut [u8],
) -> (NetworkResponse, u32) {
    let tcp_session = match plain_tcp_slot(session).and_then(|s| *s) {
        Some(id) => id,
        None => {
            return (
                NetworkResponse::Error {
                    code: NetworkError::InvalidRequest.code(),
                },
                0,
            );
        }
    };
    let tick = match monotonic_ticks() {
        Ok(tick) => tick,
        Err(_) => {
            return (
                NetworkResponse::Error {
                    code: NetworkError::Timeout.code(),
                },
                0,
            );
        }
    };
    let generation = SessionGeneration::new(service_generation);
    let tcp = match ensure_plain_tcp_transport(raw_handle, generation) {
        Ok(tcp) => tcp,
        Err(response) => return (response, 0),
    };
    let max_len = max_len as usize;
    let want = max_len
        .min(response_payload.len())
        .min(NETWORK_MAX_PAYLOAD_BYTES);
    for _ in 0..TLS_POLL_LIMIT {
        let now = match monotonic_ticks() {
            Ok(now) => now,
            Err(_) => break,
        };
        let _ = tcp.poll(now);
        match tcp.receive(tcp_session, caller, &mut response_payload[..want]) {
            Ok(0) => {
                if matches!(
                    tcp.state(tcp_session, caller),
                    Ok(TcpState::CloseWait | TcpState::Closed | TcpState::TimeWait)
                ) {
                    return (NetworkResponse::Receive { payload_len: 0 }, 0);
                }
            }
            Ok(n) => {
                if service
                    .stage_response_payload(caller, session, &response_payload[..n])
                    .is_err()
                {
                    return (
                        NetworkResponse::Error {
                            code: NetworkError::InvalidRequest.code(),
                        },
                        0,
                    );
                }
                return (NetworkResponse::Receive { payload_len: n as u32 }, n as u32);
            }
            Err(err) => {
                return (
                    NetworkResponse::Error {
                        code: NetworkError::from(err).code(),
                    },
                    0,
                );
            }
        }
        if now.saturating_sub(tick) >= TCP_CONNECT_TIMEOUT_TICKS {
            break;
        }
        yield_cpu();
    }
    (
        NetworkResponse::Error {
            code: NetworkError::Timeout.code(),
        },
        0,
    )
}

fn handle_service_request(
    service: &mut ServiceState,
    raw_handle: u64,
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    request: NetworkRequest,
    payload: &[u8],
    response_payload: &mut [u8],
) -> (NetworkResponse, u32) {
    match request {
        NetworkRequest::Resolve { name } => (handle_service_resolve(caller, name), 0),
        NetworkRequest::Connect { session, dest }
            if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp)) =>
        {
            service.handle_request(
                caller,
                NetworkRequest::Connect { session, dest },
                payload,
                response_payload,
            )
        }
        NetworkRequest::Send {
            session,
            payload_len,
        } if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp))
            && service
                .connected_dest(caller, session)
                .ok()
                .flatten()
                .is_some_and(|dest| dest.port == TLS_PORT) =>
        {
            if payload.len() != payload_len as usize {
                return (
                    NetworkResponse::Error {
                        code: NetworkError::InvalidRequest.code(),
                    },
                    0,
                );
            }
            match handle_service_tls_send(service, service_generation, caller, session, payload) {
                Ok(bytes_sent) => (NetworkResponse::Send { bytes_sent }, 0),
                Err(response) => (response, 0),
            }
        }
        NetworkRequest::Send {
            session,
            payload_len,
        } if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp)) => {
            if payload.len() != payload_len as usize {
                return (
                    NetworkResponse::Error {
                        code: NetworkError::InvalidRequest.code(),
                    },
                    0,
                );
            }
            match handle_service_plain_tcp_send(
                service,
                raw_handle,
                service_generation,
                caller,
                session,
                payload,
            ) {
                Ok(bytes_sent) => (NetworkResponse::Send { bytes_sent }, 0),
                Err(response) => (response, 0),
            }
        }
        NetworkRequest::Send {
            session,
            payload_len,
        } if matches!(service.session_kind(caller, session), Ok(SocketKind::Udp)) => {
            if payload.len() != payload_len as usize {
                return (
                    NetworkResponse::Error {
                        code: NetworkError::InvalidRequest.code(),
                    },
                    0,
                );
            }
            match handle_service_udp_send(service, caller, session, payload) {
                Ok(bytes_sent) => (NetworkResponse::Send { bytes_sent }, 0),
                Err(response) => (response, 0),
            }
        }
        NetworkRequest::Receive { session, max_len }
            if matches!(service.session_kind(caller, session), Ok(SocketKind::Udp)) =>
        {
            handle_service_udp_receive(service, caller, session, max_len, response_payload)
        }
        NetworkRequest::Receive { session, max_len }
            if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp))
                && service
                    .connected_dest(caller, session)
                    .ok()
                    .flatten()
                    .is_some_and(|dest| dest.port == TLS_PORT) =>
        {
            service.handle_request(
                caller,
                NetworkRequest::Receive { session, max_len },
                payload,
                response_payload,
            )
        }
        NetworkRequest::Receive { session, max_len }
            if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp)) =>
        {
            handle_service_plain_tcp_receive(
                service,
                raw_handle,
                service_generation,
                caller,
                session,
                max_len,
                response_payload,
            )
        }
        other => service.handle_request(caller, other, payload, response_payload),
    }
}

fn handle_service_resolve(
    caller: clean_slate_network::protocol::TrustedCaller,
    name: BoundedHostname,
) -> NetworkResponse {
    let name = match name.as_str() {
        Ok(name) => name,
        Err(_) => {
            return NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            };
        }
    };
    let resolver = unsafe {
        match (*service_dns_resolver_slot()).as_mut() {
            Some(resolver) => resolver,
            None => {
                return NetworkResponse::Error {
                    code: NetworkError::NotFound.code(),
                };
            }
        }
    };
    let start = match monotonic_ticks() {
        Ok(tick) => tick,
        Err(_) => {
            return NetworkResponse::Error {
                code: NetworkError::Timeout.code(),
            };
        }
    };
    let deadline = start.saturating_add(DNS_QUERY_TIMEOUT_TICKS);
    let query_id = match resolver.resolve(start, caller, name) {
        Ok(ResolveOutcome::Cached { addr, ttl }) => return NetworkResponse::Resolve { addr, ttl },
        Ok(ResolveOutcome::Pending { query_id }) => query_id,
        Err(err) => {
            return NetworkResponse::Error {
                code: NetworkError::from(err).code(),
            };
        }
    };
    for _ in 0..DNS_POLL_LIMIT {
        let now = match monotonic_ticks() {
            Ok(tick) => tick,
            Err(_) => {
                return NetworkResponse::Error {
                    code: NetworkError::Timeout.code(),
                };
            }
        };
        if let Err(err) = resolver.poll(now) {
            return NetworkResponse::Error {
                code: NetworkError::from(err).code(),
            };
        }
        if let Some(result) = resolver.take_result(query_id, caller) {
            return match result {
                Ok((addr, ttl)) => NetworkResponse::Resolve { addr, ttl },
                Err(err) => NetworkResponse::Error {
                    code: NetworkError::from(err).code(),
                },
            };
        }
        if now >= deadline {
            break;
        }
        yield_cpu();
    }
    NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    }
}

fn handle_service_tls_send(
    service: &mut ServiceState,
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    payload: &[u8],
) -> Result<u32, NetworkResponse> {
    let scratch = TlsScratchGuard::claim()?;
    let dest = match service.connected_dest(caller, session) {
        Ok(Some(dest)) => dest,
        Ok(None) => {
            return Err(NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            });
        }
        Err(response) => return Err(response),
    };
    let tick = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let tcp = unsafe { &mut *service_tls_transport_ptr() };
    tcp.reset(tick).map_err(|err| NetworkResponse::Error {
        code: NetworkError::from(err).code(),
    })?;
    tcp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, tick);
    let read_buf = unsafe { &mut *service_tls_read_buf_ptr() };
    let write_buf = unsafe { &mut *service_tls_write_buf_ptr() };
    read_buf.fill(0);
    write_buf.fill(0);
    let mut app_buf = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    let response_len = {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let config = TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX);
        let rng = RdrandRng::new().map_err(|_| NetworkResponse::Error {
            code: NetworkError::Protocol.code(),
        })?;
        let service_owner =
            clean_slate_network::protocol::TrustedCaller::new(0x5200, 0, service_generation);
        let handshake_deadline = tick.saturating_add(8_192);
        let (mut tls, _) = TlsSession::connect_with_handshake_deadline(
            tick,
            handshake_deadline,
            tcp,
            service_owner,
            dest,
            config,
            rng,
            read_buf,
            write_buf,
            None,
        )
        .map_err(|err| NetworkResponse::Error {
            code: map_tls_error_code(err) as u16,
        })?;
        write_all_tls(&mut tls, tick.saturating_add(1), payload)
            .map_err(|err| NetworkResponse::Error { code: err as u16 })?;
        let response_len = read_tls(&mut tls, tick.saturating_add(2), &mut app_buf)
            .map_err(|err| NetworkResponse::Error { code: err as u16 })?;
        let tcp_session = tls.tcp_session_id();
        let close_now = monotonic_ticks()
            .map_err(|_| NetworkResponse::Error {
                code: NetworkError::Timeout.code(),
            })?
            .saturating_add(TLS_CLOSE_TIMEOUT_TICKS);
        tls.close(close_now).map_err(|err| NetworkResponse::Error {
            code: map_tls_error_code(err) as u16,
        })?;
        drop(tls);
        drain_tcp_close(tcp, service_owner, tcp_session, close_now)?;
        response_len
    };
    let reset_now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    tcp.reset(reset_now).map_err(|err| NetworkResponse::Error {
        code: NetworkError::from(err).code(),
    })?;
    scratch.verify_reused()?;
    service.stage_response_payload(caller, session, &app_buf[..response_len])?;
    Ok(payload.len() as u32)
}

fn current_heap_offset() -> usize {
    NEXT_HEAP_OFFSET.load(Ordering::SeqCst)
}

struct TlsScratchGuard {
    checkpoint: usize,
}

impl TlsScratchGuard {
    fn claim() -> Result<Self, NetworkResponse> {
        if TLS_SCRATCH_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            });
        }
        let checkpoint = TLS_HEAP_CHECKPOINT.load(Ordering::SeqCst);
        if current_heap_offset() != checkpoint {
            TLS_SCRATCH_ACTIVE.store(false, Ordering::SeqCst);
            return Err(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            });
        }
        Ok(Self { checkpoint })
    }

    fn verify_reused(&self) -> Result<(), NetworkResponse> {
        let current = current_heap_offset();
        let bootstrap = bootstrap_mut();
        bootstrap.tls_heap_after_last = current as u64;
        if current != self.checkpoint {
            return Err(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            });
        }
        bootstrap.tls_transactions = bootstrap.tls_transactions.saturating_add(1);
        Ok(())
    }
}

impl Drop for TlsScratchGuard {
    fn drop(&mut self) {
        TLS_SCRATCH_ACTIVE.store(false, Ordering::SeqCst);
    }
}

fn drain_holder_exits(service: &mut NetworkService<SyscallRawLink, AllowAllAuthorizer>) {
    loop {
        let mut caller_buf = [0u8; 24];
        let status = net_request([
            NET_SUBOP_POP_HOLDER_EXIT,
            0,
            caller_buf.as_mut_ptr() as u64,
            0,
            0,
            0,
        ]);
        if status == 0 {
            return;
        }
        if status >= u64::MAX - 4095 {
            return;
        }
        let caller = clean_slate_network::protocol::TrustedCaller::new(
            u64::from_le_bytes(caller_buf[0..8].try_into().unwrap()),
            u64::from_le_bytes(caller_buf[8..16].try_into().unwrap()),
            u64::from_le_bytes(caller_buf[16..24].try_into().unwrap()),
        );
        let (sessions, pending) = service.on_holder_exit(caller);
        let ack = net_request([
            NET_SUBOP_ACK_HOLDER_EXIT,
            sessions as u64,
            pending as u64,
            0,
            0,
            0,
        ]);
        if ack >= u64::MAX - 4095 {
            return;
        }
    }
}

fn service_next(
    role_handle: u64,
    request_buf: &mut [u8; NETWORK_REQUEST_BYTES],
    payload_buf: &mut [u8; NETWORK_SERVICE_NEXT_WIRE_BYTES],
) -> Result<u64, u64> {
    let status = net_request([
        NET_SUBOP_SERVICE_NEXT,
        role_handle,
        request_buf.as_mut_ptr() as u64,
        payload_buf.as_mut_ptr() as u64,
        payload_buf.len() as u64,
        0,
    ]);
    if status >= u64::MAX - 4095 {
        return Err(status);
    }
    Ok(status)
}

fn abort_dequeued_request(raw_handle: u64, request_id: u64) {
    let mut response_buf = [0u8; NETWORK_RESPONSE_BYTES];
    let response = NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    };
    response_buf.copy_from_slice(&response.encode());
    let _ = service_complete(raw_handle, request_id, &response_buf, 0, &[]);
}

fn service_complete(
    role_handle: u64,
    request_id: u64,
    response_wire: &[u8; NETWORK_RESPONSE_BYTES],
    payload_len: u32,
    payload: &[u8],
) -> Result<(), u64> {
    let status = net_request([
        NET_SUBOP_SERVICE_COMPLETE,
        role_handle,
        request_id,
        response_wire.as_ptr() as u64,
        payload.as_ptr() as u64,
        payload_len as u64,
    ]);
    if status >= u64::MAX - 4095 {
        return Err(status);
    }
    Ok(())
}

fn open_session(handle: u64, kind: SocketKind) -> Result<SessionId, u64> {
    let open = NetworkRequest::Open { kind }.encode();
    let open_id = client_submit(handle, &open, &[])?;
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match poll_until_done(handle, open_id, &mut payload)? {
        NetworkResponse::Open { session } => Ok(session),
        _ => Err(0),
    }
}

fn open_udp_session(handle: u64) -> Result<SessionId, u64> {
    open_session(handle, SocketKind::Udp)
}

fn open_tcp_session(handle: u64) -> Result<SessionId, u64> {
    open_session(handle, SocketKind::Tcp)
}

fn connect_session(handle: u64, session: SessionId, dest: SocketAddrV4) -> Result<(), u64> {
    let request = NetworkRequest::Connect { session, dest }.encode();
    let request_id = client_submit(handle, &request, &[])?;
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match poll_until_done(handle, request_id, &mut payload)? {
        NetworkResponse::Connect => Ok(()),
        NetworkResponse::Error { code } => Err(code as u64),
        _ => Err(0),
    }
}

fn send_session(handle: u64, session: SessionId, payload: &[u8]) -> Result<u32, u64> {
    let request = NetworkRequest::Send {
        session,
        payload_len: payload.len() as u32,
    }
    .encode();
    let request_id = client_submit(handle, &request, payload)?;
    let mut response_payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match poll_until_done(handle, request_id, &mut response_payload)? {
        NetworkResponse::Send { bytes_sent } => Ok(bytes_sent),
        NetworkResponse::Error { code } => Err(code as u64),
        _ => Err(0),
    }
}

fn receive_session(handle: u64, session: SessionId, out: &mut [u8]) -> Result<usize, u64> {
    let request = NetworkRequest::Receive {
        session,
        max_len: out.len() as u32,
    }
    .encode();
    let request_id = client_submit(handle, &request, &[])?;
    match poll_until_done(handle, request_id, out)? {
        NetworkResponse::Receive { payload_len } => Ok(payload_len as usize),
        NetworkResponse::Error { code } => Err(code as u64),
        _ => Err(0),
    }
}

struct RdrandRng;

impl RdrandRng {
    fn new() -> Result<Self, u64> {
        let leaf1 = unsafe { __cpuid(1) };
        if leaf1.ecx & (1 << 30) == 0 {
            return Err(0);
        }
        let mut word = 0u64;
        if unsafe { _rdrand64_step(&mut word) } == 0 {
            return Err(0);
        }
        Ok(Self)
    }
}

impl CryptoRng for RdrandRng {}

impl RngCore for RdrandRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = 0u64;
        while unsafe { _rdrand64_step(&mut word) } == 0 {
            spin_loop();
        }
        word
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0usize;
        while offset < dest.len() {
            let mut word = 0u64;
            while unsafe { _rdrand64_step(&mut word) } == 0 {
                spin_loop();
            }
            let take = (dest.len() - offset).min(8);
            dest[offset..offset + take].copy_from_slice(&word.to_le_bytes()[..take]);
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn client_handle() -> Result<u64, u64> {
    network_capability(NETWORK_CLIENT_DEVICE_ID)
}

fn client_submit(
    handle: u64,
    request_wire: &[u8; NETWORK_REQUEST_BYTES],
    payload: &[u8],
) -> Result<u64, u64> {
    let status = net_request([
        NET_SUBOP_SUBMIT,
        handle,
        request_wire.as_ptr() as u64,
        payload.as_ptr() as u64,
        payload.len() as u64,
        0,
    ]);
    if status >= u64::MAX - 4095 {
        return Err(status);
    }
    Ok(status)
}

fn client_poll(
    handle: u64,
    request_id: u64,
    response_wire: &mut [u8; NETWORK_RESPONSE_BYTES],
    out_payload: &mut [u8],
) -> Result<u64, u64> {
    let status = net_request([
        NET_SUBOP_POLL,
        handle,
        request_id,
        response_wire.as_mut_ptr() as u64,
        out_payload.as_mut_ptr() as u64,
        out_payload.len() as u64,
    ]);
    if status == NETWORK_STATUS_PENDING {
        return Err(NETWORK_STATUS_PENDING);
    }
    if status >= u64::MAX - 4095 {
        return Err(status);
    }
    Ok(status)
}

fn poll_until_done(
    handle: u64,
    request_id: u64,
    out_payload: &mut [u8],
) -> Result<NetworkResponse, u64> {
    let mut response_wire = [0u8; NETWORK_RESPONSE_BYTES];
    for _ in 0..10_000 {
        match client_poll(handle, request_id, &mut response_wire, out_payload) {
            Ok(_) => return NetworkResponse::decode(&response_wire).map_err(|_| 0u64),
            Err(NETWORK_STATUS_PENDING) => {
                let _ = raw_syscall(SYSCALL_NR_VERSION, [0, 0, 0, 0, 0, 0]);
            }
            Err(error) => return Err(error),
        }
    }
    Err(0)
}

fn run_converged_client(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    bootstrap.aux_status = 1;
    bootstrap.aux_status = 2;
    let resolved_addr = run_dns_phase()?;
    bootstrap.aux_status = 3;
    bootstrap.aux_status = 4;
    let first_len = run_tls_phase(resolved_addr)?;
    bootstrap.aux_status = 5;
    let second_len = run_tls_phase(resolved_addr)?;
    bootstrap.echo_len = (first_len + second_len) as u64;
    // Like `run_client_echo`, leave exactly one session open at exit: the kernel test
    // expects holder-exit reclamation of that session and reuses its id for the
    // inflight-failure and stale-generation-denial phases.
    let handle = client_handle()?;
    bootstrap.net_role_handle = handle;
    let lingering = open_udp_session(handle)?;
    bootstrap.session_id_raw = lingering.raw();
    bootstrap.aux_status = 6;
    Ok(NETWORK_SERVICE_RESULT_OK)
}

fn run_dns_phase() -> Result<Ipv4Addr, u64> {
    let handle = client_handle()?;
    let name = BoundedHostname::try_from_str(FIXTURE_HOSTNAME).map_err(|_| 0u64)?;
    let request = NetworkRequest::Resolve { name }.encode();
    let request_id = client_submit(handle, &request, &[])?;
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    let response = poll_until_done(handle, request_id, &mut payload)?;
    match response {
        NetworkResponse::Resolve { addr, ttl }
            if addr == FIXTURE_A_RECORD && ttl == FIXTURE_A_TTL_SECS =>
        {
            Ok(addr)
        }
        NetworkResponse::Error { code } => Err(code as u64),
        _ => Err(0),
    }
}

fn run_tls_phase(resolved_addr: Ipv4Addr) -> Result<usize, u64> {
    let handle = client_handle()?;
    let session = open_tcp_session(handle)?;
    let remote_tls = SocketAddrV4::new(resolved_addr, TLS_PORT);
    connect_session(handle, session, remote_tls)?;
    let bytes_sent = send_session(handle, session, APP_REQUEST_BYTES)?;
    if bytes_sent as usize != APP_REQUEST_BYTES.len() {
        return Err(0);
    }
    let mut app_buf = [0u8; 64];
    let n = receive_session(handle, session, &mut app_buf)?;
    if &app_buf[..n] != APP_RESPONSE_BYTES {
        return Err(0);
    }
    let close = NetworkRequest::Close { session }.encode();
    let close_id = client_submit(handle, &close, &[])?;
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match poll_until_done(handle, close_id, &mut payload)? {
        NetworkResponse::Close => Ok(n),
        NetworkResponse::Error { code } => Err(code as u64),
        _ => Err(0),
    }
}

fn drain_tcp_close(
    tcp: &mut TcpTransport<SyscallRawLink>,
    owner: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    start_tick: u64,
) -> Result<(), NetworkResponse> {
    let deadline = start_tick.saturating_add(TLS_CLOSE_TIMEOUT_TICKS);
    for _ in 0..TLS_POLL_LIMIT {
        let now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
            code: NetworkError::Timeout.code(),
        })?;
        tcp.poll(now)
            .map_err(|err| NetworkResponse::Error { code: err.code() })?;
        match tcp.state(session, owner) {
            Ok(state) if state.is_terminal() => return Ok(()),
            Err(NetworkError::NotFound) => return Ok(()),
            Ok(_) => {}
            Err(err) => return Err(NetworkResponse::Error { code: err.code() }),
        }
        if now >= deadline {
            break;
        }
        yield_cpu();
    }
    Ok(())
}

fn write_all_tls(
    tls: &mut TlsSession<'_, '_, SyscallRawLink>,
    start_tick: u64,
    data: &[u8],
) -> Result<(), u64> {
    let deadline = start_tick.saturating_add(TLS_IO_TIMEOUT_TICKS);
    let mut offset = 0usize;
    for _ in 0..TLS_POLL_LIMIT {
        let tick = monotonic_ticks()?;
        match tls.write(tick, &data[offset..]) {
            Ok(0) => {}
            Ok(written) => offset = offset.saturating_add(written),
            Err(err) => return Err(map_tls_error_code(err)),
        }
        if offset >= data.len() {
            tls.flush().map_err(map_tls_error_code)?;
            return Ok(());
        }
        if tick >= deadline {
            break;
        }
        yield_cpu();
    }
    Err(0)
}

fn read_tls(
    tls: &mut TlsSession<'_, '_, SyscallRawLink>,
    start_tick: u64,
    out: &mut [u8],
) -> Result<usize, u64> {
    let deadline = start_tick.saturating_add(TLS_IO_TIMEOUT_TICKS);
    for _ in 0..TLS_POLL_LIMIT {
        let tick = monotonic_ticks()?;
        match tls.read(tick, out) {
            Ok(0) => {}
            Ok(n) => return Ok(n),
            Err(TlsError::Timeout) => {}
            Err(err) => return Err(map_tls_error_code(err)),
        }
        if tick >= deadline {
            break;
        }
        yield_cpu();
    }
    Err(0)
}

fn map_tls_error_code(err: TlsError) -> u64 {
    match err {
        TlsError::Tcp(_) => 7,
        TlsError::Handshake => 7,
        TlsError::PeerIdentity => 7,
        TlsError::Protocol => 7,
        TlsError::TruncatedRecord => 7,
        TlsError::Timeout => 7,
        TlsError::Closed => 7,
        TlsError::BufferTooSmall => 7,
        TlsError::Rng => 7,
    }
}

fn run_client_echo(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    let handle = client_handle()?;
    bootstrap.net_role_handle = handle;
    let open = NetworkRequest::Open {
        kind: SocketKind::Udp,
    }
    .encode();
    let open_id = client_submit(handle, &open, &[])?;
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    let open_response = poll_until_done(handle, open_id, &mut payload)?;
    let session = match open_response {
        NetworkResponse::Open { session } => session,
        _ => return Err(0),
    };
    bootstrap.session_id_raw = session.raw();
    let echo = b"m7-echo-payload";
    let send = NetworkRequest::Send {
        session,
        payload_len: echo.len() as u32,
    }
    .encode();
    let send_id = client_submit(handle, &send, echo)?;
    let _ = poll_until_done(handle, send_id, &mut payload)?;
    let recv = NetworkRequest::Receive {
        session,
        max_len: payload.len() as u32,
    }
    .encode();
    let recv_id = client_submit(handle, &recv, &[])?;
    let recv_response = poll_until_done(handle, recv_id, &mut payload)?;
    let len = match recv_response {
        NetworkResponse::Receive { payload_len } => payload_len as u64,
        _ => return Err(0),
    };
    if &payload[..len as usize] != echo {
        return Err(0);
    }
    bootstrap.echo_len = len;
    Ok(NETWORK_SERVICE_RESULT_OK)
}

fn run_inflight_arm(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    let handle = client_handle()?;
    let session = SessionId::from_raw(bootstrap.session_id_raw);
    let send = NetworkRequest::Send {
        session,
        payload_len: 4,
    }
    .encode();
    let _ = client_submit(handle, &send, b"halt")?;
    Ok(NETWORK_SERVICE_RESULT_OK)
}

fn run_stale_close(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    let handle = client_handle()?;
    let session = SessionId::from_raw(bootstrap.session_id_raw);
    let close = NetworkRequest::Close { session }.encode();
    let close_id = match client_submit(handle, &close, &[]) {
        Err(SYSCALL_ESTALE) => {
            bootstrap.aux_status = session.generation().get();
            return Ok(NETWORK_SERVICE_RESULT_OK);
        }
        other => other?,
    };
    let mut payload = [0u8; 64];
    let response = poll_until_done(handle, close_id, &mut payload)?;
    match response {
        NetworkResponse::Error { code }
            if code == NetworkError::Denied(DenialReason::StaleGeneration).code() =>
        {
            bootstrap.aux_status = session.generation().get();
            Ok(NETWORK_SERVICE_RESULT_OK)
        }
        _ => Err(0),
    }
}

fn run_capacity_loop(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    let handle = client_handle()?;
    let generation = SessionGeneration::new(bootstrap.service_generation);
    for _ in 0..=(MAX_SESSIONS * 4) {
        let open = NetworkRequest::Open {
            kind: SocketKind::Udp,
        }
        .encode();
        let open_id = client_submit(handle, &open, &[])?;
        let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
        let open_response = poll_until_done(handle, open_id, &mut payload)?;
        let session = match open_response {
            NetworkResponse::Open { session } => {
                if !session.matches_generation(generation) {
                    return Err(0);
                }
                session
            }
            _ => return Err(0),
        };
        let send = NetworkRequest::Send {
            session,
            payload_len: 1,
        }
        .encode();
        let send_id = client_submit(handle, &send, b"x")?;
        let _ = poll_until_done(handle, send_id, &mut payload)?;
        let recv = NetworkRequest::Receive {
            session,
            max_len: payload.len() as u32,
        }
        .encode();
        let recv_id = client_submit(handle, &recv, &[])?;
        let _ = poll_until_done(handle, recv_id, &mut payload)?;
        let close = NetworkRequest::Close { session }.encode();
        let close_id = client_submit(handle, &close, &[])?;
        let _ = poll_until_done(handle, close_id, &mut payload)?;
    }
    bootstrap.result_code = NETWORK_SERVICE_RESULT_OK;
    Ok(NETWORK_SERVICE_RESULT_OK)
}
