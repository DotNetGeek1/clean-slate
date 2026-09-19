#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_ESTALE, SYSCALL_NR_NETWORK_CAPABILITY, SYSCALL_NR_NETWORK_REQUEST,
};
use clean_slate_network::addr::SocketAddrV4;
use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use clean_slate_network::dns::{DnsError, DnsResolver, ResolveOutcome, DNS_QUERY_TIMEOUT_TICKS};
use clean_slate_network::error::{DenialReason, NetworkError};
use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS,
    FIXTURE_HOSTNAME, GUEST_IPV4, GUEST_MAC, PEER_IPV4, PEER_MAC, TLS_PORT, TLS_SERVER_NAME,
};
use clean_slate_network::limits::{MAX_ETHERNET_FRAME_BYTES, MAX_SESSIONS};
use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};
use clean_slate_network::session::{SessionGeneration, SessionId, SocketKind};
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::{TcpState, TcpTransport, TCP_CONNECT_TIMEOUT_TICKS};
use clean_slate_network::tls::{
    TlsConfig, TlsError, TlsSession, TLS_RECORD_BUFFER_BYTES, VALIDATION_TIME_UNIX,
};
use clean_slate_network::udp::UdpTransport;
use clean_slate_service_fixtures::{
    AllowAllAuthorizer, NetworkService, NetworkServiceBootstrap, PassthroughPacketPath,
    NETWORK_CAPABILITY_VERSION, NETWORK_CLIENT_DEVICE_ID, NETWORK_DEVICE_ID,
    NETWORK_MAX_PAYLOAD_BYTES, NETWORK_SERVICE_BOOTSTRAP_ADDRESS, NETWORK_SERVICE_MODE_ACCEPTANCE,
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
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};
use rand_core::{CryptoRng, RngCore};

const SYSCALL_NR_VERSION: u64 = 0;
const ARP_TTL_TICKS: u64 = 50_000;
const DNS_POLL_LIMIT: usize = 5_000_000;
const TCP_POLL_LIMIT: usize = 10_000_000;
const TLS_POLL_LIMIT: usize = 10_000_000;
const TLS_IO_TIMEOUT_TICKS: u64 = 2_000;
const TLS_CLOSE_TIMEOUT_TICKS: u64 = 100;
const OWNER: clean_slate_network::protocol::TrustedCaller =
    clean_slate_network::protocol::TrustedCaller::new(0x5200, 0, 1);

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static NEXT_HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
const HEAP_BYTES: usize = 96 * 1024;
static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

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
        Err(SYSCALL_EACCES) => Ok(NETWORK_SERVICE_RESULT_OK),
        Ok(_) => Err(1),
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

type ServiceState = NetworkService<SyscallRawLink, AllowAllAuthorizer, PassthroughPacketPath>;

static mut SERVICE_STATE: Option<ServiceState> = None;
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

unsafe fn service_request_buf_ptr() -> *mut [u8; NETWORK_REQUEST_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_REQUEST_BUF)
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
    unsafe {
        *service_state_slot() = Some(NetworkService::new(
            generation,
            AllowAllAuthorizer,
            PassthroughPacketPath,
        ));
        if let Some(service) = (*service_state_slot()).as_mut() {
            service.attach_backend(SyscallRawLink::attach(raw_handle));
        }
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
            Err(_) => continue,
        };
        let Ok(pid_bytes) = payload_buf[0..8].try_into() else {
            continue;
        };
        let Ok(domain_bytes) = payload_buf[8..16].try_into() else {
            continue;
        };
        let Ok(gen_bytes) = payload_buf[16..24].try_into() else {
            continue;
        };
        let Ok(len_bytes) = payload_buf[24..28].try_into() else {
            continue;
        };
        let caller = clean_slate_network::protocol::TrustedCaller::new(
            u64::from_le_bytes(pid_bytes),
            u64::from_le_bytes(domain_bytes),
            u64::from_le_bytes(gen_bytes),
        );
        let payload_len = u32::from_le_bytes(len_bytes) as usize;
        if payload_len > NETWORK_MAX_PAYLOAD_BYTES {
            continue;
        }
        let payload_start = NETWORK_SERVICE_NEXT_METADATA_BYTES;
        let payload_end = payload_start.saturating_add(payload_len);
        if payload_end > payload_buf.len() {
            continue;
        }
        let payload = &payload_buf[payload_start..payload_end];
        let (response, out_len) =
            service.handle_request(caller, request, payload, response_payload);
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

fn drain_holder_exits(
    service: &mut NetworkService<SyscallRawLink, AllowAllAuthorizer, PassthroughPacketPath>,
) {
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

struct ServiceClientLink {
    handle: u64,
    session: SessionId,
    recv_payload: [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

impl ServiceClientLink {
    fn open() -> Result<Self, u64> {
        let handle = client_handle()?;
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
        Ok(Self {
            handle,
            session,
            recv_payload: [0u8; NETWORK_MAX_PAYLOAD_BYTES],
        })
    }

    fn close(&mut self) {
        let close = NetworkRequest::Close {
            session: self.session,
        }
        .encode();
        if let Ok(close_id) = client_submit(self.handle, &close, &[]) {
            let _ = poll_until_done(self.handle, close_id, &mut self.recv_payload);
        }
    }
}

impl Drop for ServiceClientLink {
    fn drop(&mut self) {
        self.close();
    }
}

impl NetworkLink for ServiceClientLink {
    fn link(&self) -> LinkProperties {
        LinkProperties::new(GUEST_MAC, true)
    }

    fn state(&self) -> DeviceState {
        DeviceState::Ready
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        let bytes = frame.as_slice();
        let request = NetworkRequest::Send {
            session: self.session,
            payload_len: bytes.len() as u32,
        }
        .encode();
        let send_id = match client_submit(self.handle, &request, bytes) {
            Ok(id) => id,
            Err(_) => return Err((NetworkDeviceError::NotReady, frame)),
        };
        match poll_until_done(self.handle, send_id, &mut self.recv_payload) {
            Ok(NetworkResponse::Send { bytes_sent }) if bytes_sent as usize == bytes.len() => {
                Ok(())
            }
            _ => Err((NetworkDeviceError::NotReady, frame)),
        }
    }

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        let request = NetworkRequest::Receive {
            session: self.session,
            max_len: MAX_ETHERNET_FRAME_BYTES as u32,
        }
        .encode();
        let recv_id =
            client_submit(self.handle, &request, &[]).map_err(|_| NetworkDeviceError::NotReady)?;
        let response = poll_until_done(self.handle, recv_id, &mut self.recv_payload)
            .map_err(|_| NetworkDeviceError::NotReady)?;
        let payload_len = match response {
            NetworkResponse::Receive { payload_len } => payload_len as usize,
            _ => return Err(NetworkDeviceError::Malformed),
        };
        if payload_len == 0 {
            return Ok(None);
        }
        FrameBuf::from_slice(&self.recv_payload[..payload_len])
            .map(Some)
            .map_err(|_| NetworkDeviceError::Malformed)
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        self.close();
        let refreshed = ServiceClientLink::open().map_err(|_| NetworkDeviceError::NotReady)?;
        self.handle = refreshed.handle;
        self.session = refreshed.session;
        self.recv_payload = refreshed.recv_payload;
        Ok(())
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
    run_dns_phase(bootstrap.service_generation)?;
    let app_len = run_tls_phase(bootstrap.service_generation)?;
    bootstrap.echo_len = app_len as u64;
    Ok(NETWORK_SERVICE_RESULT_OK)
}

fn run_dns_phase(generation: u64) -> Result<(), u64> {
    let link = ServiceClientLink::open()?;
    let mac = link.link().mac;
    let stack = L3Stack::new(link, mac, GUEST_IPV4, ARP_TTL_TICKS);
    let udp = UdpTransport::new(stack, SessionGeneration::new(generation));
    let mut resolver = DnsResolver::new(udp, DNS_SERVER_ADDR);
    let start = monotonic_ticks()?;
    let deadline = start.saturating_add(DNS_QUERY_TIMEOUT_TICKS);
    let query_id = match resolver
        .resolve(start, OWNER, FIXTURE_HOSTNAME)
        .map_err(map_dns_error_code)?
    {
        ResolveOutcome::Cached { addr, ttl } => {
            if addr != FIXTURE_A_RECORD || ttl != FIXTURE_A_TTL_SECS {
                return Err(0);
            }
            return Ok(());
        }
        ResolveOutcome::Pending { query_id } => query_id,
    };

    for _ in 0..DNS_POLL_LIMIT {
        let now = monotonic_ticks()?;
        resolver.poll(now).map_err(map_dns_error_code)?;
        if let Some(result) = resolver.take_result(query_id, OWNER) {
            let (addr, ttl) = result.map_err(map_dns_error_code)?;
            if addr != FIXTURE_A_RECORD || ttl != FIXTURE_A_TTL_SECS {
                return Err(0);
            }
            return Ok(());
        }
        if now >= deadline {
            break;
        }
        yield_cpu();
    }
    Err(0)
}

fn run_tls_phase(generation: u64) -> Result<usize, u64> {
    let link = ServiceClientLink::open()?;
    let mac = link.link().mac;
    let mut tcp = TcpTransport::new(
        L3Stack::new(link, mac, GUEST_IPV4, ARP_TTL_TICKS),
        SessionGeneration::new(generation),
    );
    tcp.stack_mut()
        .arp_cache_mut()
        .insert(PEER_IPV4, PEER_MAC, 0);
    let remote_tls = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
    let mut tick = monotonic_ticks()?;
    let tcp_session = tcp
        .connect(tick, OWNER, remote_tls)
        .map_err(map_network_error_code)?;
    tick = drive_tcp_until_established(&mut tcp, tcp_session, tick)?;

    let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
    let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
    let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
    let config = TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX);
    let rng = RdrandRng::new()?;
    let handshake_deadline = tick.saturating_add(8_192);
    let (mut tls, _) = TlsSession::connect_with_handshake_deadline(
        tick,
        handshake_deadline,
        &mut tcp,
        OWNER,
        remote_tls,
        config,
        rng,
        &mut read_buf,
        &mut write_buf,
        None,
    )
    .map_err(map_tls_error_code)?;

    write_all_tls(&mut tls, tick.saturating_add(1), APP_REQUEST_BYTES)?;
    let mut app_buf = [0u8; 64];
    let n = read_tls(&mut tls, tick.saturating_add(2), &mut app_buf)?;
    if &app_buf[..n] != APP_RESPONSE_BYTES {
        return Err(0);
    }
    let close_now = monotonic_ticks()?.saturating_add(TLS_CLOSE_TIMEOUT_TICKS);
    tls.close(close_now).map_err(map_tls_error_code)?;
    Ok(n)
}

fn drive_tcp_until_established(
    tcp: &mut TcpTransport<ServiceClientLink>,
    id: SessionId,
    start_tick: u64,
) -> Result<u64, u64> {
    let deadline = start_tick.saturating_add(TCP_CONNECT_TIMEOUT_TICKS);
    for _ in 0..TCP_POLL_LIMIT {
        let tick = monotonic_ticks()?;
        tcp.poll(tick).map_err(map_network_error_code)?;
        match tcp.state(id, OWNER) {
            Ok(TcpState::Established) => return Ok(tick),
            Ok(TcpState::Reset) | Ok(TcpState::Closed) => return Err(0),
            Ok(_) => {}
            Err(_) => return Err(0),
        }
        if tick >= deadline {
            break;
        }
        yield_cpu();
    }
    Err(0)
}

fn write_all_tls(
    tls: &mut TlsSession<'_, '_, ServiceClientLink>,
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
    tls: &mut TlsSession<'_, '_, ServiceClientLink>,
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

fn map_dns_error_code(err: DnsError) -> u64 {
    match err {
        DnsError::NameNotFound => 1,
        DnsError::Timeout => 2,
        DnsError::QueueFull => 3,
        DnsError::Transport(_) => 4,
        _ => 5,
    }
}

fn map_network_error_code(_err: NetworkError) -> u64 {
    6
}

fn map_tls_error_code(_err: TlsError) -> u64 {
    7
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
