#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::boxed::Box;
use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_ESTALE, SYSCALL_NR_NETWORK_CAPABILITY, SYSCALL_NR_NETWORK_REQUEST,
};
use clean_slate_network::addr::{BoundedHostname, EtherType, IpProtocol, Ipv4Addr, SocketAddrV4};
use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use clean_slate_network::dns::{DnsResolver, ResolveOutcome, DNS_QUERY_TIMEOUT_MS};
use clean_slate_network::error::{DenialReason, NetworkError};
use clean_slate_network::ethernet::EthernetFrame;
use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS,
    FIXTURE_HOSTNAME, GUEST_IPV4, PEER_MAC, TLS_PORT, TLS_SERVER_NAME,
};
use clean_slate_network::ipv4::Ipv4Header;
use clean_slate_network::limits::MAX_SESSIONS;
use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};
use clean_slate_network::session::{SessionGeneration, SessionId, SocketKind};
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::TcpState;
use clean_slate_network::tcp::TcpTransport;
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
    NET_SUBOP_RAW_TRANSMIT, NET_SUBOP_SERVICE_COMPLETE, NET_SUBOP_SERVICE_NEXT,
    NET_SUBOP_SERVICE_REQUEUE, NET_SUBOP_SUBMIT,
    NET_SUBOP_TICK_PERIOD_NS,
};
use core::alloc::{GlobalAlloc, Layout};
use core::arch::x86_64::{__cpuid, _rdrand64_step};
use core::hint::spin_loop;
use core::mem::{size_of, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use rand_core::{CryptoRng, RngCore};

const SYSCALL_NR_VERSION: u64 = 0;
/// ARP cache TTL (~40 s wall time at production 1 ms LAPIC tick).
const ARP_TTL_MS: u64 = 40_000;
const DNS_POLL_LIMIT: usize = 5_000_000;
const TLS_POLL_LIMIT: usize = 10_000_000;
const TLS_IO_TIMEOUT_MS: u64 = 2_000;
const PLAIN_TCP_IO_TIMEOUT_MS: u64 = 2_000;
const TLS_CLOSE_TIMEOUT_MS: u64 = 100;
/// Active-open timeout while waiting for SYN-ACK (matches `TCP_CONNECT_TIMEOUT_TICKS` at 1 ms/tick).
const TCP_CONNECT_TIMEOUT_MS: u64 = 500;

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static NEXT_HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
const PHASE_HEAP_MARGIN_BYTES: usize = 16 * 1024;
const DNS_PHASE_HEAP_REQUIRED_BYTES: usize =
    size_of::<DnsResolver<ServiceLink>>() + PHASE_HEAP_MARGIN_BYTES;
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

fn tick_period_ns() -> u64 {
    let period = net_request([NET_SUBOP_TICK_PERIOD_NS, 0, 0, 0, 0, 0]);
    if period == 0 {
        1_000_000
    } else {
        period
    }
}

fn ms_to_irq_ticks(ms: u64) -> u64 {
    if ms == 0 {
        return 0;
    }
    let period = tick_period_ns();
    let ns = ms.saturating_mul(1_000_000);
    ns.div_ceil(period).max(1)
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

/// One raw NIC reader demuxes frames into bounded per-stack queues (depth 4).
const INGRESS_DEPTH: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StackConsumer {
    Udp,
    Tcp,
}

struct PendingFrames {
    slots: [Option<FrameBuf>; INGRESS_DEPTH],
    len: usize,
}

impl PendingFrames {
    const fn empty() -> Self {
        Self {
            slots: [const { None }; INGRESS_DEPTH],
            len: 0,
        }
    }

    fn push(&mut self, frame: FrameBuf) {
        if self.len >= INGRESS_DEPTH {
            for i in 1..INGRESS_DEPTH {
                self.slots[i - 1] = self.slots[i].take();
            }
            self.len = INGRESS_DEPTH - 1;
        }
        self.slots[self.len] = Some(frame);
        self.len += 1;
    }

    fn pop(&mut self) -> Option<FrameBuf> {
        if self.len == 0 {
            return None;
        }
        let frame = self.slots[0].take();
        for i in 1..self.len {
            self.slots[i - 1] = self.slots[i].take();
        }
        self.len -= 1;
        frame
    }
}

struct NicIngress {
    raw_handle: u64,
    pending_udp: PendingFrames,
    pending_tcp: PendingFrames,
}

static mut NIC_INGRESS: NicIngress = NicIngress {
    raw_handle: 0,
    pending_udp: PendingFrames::empty(),
    pending_tcp: PendingFrames::empty(),
};

fn frame_ipv4_protocol(frame: &FrameBuf) -> Option<IpProtocol> {
    let data = frame.as_slice();
    let (_, l3) = EthernetFrame::parse_frame(data).ok()?;
    let (ipv4, _) = Ipv4Header::parse(l3).ok()?;
    Some(ipv4.protocol)
}

fn frame_is_arp(frame: &FrameBuf) -> bool {
    EthernetFrame::parse_frame(frame.as_slice())
        .ok()
        .is_some_and(|(eth, _)| eth.ethertype == EtherType::ARP)
}

fn nic_ingress_init(raw_handle: u64) {
    unsafe {
        NIC_INGRESS.raw_handle = raw_handle;
        NIC_INGRESS.pending_udp = PendingFrames::empty();
        NIC_INGRESS.pending_tcp = PendingFrames::empty();
    }
}

fn nic_ingress_read_raw() -> Result<Option<FrameBuf>, NetworkDeviceError> {
    let handle = unsafe { NIC_INGRESS.raw_handle };
    let mut buf = [0u8; clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES];
    let status = net_request([
        NET_SUBOP_RAW_RECEIVE,
        handle,
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

#[allow(static_mut_refs)]
fn nic_ingress_stash_udp(frame: FrameBuf) {
    unsafe {
        NIC_INGRESS.pending_udp.push(frame);
    }
}

#[allow(static_mut_refs)]
fn nic_ingress_stash_tcp(frame: FrameBuf) {
    unsafe {
        NIC_INGRESS.pending_tcp.push(frame);
    }
}

fn nic_ingress_enqueue(frame: FrameBuf) {
    if frame_is_arp(&frame) {
        nic_ingress_stash_udp(frame.clone());
        nic_ingress_stash_tcp(frame);
        return;
    }
    match frame_ipv4_protocol(&frame) {
        Some(IpProtocol::UDP) => nic_ingress_stash_udp(frame),
        Some(IpProtocol::TCP) => nic_ingress_stash_tcp(frame),
        _ => {}
    }
}

#[allow(static_mut_refs)]
fn nic_ingress_take_pending(consumer: StackConsumer) -> Option<FrameBuf> {
    unsafe {
        match consumer {
            StackConsumer::Udp => NIC_INGRESS.pending_udp.pop(),
            StackConsumer::Tcp => NIC_INGRESS.pending_tcp.pop(),
        }
    }
}

fn nic_ingress_dequeue(consumer: StackConsumer) -> Result<Option<FrameBuf>, NetworkDeviceError> {
    if let Some(frame) = nic_ingress_take_pending(consumer) {
        return Ok(Some(frame));
    }
    let frame = nic_ingress_read_raw()?;
    let Some(frame) = frame else {
        return Ok(None);
    };
    nic_ingress_enqueue(frame);
    Ok(nic_ingress_take_pending(consumer))
}

struct DemuxLink {
    consumer: StackConsumer,
}

impl DemuxLink {
    fn for_udp() -> Self {
        Self {
            consumer: StackConsumer::Udp,
        }
    }

    fn for_tcp() -> Self {
        Self {
            consumer: StackConsumer::Tcp,
        }
    }

    fn raw_geometry() -> LinkProperties {
        let handle = unsafe { NIC_INGRESS.raw_handle };
        let mut mac = [0u8; 6];
        let status = net_request([
            NET_SUBOP_RAW_GEOMETRY,
            handle,
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

impl NetworkLink for DemuxLink {
    fn link(&self) -> LinkProperties {
        Self::raw_geometry()
    }

    fn state(&self) -> DeviceState {
        DeviceState::Ready
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        let handle = unsafe { NIC_INGRESS.raw_handle };
        let bytes = frame.as_slice();
        let status = net_request([
            NET_SUBOP_RAW_TRANSMIT,
            handle,
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
        nic_ingress_dequeue(self.consumer)
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        Ok(())
    }
}

type ServiceLink = DemuxLink;
type ServiceState = NetworkService<ServiceLink, AllowAllAuthorizer>;

static mut SERVICE_STATE: Option<ServiceState> = None;
static mut SERVICE_DNS_RESOLVER: Option<Box<DnsResolver<ServiceLink>>> = None;
static mut SERVICE_TLS_TRANSPORT: MaybeUninit<TcpTransport<ServiceLink>> = MaybeUninit::uninit();
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

const MAX_PENDING_LINUX_UDP_RECV: usize = 16;

#[derive(Clone, Copy)]
struct PendingLinuxUdpReceive {
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
}

static mut PENDING_LINUX_UDP_RECV: [Option<PendingLinuxUdpReceive>; MAX_PENDING_LINUX_UDP_RECV] =
    [None; MAX_PENDING_LINUX_UDP_RECV];

/// Single-threaded service loop; use raw pointers to satisfy `static_mut_refs` under `-D warnings`.
unsafe fn service_state_slot() -> *mut Option<ServiceState> {
    core::ptr::addr_of_mut!(SERVICE_STATE)
}

unsafe fn service_dns_resolver_slot() -> *mut Option<Box<DnsResolver<ServiceLink>>> {
    core::ptr::addr_of_mut!(SERVICE_DNS_RESOLVER)
}

unsafe fn service_request_buf_ptr() -> *mut [u8; NETWORK_REQUEST_BYTES] {
    core::ptr::addr_of_mut!(SERVICE_REQUEST_BUF)
}

unsafe fn service_tls_transport_ptr() -> *mut TcpTransport<ServiceLink> {
    core::ptr::addr_of_mut!(SERVICE_TLS_TRANSPORT) as *mut TcpTransport<ServiceLink>
}

fn shared_tcp_transport_mut() -> &'static mut TcpTransport<ServiceLink> {
    unsafe { &mut *service_tls_transport_ptr() }
}

fn plain_tcp_owner(service_generation: u64) -> clean_slate_network::protocol::TrustedCaller {
    clean_slate_network::protocol::TrustedCaller::new(0x5200, 0, service_generation)
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
    nic_ingress_init(raw_handle);
    let raw_mac = DemuxLink::raw_geometry().mac;
    unsafe {
        *service_state_slot() = Some(NetworkService::new(generation, AllowAllAuthorizer));
        if let Some(service) = (*service_state_slot()).as_mut() {
            service.attach_backend(DemuxLink::for_udp());
        }
        *service_dns_resolver_slot() = Some(DnsResolver::alloc_boxed(
            L3Stack::new(
                DemuxLink::for_udp(),
                raw_mac,
                GUEST_IPV4,
                ms_to_irq_ticks(ARP_TTL_MS),
            ),
            generation,
            DNS_SERVER_ADDR,
            DnsResolver::<ServiceLink>::DEFAULT_TICKS_PER_SEC,
        ));
        TcpTransport::init_in_place(
            service_tls_transport_ptr(),
            L3Stack::new(
                DemuxLink::for_tcp(),
                raw_mac,
                GUEST_IPV4,
                ms_to_irq_ticks(ARP_TTL_MS),
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
        pump_pending_linux_udp_receives(raw_handle, response_buf, response_payload);
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
        match handle_service_request(
            service,
            bootstrap.service_generation,
            request_id,
            caller,
            request,
            payload,
            response_payload,
        ) {
            Some((response, out_len)) => {
                response_buf.copy_from_slice(&response.encode());
                let _ = service_complete(
                    raw_handle,
                    request_id,
                    response_buf,
                    out_len,
                    &response_payload[..out_len as usize],
                );
            }
            None => {
                let _ = service_requeue(raw_handle, request_id);
            }
        }
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
    unsafe {
        Some(&mut *core::ptr::addr_of_mut!(
            UDP_ENDPOINT_BY_SESSION[index]
        ))
    }
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
    let deadline = start.saturating_add(ms_to_irq_ticks(DNS_QUERY_TIMEOUT_MS));
    let resolver = unsafe {
        (*service_dns_resolver_slot())
            .as_mut()
            .ok_or(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            })?
    };
    let udp_sid = ensure_udp_endpoint(caller, session, dest, start)?;
    for _ in 0..DNS_POLL_LIMIT {
        let now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
            code: NetworkError::Timeout.code(),
        })?;
        let udp = resolver.udp_mut();
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

fn enqueue_pending_linux_udp_receive(entry: PendingLinuxUdpReceive) -> bool {
    unsafe {
        for slot in PENDING_LINUX_UDP_RECV.iter_mut() {
            if slot.is_none() {
                *slot = Some(entry);
                return true;
            }
        }
    }
    false
}

fn try_udp_receive_once(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
    response_payload: &mut [u8],
) -> Result<Option<u32>, NetworkResponse> {
    let dest = match service_connected_dest_for_linux_udp(caller, session)? {
        Some(dest) => dest,
        None => {
            return Err(NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            });
        }
    };
    let start = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let resolver = unsafe {
        (*service_dns_resolver_slot())
            .as_mut()
            .ok_or(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            })?
    };
    let udp_sid = ensure_udp_endpoint(caller, session, dest, start)?;
    let want = max_len as usize;
    let want = want.min(response_payload.len());
    let now = start;
    let udp = resolver.udp_mut();
    if let Err(err) = udp.poll(now) {
        return Err(NetworkResponse::Error {
            code: NetworkError::from(err).code(),
        });
    }
    match udp.receive(udp_sid, caller, &mut response_payload[..want]) {
        Ok(Some((_from, n))) if n > 0 => Ok(Some(n as u32)),
        Ok(Some(_)) | Ok(None) => Ok(None),
        Err(err) => Err(NetworkResponse::Error {
            code: NetworkError::from(err).code(),
        }),
    }
}

fn service_connected_dest_for_linux_udp(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
) -> Result<Option<SocketAddrV4>, NetworkResponse> {
    let service = unsafe {
        (*service_state_slot())
            .as_ref()
            .ok_or(NetworkResponse::Error {
                code: NetworkError::Protocol.code(),
            })?
    };
    service.connected_dest(caller, session)
}

fn pump_pending_linux_udp_receives(
    raw_handle: u64,
    response_buf: &mut [u8; NETWORK_RESPONSE_BYTES],
    response_payload: &mut [u8; NETWORK_MAX_PAYLOAD_BYTES],
) {
    if let Ok(now) = monotonic_ticks() {
        if let Some(resolver) = unsafe { (*service_dns_resolver_slot()).as_mut() } {
            let _ = resolver.poll(now);
        }
    }
    let mut completions = [(0u64, NetworkResponse::Close, 0u32); MAX_PENDING_LINUX_UDP_RECV];
    let mut completion_count = 0usize;
    unsafe {
        for slot in PENDING_LINUX_UDP_RECV.iter_mut() {
            let Some(pending) = slot else {
                continue;
            };
            let entry = *pending;
            match try_udp_receive_once(
                entry.caller,
                entry.session,
                entry.max_len,
                response_payload,
            ) {
                Ok(Some(n)) => {
                    *slot = None;
                    if completion_count < completions.len() {
                        completions[completion_count] = (
                            entry.request_id,
                            NetworkResponse::Receive { payload_len: n },
                            n,
                        );
                        completion_count += 1;
                    }
                }
                Ok(None) => {}
                Err(response) => {
                    *slot = None;
                    if completion_count < completions.len() {
                        completions[completion_count] = (entry.request_id, response, 0);
                        completion_count += 1;
                    }
                }
            }
        }
    }
    for i in 0..completion_count {
        let (request_id, response, out_len) = completions[i];
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

enum LinuxSocketDispatch {
    NotHandled,
    Done(NetworkResponse, u32),
    Deferred,
}

fn handle_service_udp_receive(
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
    response_payload: &mut [u8],
) -> LinuxSocketDispatch {
    match try_udp_receive_once(caller, session, max_len, response_payload) {
        Ok(Some(n)) => LinuxSocketDispatch::Done(
            NetworkResponse::Receive {
                payload_len: n,
            },
            n,
        ),
        Ok(None) => {
            if enqueue_pending_linux_udp_receive(PendingLinuxUdpReceive {
                request_id,
                caller,
                session,
                max_len,
            }) {
                LinuxSocketDispatch::Deferred
            } else {
                LinuxSocketDispatch::Done(
                    NetworkResponse::Error {
                        code: NetworkError::QueueFull.code(),
                    },
                    0,
                )
            }
        }
        Err(response) => LinuxSocketDispatch::Done(response, 0),
    }
}

fn poll_plain_tcp_until<F>(
    tcp: &mut TcpTransport<ServiceLink>,
    start: u64,
    deadline_ticks: u64,
    mut ready: F,
) -> Result<(), NetworkResponse>
where
    F: FnMut(&mut TcpTransport<ServiceLink>, u64) -> Result<bool, NetworkResponse>,
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

fn establish_plain_tcp_session(
    _raw_handle: u64,
    service_generation: u64,
    _caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    dest: SocketAddrV4,
) -> Result<SessionId, NetworkResponse> {
    let tick = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let tcp = shared_tcp_transport_mut();
    tcp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, tick);
    let slot = plain_tcp_slot(session).ok_or(NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    })?;
    let tcp_session = match *slot {
        Some(id) => id,
        None => tcp
            .connect(tick, plain_tcp_owner(service_generation), dest)
            .map_err(|err| NetworkResponse::Error { code: err.code() })?,
    };
    let owner = plain_tcp_owner(service_generation);
    poll_plain_tcp_until(
        tcp,
        tick,
        ms_to_irq_ticks(TCP_CONNECT_TIMEOUT_MS),
        |tcp, _now| {
            match tcp.state(tcp_session, owner) {
                Ok(TcpState::Established) => Ok(true),
                Ok(TcpState::Reset) | Ok(TcpState::Closed) => Err(NetworkResponse::Error {
                    code: NetworkError::Reset.code(),
                }),
                Ok(_) => Ok(false),
                // `poll` frees the slot after an acceptable RST; connect must still fail closed.
                Err(NetworkError::NotFound) => Err(NetworkResponse::Error {
                    code: NetworkError::Reset.code(),
                }),
                Err(err) => Err(NetworkResponse::Error { code: err.code() }),
            }
        },
    )?;
    if let Some(slot) = plain_tcp_slot(session) {
        *slot = Some(tcp_session);
    }
    Ok(tcp_session)
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
    let tcp_session =
        establish_plain_tcp_session(raw_handle, service_generation, caller, session, dest)?;
    let tcp = shared_tcp_transport_mut();
    let sent = tcp
        .send(
            tick,
            tcp_session,
            plain_tcp_owner(service_generation),
            payload,
        )
        .map_err(|err| NetworkResponse::Error { code: err.code() })? as u32;
    Ok(sent)
}

fn handle_service_plain_tcp_receive(
    service: &mut ServiceState,
    _raw_handle: u64,
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
    let tcp = shared_tcp_transport_mut();
    let owner = plain_tcp_owner(service_generation);
    let max_len = max_len as usize;
    let want = max_len
        .min(response_payload.len())
        .min(NETWORK_MAX_PAYLOAD_BYTES);
    let _ = tcp.poll(tick);
    match tcp.receive(tcp_session, owner, &mut response_payload[..want]) {
        Ok(0) => {}
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
            return (
                NetworkResponse::Receive {
                    payload_len: n as u32,
                },
                n as u32,
            );
        }
        Err(NetworkError::Closed) => {
            return (NetworkResponse::Receive { payload_len: 0 }, 0);
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
    let deadline = tick.saturating_add(ms_to_irq_ticks(PLAIN_TCP_IO_TIMEOUT_MS));
    for _ in 0..TLS_POLL_LIMIT {
        let now = match monotonic_ticks() {
            Ok(now) => now,
            Err(_) => break,
        };
        let _ = tcp.poll(now);
        match tcp.receive(tcp_session, owner, &mut response_payload[..want]) {
            Ok(0) => {}
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
                return (
                    NetworkResponse::Receive {
                        payload_len: n as u32,
                    },
                    n as u32,
                );
            }
            Err(NetworkError::Closed) => {
                return (NetworkResponse::Receive { payload_len: 0 }, 0);
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
        if now >= deadline {
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

mod linux_socket_data_plane {
    use super::*;

    pub(super) fn handle(
        service: &mut ServiceState,
        raw_handle: u64,
        service_generation: u64,
        request_id: u64,
        caller: clean_slate_network::protocol::TrustedCaller,
        request: NetworkRequest,
        payload: &[u8],
        response_payload: &mut [u8],
    ) -> LinuxSocketDispatch {
        match request {
            NetworkRequest::Connect { session, dest }
                if matches!(
                    service.session_kind(caller, session),
                    Ok(SocketKind::LinuxTcp)
                ) =>
            {
                let (response, out_len) = match establish_plain_tcp_session(
                    raw_handle,
                    service_generation,
                    caller,
                    session,
                    dest,
                ) {
                    Ok(_) => {
                        if let Err(response) =
                            service.attach_connected_dest(caller, session, dest)
                        {
                            return LinuxSocketDispatch::Done(response, 0);
                        }
                        (NetworkResponse::Connect, 0)
                    }
                    Err(response) => (response, 0),
                };
                LinuxSocketDispatch::Done(response, out_len)
            }
            NetworkRequest::Send {
                session,
                payload_len,
            } if matches!(
                service.session_kind(caller, session),
                Ok(SocketKind::LinuxTcp)
            ) =>
            {
                if payload.len() != payload_len as usize {
                    return LinuxSocketDispatch::Done(
                        NetworkResponse::Error {
                            code: NetworkError::InvalidRequest.code(),
                        },
                        0,
                    );
                }
                {
                    let (response, out_len) = match handle_service_plain_tcp_send(
                        service,
                        raw_handle,
                        service_generation,
                        caller,
                        session,
                        payload,
                    ) {
                        Ok(bytes_sent) => (NetworkResponse::Send { bytes_sent }, 0),
                        Err(response) => (response, 0),
                    };
                    LinuxSocketDispatch::Done(response, out_len)
                }
            }
            NetworkRequest::Send {
                session,
                payload_len,
            } if matches!(
                service.session_kind(caller, session),
                Ok(SocketKind::LinuxUdp)
            ) =>
            {
                if payload.len() != payload_len as usize {
                    return LinuxSocketDispatch::Done(
                        NetworkResponse::Error {
                            code: NetworkError::InvalidRequest.code(),
                        },
                        0,
                    );
                }
                let (response, out_len) =
                    match handle_service_udp_send(service, caller, session, payload) {
                        Ok(bytes_sent) => (NetworkResponse::Send { bytes_sent }, 0),
                        Err(response) => (response, 0),
                    };
                LinuxSocketDispatch::Done(response, out_len)
            }
            NetworkRequest::Receive { session, max_len }
                if matches!(
                    service.session_kind(caller, session),
                    Ok(SocketKind::LinuxUdp)
                ) =>
            {
                handle_service_udp_receive(
                    request_id,
                    caller,
                    session,
                    max_len,
                    response_payload,
                )
            }
            NetworkRequest::Receive { session, max_len }
                if matches!(
                    service.session_kind(caller, session),
                    Ok(SocketKind::LinuxTcp)
                ) =>
            {
                {
                    let (response, out_len) = handle_service_plain_tcp_receive(
                        service,
                        raw_handle,
                        service_generation,
                        caller,
                        session,
                        max_len,
                        response_payload,
                    );
                    LinuxSocketDispatch::Done(response, out_len)
                }
            }
            _ => LinuxSocketDispatch::NotHandled,
        }
    }
}

fn handle_linux_socket_data_plane(
    service: &mut ServiceState,
    raw_handle: u64,
    service_generation: u64,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    request: NetworkRequest,
    payload: &[u8],
    response_payload: &mut [u8],
) -> LinuxSocketDispatch {
    linux_socket_data_plane::handle(
        service,
        raw_handle,
        service_generation,
        request_id,
        caller,
        request,
        payload,
        response_payload,
    )
}

fn handle_service_request(
    service: &mut ServiceState,
    service_generation: u64,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    request: NetworkRequest,
    payload: &[u8],
    response_payload: &mut [u8],
) -> Option<(NetworkResponse, u32)> {
    let raw_handle = bootstrap_mut().net_role_handle;
    match handle_linux_socket_data_plane(
        service,
        raw_handle,
        service_generation,
        request_id,
        caller,
        request,
        payload,
        response_payload,
    ) {
        LinuxSocketDispatch::Done(response, out_len) => return Some((response, out_len)),
        LinuxSocketDispatch::Deferred => return None,
        LinuxSocketDispatch::NotHandled => {}
    }
    match request {
        NetworkRequest::Resolve { name } => Some((handle_service_resolve(caller, name), 0)),
        NetworkRequest::Connect { session, dest }
            if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp)) =>
        {
            Some(service.handle_request(
                caller,
                NetworkRequest::Connect { session, dest },
                payload,
                response_payload,
            ))
        }
        NetworkRequest::Send {
            session,
            payload_len,
        } if matches!(service.session_kind(caller, session), Ok(SocketKind::Tcp)) => {
            if payload.len() != payload_len as usize {
                return Some((
                    NetworkResponse::Error {
                        code: NetworkError::InvalidRequest.code(),
                    },
                    0,
                ));
            }
            Some(
                match handle_service_tls_send(service, service_generation, caller, session, payload)
                {
                    Ok(bytes_sent) => (NetworkResponse::Send { bytes_sent }, 0),
                    Err(response) => (response, 0),
                },
            )
        }
        other => Some(service.handle_request(caller, other, payload, response_payload)),
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
    let deadline = start.saturating_add(ms_to_irq_ticks(DNS_QUERY_TIMEOUT_MS));
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
            .saturating_add(ms_to_irq_ticks(TLS_CLOSE_TIMEOUT_MS));
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

fn drain_holder_exits(service: &mut NetworkService<ServiceLink, AllowAllAuthorizer>) {
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

fn service_requeue(role_handle: u64, request_id: u64) -> Result<(), u64> {
    let status = net_request([
        NET_SUBOP_SERVICE_REQUEUE,
        role_handle,
        request_id,
        0,
        0,
        0,
    ]);
    if status >= u64::MAX - 4095 {
        return Err(status);
    }
    Ok(())
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
    tcp: &mut TcpTransport<ServiceLink>,
    owner: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    start_tick: u64,
) -> Result<(), NetworkResponse> {
    let deadline = start_tick.saturating_add(ms_to_irq_ticks(TLS_CLOSE_TIMEOUT_MS));
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
    tls: &mut TlsSession<'_, '_, ServiceLink>,
    start_tick: u64,
    data: &[u8],
) -> Result<(), u64> {
    let deadline = start_tick.saturating_add(ms_to_irq_ticks(TLS_IO_TIMEOUT_MS));
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
    tls: &mut TlsSession<'_, '_, ServiceLink>,
    start_tick: u64,
    out: &mut [u8],
) -> Result<usize, u64> {
    let deadline = start_tick.saturating_add(ms_to_irq_ticks(TLS_IO_TIMEOUT_MS));
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
