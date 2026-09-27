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
use clean_slate_network::dns::{DnsResolver, ResolveOutcome};
use clean_slate_network::error::{DenialReason, NetworkError};
use clean_slate_network::ethernet::EthernetFrame;
use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, DNS_SERVER_ADDR, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS,
    FIXTURE_HOSTNAME, GUEST_IPV4, PEER_IPV4, PEER_MAC, TLS_PORT, TLS_SERVER_NAME,
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
    tls_transaction, TlsConfig, TlsError, TlsTransactionBudget, TlsTransactionClock,
    TLS_RECORD_BUFFER_BYTES, VALIDATION_TIME_UNIX,
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
    NET_SUBOP_TICK_PERIOD_NS, NET_SUBOP_WAIT_WORK, NET_WAIT_WORK_REQUESTS, NET_WAIT_WORK_RX,
};
use core::alloc::{GlobalAlloc, Layout};
use core::arch::x86_64::{__cpuid, _rdrand64_step};
use core::future::Future;
use core::mem::{size_of, MaybeUninit};
use core::pin::{pin, Pin};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use rand_core::{CryptoRng, RngCore};

/// ARP cache TTL (~40 s wall time at production 1 ms LAPIC tick).
const ARP_TTL_MS: u64 = 40_000;
/// TCP connect plus TLS handshake budget for one service TLS transaction.
const TLS_HANDSHAKE_TIMEOUT_MS: u64 = 8_192;
/// Budget for the TLS request write, and separately for the response read.
const TLS_IO_TIMEOUT_MS: u64 = 2_000;
/// Active-open timeout while waiting for SYN-ACK (matches `TCP_CONNECT_TIMEOUT_TICKS` at 1 ms/tick).
const TCP_CONNECT_TIMEOUT_MS: u64 = 500;
/// Consecutive RDRAND underflows tolerated before the service fails closed (Intel SDM
/// guidance: ten retries make exhaustion vanishingly unlikely on healthy hardware).
const RDRAND_RETRIES: usize = 10;

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
    // `session_id_raw` is an input for the stale-close fixture.
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

/// Phase fixtures start only once the kernel self-test spawns them for their phase, so no
/// mode waits for a release signal.
fn run(bootstrap: &mut NetworkServiceBootstrap) -> Result<u64, u64> {
    match bootstrap.mode {
        NETWORK_SERVICE_MODE_ACCEPTANCE => {
            run_service_loop(bootstrap);
        }
        NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE => run_unauthorized_probe(),
        NETWORK_SERVICE_MODE_CLIENT => run_client_echo(bootstrap),
        NETWORK_SERVICE_MODE_CONVERGED_CLIENT => run_converged_client(bootstrap),
        NETWORK_SERVICE_MODE_INFLIGHT_ARM => run_inflight_arm(),
        NETWORK_SERVICE_MODE_STALE_CLOSE => run_stale_close(bootstrap),
        NETWORK_SERVICE_MODE_CAPACITY_LOOP => run_capacity_loop(bootstrap),
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

/// Idle point of the service loop, entered after `drain_ingress` fed both stacks and no
/// parked request, TLS transaction or new request made progress. Loops at once while
/// frames are stashed; otherwise blocks until a client request, a NIC frame, or
/// `deadline` (the earliest stack timer or parked-work deadline).
fn wait_for_service_work(
    parked: &ParkedRequests,
    tls_active: bool,
    now: u64,
    deadline: Option<u64>,
) {
    if nic_ingress_stashed(StackConsumer::Udp) > 0 || nic_ingress_stashed(StackConsumer::Tcp) > 0 {
        return;
    }
    publish_occupancy(parked, tls_active);
    if wait_net_work(NET_WAIT_WORK_REQUESTS | NET_WAIT_WORK_RX, now, deadline).is_err() {
        finish();
    }
}

fn occupied<T>(rows: &[Option<T>]) -> u64 {
    rows.iter().filter(|row| row.is_some()).count() as u64
}

/// Counts every bounded table the service keeps across requests into the bootstrap page
/// (see `NetworkServiceOccupancy`). Runs only at the idle point, right before blocking.
fn publish_occupancy(parked: &ParkedRequests, tls_active: bool) {
    let (sessions, session_pending) =
        unsafe { service_state().map(|state| &*state) }.map_or((0, 0), |service| {
            (
                u64::from(service.sessions_in_use()),
                u64::from(service.pending_requests()),
            )
        });
    let (udp_endpoints, udp_queued, dns_queries) = match udp_resolver() {
        Ok(resolver) => {
            let dns_queries = resolver.pending_queries() as u64;
            let table = resolver.udp_mut().table();
            (
                table.endpoints_in_use() as u64,
                table.queued_datagrams() as u64,
                dns_queries,
            )
        }
        Err(_) => (0, 0, 0),
    };
    let occupancy = &mut bootstrap_mut().occupancy;
    occupancy.sessions = sessions;
    occupancy.session_pending = session_pending;
    occupancy.tcp_connections = shared_tcp_transport_mut().connections_in_use() as u64;
    occupancy.tcp_mappings = occupied(unsafe { &*core::ptr::addr_of!(PLAIN_TCP_BY_SESSION) });
    occupancy.udp_endpoints = udp_endpoints;
    occupancy.udp_mappings = occupied(unsafe { &*core::ptr::addr_of!(UDP_ENDPOINT_BY_SESSION) });
    occupancy.udp_queued = udp_queued;
    let parked_kind = |kind: fn(&ParkedWork) -> bool| {
        parked
            .slots
            .iter()
            .flatten()
            .filter(|entry| kind(&entry.work))
            .count() as u64
    };
    occupancy.parked_connects = parked_kind(|work| matches!(work, ParkedWork::TcpConnect { .. }));
    occupancy.parked_tcp_receives =
        parked_kind(|work| matches!(work, ParkedWork::TcpReceive { .. }));
    occupancy.parked_udp_receives =
        parked_kind(|work| matches!(work, ParkedWork::UdpReceive { .. }));
    occupancy.parked_resolves = parked_kind(|work| matches!(work, ParkedWork::Resolve { .. }));
    occupancy.tls_jobs = u64::from(tls_active);
    occupancy.dns_queries = dns_queries;
    occupancy.heap_bytes = current_heap_offset() as u64;
    occupancy.publications = occupancy.publications.wrapping_add(1);
}

fn monotonic_ticks() -> Result<u64, u64> {
    let ticks = net_request([NET_SUBOP_MONOTONIC_TICKS, 0, 0, 0, 0, 0]);
    if ticks >= u64::MAX - 4095 {
        return Err(ticks);
    }
    Ok(ticks)
}

/// Reads the kernel IRQ-tick period once. Every service deadline is derived from it, so
/// the service refuses to start without one instead of assuming a period.
fn init_tick_period() -> Result<(), u64> {
    let period = net_request([NET_SUBOP_TICK_PERIOD_NS, 0, 0, 0, 0, 0]);
    if period == 0 || period >= u64::MAX - 4095 {
        return Err(period);
    }
    TICK_PERIOD_NS.store(period, Ordering::Relaxed);
    Ok(())
}

fn tick_period_ns() -> u64 {
    TICK_PERIOD_NS.load(Ordering::Relaxed)
}

fn ms_to_irq_ticks(ms: u64) -> u64 {
    if ms == 0 {
        return 0;
    }
    let ns = ms.saturating_mul(1_000_000);
    ns.div_ceil(tick_period_ns()).max(1)
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

/// Blocks in `NET_SUBOP_WAIT_WORK` until a source in `mask` is ready or the IRQ-tick
/// `deadline` passes (`None` = no timeout). Returns at once when `deadline <= now`.
fn wait_net_work(mask: u64, now: u64, deadline: Option<u64>) -> Result<(), u64> {
    let timeout_ns = match deadline {
        None => 0,
        Some(deadline) if deadline <= now => return Ok(()),
        Some(deadline) => (deadline - now).saturating_mul(tick_period_ns()),
    };
    let handle = unsafe { NIC_INGRESS.raw_handle };
    let status = net_request([NET_SUBOP_WAIT_WORK, handle, mask, timeout_ns, 0, 0]);
    if status >= u64::MAX - 4095 {
        return Err(status);
    }
    Ok(())
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

/// One raw NIC reader demuxes frames into bounded per-stack queues (depth 4). Raw reads
/// stop while either queue is full, so frames wait in the kernel RX ring (whose own
/// overflow is counted in rx-diag) instead of being evicted here.
const INGRESS_DEPTH: usize = 4;
/// Max kernel `RAW_RECEIVE` pulls per demux dequeue when the consumer queue is empty.
const INGRESS_READ_BUDGET: usize = 8;

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

    fn is_full(&self) -> bool {
        self.len >= INGRESS_DEPTH
    }

    /// Callers only read raw frames while every queue has room (see `nic_ingress_dequeue`);
    /// a push into a full queue is still refused and counted rather than evicting.
    fn push(&mut self, frame: FrameBuf) {
        if self.is_full() {
            INGRESS_DROP_FULL.fetch_add(1, Ordering::Relaxed);
            return;
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

static INGRESS_DROP_FULL: AtomicUsize = AtomicUsize::new(0);
/// Frames that are neither ARP nor IPv4 UDP/TCP; no stack consumes them.
static INGRESS_DROP_UNHANDLED: AtomicUsize = AtomicUsize::new(0);
static TICK_PERIOD_NS: AtomicU64 = AtomicU64::new(0);

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
        // ARP is L2: both stacks may consume it; one frame is enough per queue slot budget.
        nic_ingress_stash_udp(frame.clone());
        nic_ingress_stash_tcp(frame);
        return;
    }
    match frame_ipv4_protocol(&frame) {
        Some(IpProtocol::UDP) => nic_ingress_stash_udp(frame),
        Some(IpProtocol::TCP) => nic_ingress_stash_tcp(frame),
        _ => {
            INGRESS_DROP_UNHANDLED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[allow(static_mut_refs)]
fn nic_ingress_stashed(consumer: StackConsumer) -> usize {
    unsafe {
        match consumer {
            StackConsumer::Udp => NIC_INGRESS.pending_udp.len,
            StackConsumer::Tcp => NIC_INGRESS.pending_tcp.len,
        }
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

#[allow(static_mut_refs)]
fn nic_ingress_has_room() -> bool {
    unsafe { !NIC_INGRESS.pending_udp.is_full() && !NIC_INGRESS.pending_tcp.is_full() }
}

fn nic_ingress_dequeue(consumer: StackConsumer) -> Result<Option<FrameBuf>, NetworkDeviceError> {
    if let Some(frame) = nic_ingress_take_pending(consumer) {
        return Ok(Some(frame));
    }
    for _ in 0..INGRESS_READ_BUDGET {
        if !nic_ingress_has_room() {
            break;
        }
        let frame = match nic_ingress_read_raw()? {
            Some(frame) => frame,
            None => break,
        };
        nic_ingress_enqueue(frame);
        if let Some(frame) = nic_ingress_take_pending(consumer) {
            return Ok(Some(frame));
        }
    }
    Ok(None)
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

static mut SERVICE_STATE: MaybeUninit<ServiceState> = MaybeUninit::uninit();
static SERVICE_STATE_READY: AtomicBool = AtomicBool::new(false);
static mut SERVICE_DNS_RESOLVER: Option<Box<DnsResolver<ServiceLink>>> = None;
static mut SERVICE_TLS_TRANSPORT: MaybeUninit<TcpTransport<ServiceLink>> = MaybeUninit::uninit();
/// Linux TCP session -> shared-transport connection, owned by the caller that connected it.
#[derive(Clone, Copy)]
struct LinuxTcpConnection {
    owner: clean_slate_network::protocol::TrustedCaller,
    connection: SessionId,
}

static mut PLAIN_TCP_BY_SESSION: [Option<LinuxTcpConnection>; MAX_SESSIONS as usize] =
    [None; MAX_SESSIONS as usize];
/// Linux UDP session -> datagram endpoint, owned by the caller that connected it.
#[derive(Clone, Copy)]
struct LinuxUdpEndpoint {
    owner: clean_slate_network::protocol::TrustedCaller,
    endpoint: SessionId,
}

static mut UDP_ENDPOINT_BY_SESSION: [Option<LinuxUdpEndpoint>; MAX_SESSIONS as usize] =
    [None; MAX_SESSIONS as usize];
static mut SERVICE_TLS_READ_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];
static mut SERVICE_TLS_WRITE_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];
static mut SERVICE_REQUEST_BUF: [u8; NETWORK_REQUEST_BYTES] = [0; NETWORK_REQUEST_BYTES];
static mut SERVICE_PAYLOAD_BUF: [u8; NETWORK_SERVICE_NEXT_WIRE_BYTES] =
    [0; NETWORK_SERVICE_NEXT_WIRE_BYTES];
static mut SERVICE_RESPONSE_BUF: [u8; NETWORK_RESPONSE_BYTES] = [0; NETWORK_RESPONSE_BYTES];
static mut SERVICE_RESPONSE_PAYLOAD: [u8; NETWORK_MAX_PAYLOAD_BYTES] =
    [0; NETWORK_MAX_PAYLOAD_BYTES];

/// Clock and phase deadline shared with the in-flight TLS transaction future.
static TLS_CLOCK: TlsTransactionClock = TlsTransactionClock::new();
/// Requests refused because the table they would park in was full.
static PARKED_REFUSED_FULL: AtomicUsize = AtomicUsize::new(0);
/// TLS sends refused because a transaction was already in flight.
static TLS_REFUSED_BUSY: AtomicUsize = AtomicUsize::new(0);

/// Parked requests: one per Linux socket session, plus the resolver's in-flight queries.
const MAX_PARKED_REQUESTS: usize = MAX_SESSIONS as usize;

/// A request whose response waits on the network. The service loop keeps serving other
/// requests and completes it from `pump_parked_requests` when its condition holds.
#[derive(Clone, Copy)]
enum ParkedWork {
    /// Linux UDP receive: completes when the endpoint holds a datagram. No service
    /// deadline; the client owns the timeout and cancels by closing.
    UdpReceive { session: SessionId, max_len: u32 },
    /// Linux TCP receive: completes on data, end of stream or a connection error. No
    /// service deadline, as for UDP.
    TcpReceive { session: SessionId, max_len: u32 },
    /// Linux TCP connect waiting for the handshake to finish by `deadline`.
    TcpConnect {
        session: SessionId,
        dest: SocketAddrV4,
        connection: SessionId,
        deadline: u64,
    },
    /// Cache-miss resolve; the resolver enforces the query deadline.
    Resolve { query_id: u32 },
}

#[derive(Clone, Copy)]
struct ParkedRequest {
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    work: ParkedWork,
}

impl ParkedRequest {
    fn session(&self) -> Option<SessionId> {
        match self.work {
            ParkedWork::UdpReceive { session, .. }
            | ParkedWork::TcpReceive { session, .. }
            | ParkedWork::TcpConnect { session, .. } => Some(session),
            ParkedWork::Resolve { .. } => None,
        }
    }
}

struct ParkedRequests {
    slots: [Option<ParkedRequest>; MAX_PARKED_REQUESTS],
}

impl ParkedRequests {
    const fn new() -> Self {
        Self {
            slots: [None; MAX_PARKED_REQUESTS],
        }
    }

    fn contains(&self, request_id: u64) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.is_some_and(|entry| entry.request_id == request_id))
    }

    fn has_room(&self) -> bool {
        self.slots.iter().any(Option::is_none)
    }

    /// Callers check `has_room` first when parking has side effects to undo.
    fn park(&mut self, entry: ParkedRequest) -> bool {
        match self.slots.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(entry);
                true
            }
            None => {
                PARKED_REFUSED_FULL.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    /// Earliest deadline the service itself enforces for parked work.
    fn next_deadline(&self) -> Option<u64> {
        self.slots
            .iter()
            .flatten()
            .filter_map(|entry| match entry.work {
                ParkedWork::TcpConnect { deadline, .. } => Some(deadline),
                _ => None,
            })
            .min()
    }
}

fn queue_full() -> NetworkResponse {
    NetworkResponse::Error {
        code: NetworkError::QueueFull.code(),
    }
}

const TLS_TRUST_ANCHOR: &[u8] = include_bytes!("../../../xtask/fixtures/m7/ca.crt");

/// The request that owns the in-flight TLS transaction.
struct ActiveTls {
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    bytes_sent: u32,
    scratch: TlsScratchGuard,
}

struct TlsJobInput {
    remote: SocketAddrV4,
    owner: clean_slate_network::protocol::TrustedCaller,
    budget: TlsTransactionBudget,
    rng: RdrandRng,
    request: [u8; NETWORK_MAX_PAYLOAD_BYTES],
    request_len: usize,
}

struct TlsJobOutput {
    result: Result<usize, TlsError>,
    response: [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

/// The service's single TLS transaction slot. The future lives in `run_service_loop`'s
/// frame (the loop never returns), which keeps it pinned without static storage.
struct TlsJob<'a, F> {
    future: Pin<&'a mut Option<F>>,
    start: fn(TlsJobInput) -> F,
    active: Option<ActiveTls>,
}

async fn start_tls_job(input: TlsJobInput) -> TlsJobOutput {
    let mut response = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    let config = TlsConfig::new(TLS_SERVER_NAME, TLS_TRUST_ANCHOR, VALIDATION_TIME_UNIX);
    // SAFETY: only the service loop uses the TLS buffers and the shared transport, and
    // it holds no reference to either while it polls or drops this future.
    let transaction = unsafe {
        let read_buf = &mut *service_tls_read_buf_ptr();
        let write_buf = &mut *service_tls_write_buf_ptr();
        read_buf.fill(0);
        write_buf.fill(0);
        tls_transaction(
            service_tls_transport_ptr(),
            &TLS_CLOCK,
            input.budget,
            input.owner,
            input.remote,
            config,
            input.rng,
            read_buf,
            write_buf,
            &input.request[..input.request_len],
            &mut response,
        )
    };
    let result = transaction.await;
    TlsJobOutput { result, response }
}

/// An empty TLS slot for futures made by `start`, pinned by the caller.
fn empty_tls_slot<F>(_start: fn(TlsJobInput) -> F) -> Option<F> {
    None
}

/// Single-threaded service loop; use raw pointers to satisfy `static_mut_refs` under `-D warnings`.
unsafe fn service_state_ptr() -> *mut ServiceState {
    core::ptr::addr_of_mut!(SERVICE_STATE).cast::<ServiceState>()
}

/// The service state once `run_service_loop` has initialized it in place.
unsafe fn service_state() -> Option<*mut ServiceState> {
    SERVICE_STATE_READY
        .load(Ordering::Acquire)
        .then(|| unsafe { service_state_ptr() })
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
    if init_tick_period().is_err() {
        finish();
    }
    bootstrap.net_role_handle = raw_handle;
    let generation = SessionGeneration::new(bootstrap.service_generation);
    nic_ingress_init(raw_handle);
    let raw_mac = DemuxLink::raw_geometry().mac;
    unsafe {
        NetworkService::init_in_place(service_state_ptr(), generation, AllowAllAuthorizer);
        (*service_state_ptr()).attach_backend(DemuxLink::for_udp());
        SERVICE_STATE_READY.store(true, Ordering::Release);
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
    let Some(service) = (unsafe { service_state().map(|state| &mut *state) }) else {
        finish();
    };
    let mut parked = ParkedRequests::new();
    let start: fn(TlsJobInput) -> _ = start_tls_job;
    let tls_future = pin!(empty_tls_slot(start));
    let mut tls = TlsJob {
        future: tls_future,
        start,
        active: None,
    };
    let mut ctx = ServiceContext {
        service,
        service_generation: bootstrap.service_generation,
        raw_handle,
        parked: &mut parked,
        response_buf: unsafe { &mut *service_response_buf_ptr() },
        response_payload: unsafe { &mut *service_response_payload_ptr() },
    };
    loop {
        let request_buf = unsafe { &mut *service_request_buf_ptr() };
        let payload_buf = unsafe { &mut *service_payload_buf_ptr() };
        drain_holder_exits(&mut ctx, &mut tls);
        drain_ingress();
        let Ok(now) = monotonic_ticks() else {
            finish();
        };
        let progressed =
            pump_parked_requests(&mut ctx, now) | pump_tls_job(&mut ctx, &mut tls, now);
        let Ok(found) = service_next(raw_handle, request_buf, payload_buf) else {
            // Denied or stale authority is permanent for this instance.
            finish();
        };
        if found == 0 {
            if !progressed {
                let deadline = next_service_deadline(&ctx, &tls);
                wait_for_service_work(ctx.parked, tls.future.is_some(), now, deadline);
            }
            continue;
        }
        let request_id = found;
        let Some((request, caller, payload)) = decode_service_request(request_buf, payload_buf)
        else {
            let response = NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            };
            ctx.complete(request_id, response, 0);
            continue;
        };
        if let Some((response, out_len)) =
            handle_service_request(&mut ctx, &mut tls, request_id, caller, request, payload)
        {
            ctx.complete(request_id, response, out_len);
        }
    }
}

/// State every request handler needs; built once by `run_service_loop`.
struct ServiceContext<'a> {
    service: &'a mut ServiceState,
    service_generation: u64,
    raw_handle: u64,
    parked: &'a mut ParkedRequests,
    response_buf: &'a mut [u8; NETWORK_RESPONSE_BYTES],
    response_payload: &'a mut [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

impl ServiceContext<'_> {
    /// Completes `request_id` with `response` and the first `out_len` bytes of
    /// `response_payload`.
    fn complete(&mut self, request_id: u64, response: NetworkResponse, out_len: u32) {
        self.response_buf.copy_from_slice(&response.encode());
        let _ = service_complete(
            self.raw_handle,
            request_id,
            self.response_buf,
            out_len,
            &self.response_payload[..out_len as usize],
        );
    }

    /// Completes (with `Reset`) every parked request matching `matches`, releasing what
    /// the parked work holds.
    fn cancel_parked_where(&mut self, matches: impl Fn(&ParkedRequest) -> bool) {
        let reset = NetworkResponse::Error {
            code: NetworkError::Reset.code(),
        };
        for index in 0..MAX_PARKED_REQUESTS {
            let Some(entry) = self.parked.slots[index].filter(|entry| matches(entry)) else {
                continue;
            };
            self.parked.slots[index] = None;
            if let ParkedWork::TcpConnect { connection, .. } = entry.work {
                let owner = plain_tcp_owner(self.service_generation);
                let _ = shared_tcp_transport_mut().abort(connection, owner);
            }
            self.complete(entry.request_id, reset, 0);
        }
    }

    fn cancel_session(
        &mut self,
        caller: clean_slate_network::protocol::TrustedCaller,
        session: SessionId,
    ) {
        self.cancel_parked_where(|entry| {
            entry.caller == caller && entry.session() == Some(session)
        });
    }
}

/// Earliest tick at which the loop must run even without a request or frame: the TCP
/// stack's timers, parked connect deadlines, the resolver's query deadline, and the TLS
/// transaction's phase deadline.
fn next_service_deadline<F>(ctx: &ServiceContext<'_>, tls: &TlsJob<'_, F>) -> Option<u64> {
    let tls_deadline = tls.active.as_ref().map(|_| TLS_CLOCK.phase_deadline());
    let resolver_deadline = udp_resolver()
        .ok()
        .and_then(|resolver| resolver.next_deadline());
    [
        shared_tcp_transport_mut().next_timer_deadline(),
        ctx.parked.next_deadline(),
        resolver_deadline,
        tls_deadline,
    ]
    .into_iter()
    .flatten()
    .min()
}

/// Splits a `SERVICE_NEXT` record into the request, its trusted caller, and its payload.
#[inline(never)]
fn decode_service_request<'a>(
    request_buf: &[u8; NETWORK_REQUEST_BYTES],
    payload_buf: &'a [u8; NETWORK_SERVICE_NEXT_WIRE_BYTES],
) -> Option<(
    NetworkRequest,
    clean_slate_network::protocol::TrustedCaller,
    &'a [u8],
)> {
    let request = NetworkRequest::decode(request_buf).ok()?;
    let word = |range: core::ops::Range<usize>| -> Option<u64> {
        Some(u64::from_le_bytes(payload_buf.get(range)?.try_into().ok()?))
    };
    let caller =
        clean_slate_network::protocol::TrustedCaller::new(word(0..8)?, word(8..16)?, word(16..24)?);
    let payload_len = u32::from_le_bytes(payload_buf.get(24..28)?.try_into().ok()?) as usize;
    if payload_len > NETWORK_MAX_PAYLOAD_BYTES {
        return None;
    }
    let payload_start = NETWORK_SERVICE_NEXT_METADATA_BYTES;
    let payload = payload_buf.get(payload_start..payload_start.checked_add(payload_len)?)?;
    Some((request, caller, payload))
}

fn plain_tcp_slot(session: SessionId) -> Option<&'static mut Option<LinuxTcpConnection>> {
    let index = session.index() as usize;
    if index >= MAX_SESSIONS as usize {
        return None;
    }
    unsafe { Some(&mut *core::ptr::addr_of_mut!(PLAIN_TCP_BY_SESSION[index])) }
}

fn linux_tcp_connection(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
) -> Option<SessionId> {
    plain_tcp_slot(session)
        .and_then(|slot| *slot)
        .filter(|mapping| mapping.owner == caller)
        .map(|mapping| mapping.connection)
}

/// Linux TCP `close` (also run when the holder exits): sends FIN; the shared transport
/// finishes the teardown in `poll` and frees the connection.
fn close_linux_tcp_connection(
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
) {
    if let Some(slot) = plain_tcp_slot(session) {
        close_tcp_mapping_owned_by(service_generation, caller, slot);
    }
}

fn close_linux_tcp_connections_for_caller(
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
) {
    let mappings = unsafe { &mut *core::ptr::addr_of_mut!(PLAIN_TCP_BY_SESSION) };
    for slot in mappings.iter_mut() {
        close_tcp_mapping_owned_by(service_generation, caller, slot);
    }
}

#[inline(never)]
fn close_tcp_mapping_owned_by(
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    slot: &mut Option<LinuxTcpConnection>,
) {
    let Some(mapping) = slot.filter(|mapping| mapping.owner == caller) else {
        return;
    };
    *slot = None;
    let tcp = shared_tcp_transport_mut();
    let owner = plain_tcp_owner(service_generation);
    let is_closing = monotonic_ticks()
        .ok()
        .is_some_and(|now| tcp.close(now, mapping.connection, owner).is_ok());
    if !is_closing {
        let _ = tcp.abort(mapping.connection, owner);
    }
}

fn udp_endpoint_slot(session: SessionId) -> Option<&'static mut Option<LinuxUdpEndpoint>> {
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

fn udp_resolver() -> Result<&'static mut DnsResolver<ServiceLink>, NetworkResponse> {
    unsafe { (*service_dns_resolver_slot()).as_deref_mut() }.ok_or(NetworkResponse::Error {
        code: NetworkError::Protocol.code(),
    })
}

fn close_linux_udp_endpoint(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
) {
    let Some(slot) = udp_endpoint_slot(session) else {
        return;
    };
    let Some(mapping) = slot.filter(|mapping| mapping.owner == caller) else {
        return;
    };
    *slot = None;
    if let Ok(resolver) = udp_resolver() {
        let _ = resolver
            .udp_mut()
            .table_mut()
            .close(mapping.endpoint, caller);
    }
}

/// Linux UDP `connect` (the kernel connects before the first send): opens the session's
/// datagram endpoint, or re-points an existing one at the new peer.
fn connect_linux_udp_endpoint(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    dest: SocketAddrV4,
) -> Result<(), NetworkResponse> {
    let slot = udp_endpoint_slot(session).ok_or(NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    })?;
    let tick = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let udp = udp_resolver()?.udp_mut();
    let to_response = |err: NetworkError| NetworkResponse::Error { code: err.code() };
    udp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, tick);
    if let Some(mapping) = slot.filter(|mapping| mapping.owner == caller) {
        return udp
            .table_mut()
            .connect(mapping.endpoint, caller, dest)
            .map_err(to_response);
    }
    let endpoint = udp.table_mut().open(caller, None).map_err(to_response)?;
    if let Err(err) = udp.table_mut().connect(endpoint, caller, dest) {
        let _ = udp.table_mut().close(endpoint, caller);
        return Err(to_response(err));
    }
    *slot = Some(LinuxUdpEndpoint {
        owner: caller,
        endpoint,
    });
    Ok(())
}

/// Send and receive only use the endpoint `connect` created; a missing one is an error.
fn linux_udp_endpoint(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
) -> Result<SessionId, NetworkResponse> {
    udp_endpoint_slot(session)
        .and_then(|slot| *slot)
        .filter(|mapping| mapping.owner == caller)
        .map(|mapping| mapping.endpoint)
        .ok_or(NetworkResponse::Error {
            code: NetworkError::InvalidRequest.code(),
        })
}

fn forget_linux_udp_endpoints_for_caller(caller: clean_slate_network::protocol::TrustedCaller) {
    let mappings = unsafe { &mut *core::ptr::addr_of_mut!(UDP_ENDPOINT_BY_SESSION) };
    for slot in mappings.iter_mut() {
        if slot.is_some_and(|mapping| mapping.owner == caller) {
            *slot = None;
        }
    }
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
    let now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let udp_sid = linux_udp_endpoint(caller, session)?;
    let udp = udp_resolver()?.udp_mut();
    // Every Linux UDP peer is reached through the fixture next hop that `connect` pinned;
    // refresh the pin so a send after the ARP TTL never waits on neighbour discovery.
    udp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, now);
    let sent = udp
        .send(now, udp_sid, caller, Some(dest), payload)
        .map_err(|err| NetworkResponse::Error { code: err.code() })?;
    let _ = udp.poll(now);
    Ok(sent as u32)
}

/// One non-blocking receive attempt on the session's endpoint. Ingress is drained by
/// the service loop, not here.
fn try_udp_receive_once(
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
    response_payload: &mut [u8],
) -> Result<Option<u32>, NetworkResponse> {
    let udp_sid = linux_udp_endpoint(caller, session)?;
    let want = (max_len as usize).min(response_payload.len());
    match udp_resolver()?
        .udp_mut()
        .receive(udp_sid, caller, &mut response_payload[..want])
    {
        // `receive` reports the full datagram length; only `want` bytes were copied.
        Ok(Some((_from, datagram_len))) => Ok(Some(datagram_len.min(want) as u32)),
        Ok(None) => Ok(None),
        Err(err) => Err(NetworkResponse::Error { code: err.code() }),
    }
}

/// Moves buffered NIC ingress into the UDP endpoint queues (bounded by the ingress
/// queue depth; overflow is counted by the UDP stack) and drives the shared TCP
/// transport (inbound segments, retransmit and close timers).
#[inline(never)]
fn drain_ingress() {
    let Ok(now) = monotonic_ticks() else {
        return;
    };
    if let Ok(resolver) = udp_resolver() {
        for _ in 0..INGRESS_DEPTH {
            let _ = resolver.poll(now);
        }
    }
    let _ = shared_tcp_transport_mut().poll(now);
}

/// Completes parked requests whose condition now holds (after `drain_ingress` fed the
/// stacks). Each completion is sent before the next one reuses `response_payload`.
/// Returns whether any request completed.
fn pump_parked_requests(ctx: &mut ServiceContext<'_>, now: u64) -> bool {
    let mut completed = false;
    for index in 0..MAX_PARKED_REQUESTS {
        let Some(entry) = ctx.parked.slots[index] else {
            continue;
        };
        let Some((response, out_len)) = poll_parked(ctx, &entry, now) else {
            continue;
        };
        ctx.parked.slots[index] = None;
        ctx.complete(entry.request_id, response, out_len);
        completed = true;
    }
    completed
}

/// One non-blocking check of a parked request; `None` while it must keep waiting.
fn poll_parked(
    ctx: &mut ServiceContext<'_>,
    entry: &ParkedRequest,
    now: u64,
) -> Option<(NetworkResponse, u32)> {
    let caller = entry.caller;
    let received = |result: Result<Option<u32>, NetworkResponse>| match result {
        Ok(None) => None,
        Ok(Some(n)) => Some((NetworkResponse::Receive { payload_len: n }, n)),
        Err(response) => Some((response, 0)),
    };
    match entry.work {
        ParkedWork::UdpReceive { session, max_len } => received(try_udp_receive_once(
            caller,
            session,
            max_len,
            &mut ctx.response_payload[..],
        )),
        ParkedWork::TcpReceive { session, max_len } => received(try_tcp_receive_once(
            ctx.service_generation,
            caller,
            session,
            max_len,
            &mut ctx.response_payload[..],
        )),
        ParkedWork::TcpConnect {
            session,
            dest,
            connection,
            deadline,
        } => match plain_tcp_connect_progress(ctx.service_generation, connection) {
            Ok(false) if now < deadline => None,
            Ok(false) => {
                let _ = shared_tcp_transport_mut()
                    .abort(connection, plain_tcp_owner(ctx.service_generation));
                Some((
                    NetworkResponse::Error {
                        code: NetworkError::Timeout.code(),
                    },
                    0,
                ))
            }
            Ok(true) => Some((
                attach_plain_tcp_connection(ctx, caller, session, dest, connection),
                0,
            )),
            Err(response) => {
                let _ = shared_tcp_transport_mut()
                    .abort(connection, plain_tcp_owner(ctx.service_generation));
                Some((response, 0))
            }
        },
        ParkedWork::Resolve { query_id } => {
            let result = udp_resolver().ok()?.take_result(query_id, caller)?;
            Some((resolve_response(result), 0))
        }
    }
}

enum LinuxSocketDispatch {
    NotHandled,
    Done(NetworkResponse, u32),
    Deferred,
}

/// Answers at once when `attempt` has a result, otherwise parks `work` until the pump sees
/// its condition hold.
fn receive_or_park(
    ctx: &mut ServiceContext<'_>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    work: ParkedWork,
    attempt: Result<Option<u32>, NetworkResponse>,
) -> LinuxSocketDispatch {
    match attempt {
        Ok(Some(n)) => LinuxSocketDispatch::Done(NetworkResponse::Receive { payload_len: n }, n),
        Ok(None) => park_or_refuse(ctx, request_id, caller, work),
        Err(response) => LinuxSocketDispatch::Done(response, 0),
    }
}

fn park_or_refuse(
    ctx: &mut ServiceContext<'_>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    work: ParkedWork,
) -> LinuxSocketDispatch {
    if ctx.parked.park(ParkedRequest {
        request_id,
        caller,
        work,
    }) {
        LinuxSocketDispatch::Deferred
    } else {
        LinuxSocketDispatch::Done(queue_full(), 0)
    }
}

/// Whether the handshake of `connection` finished (`Ok(true)`), is still running
/// (`Ok(false)`), or failed.
fn plain_tcp_connect_progress(
    service_generation: u64,
    connection: SessionId,
) -> Result<bool, NetworkResponse> {
    let reset = NetworkResponse::Error {
        code: NetworkError::Reset.code(),
    };
    match shared_tcp_transport_mut().state(connection, plain_tcp_owner(service_generation)) {
        // The peer may send data and FIN before the pump observes the connection.
        Ok(TcpState::Established) | Ok(TcpState::CloseWait) => Ok(true),
        Ok(TcpState::Reset) | Ok(TcpState::Closed) => Err(reset),
        Ok(_) => Ok(false),
        // `poll` frees the slot after an acceptable RST; connect must still fail closed.
        Err(NetworkError::NotFound) => Err(reset),
        Err(err) => Err(NetworkResponse::Error { code: err.code() }),
    }
}

/// Records an established connection as the session's stream and answers the connect.
fn attach_plain_tcp_connection(
    ctx: &mut ServiceContext<'_>,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    dest: SocketAddrV4,
    connection: SessionId,
) -> NetworkResponse {
    let owner = plain_tcp_owner(ctx.service_generation);
    let Some(slot) = plain_tcp_slot(session).filter(|slot| slot.is_none()) else {
        let _ = shared_tcp_transport_mut().abort(connection, owner);
        return NetworkResponse::Error {
            code: NetworkError::InvalidRequest.code(),
        };
    };
    if let Err(response) = ctx.service.attach_connected_dest(caller, session, dest) {
        let _ = shared_tcp_transport_mut().abort(connection, owner);
        return response;
    }
    *slot = Some(LinuxTcpConnection {
        owner: caller,
        connection,
    });
    NetworkResponse::Connect
}

/// Linux TCP `connect`: opens a shared-transport connection and parks the request until
/// the handshake finishes or `TCP_CONNECT_TIMEOUT_MS` passes. A session that already
/// holds a connection answers from its state at once.
fn handle_service_plain_tcp_connect(
    ctx: &mut ServiceContext<'_>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    dest: SocketAddrV4,
) -> LinuxSocketDispatch {
    let invalid = NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    };
    let Some(slot) = plain_tcp_slot(session) else {
        return LinuxSocketDispatch::Done(invalid, 0);
    };
    match *slot {
        Some(mapping) if mapping.owner == caller => {
            let response =
                match plain_tcp_connect_progress(ctx.service_generation, mapping.connection) {
                    Ok(true) => NetworkResponse::Connect,
                    Ok(false) => invalid,
                    Err(response) => response,
                };
            return LinuxSocketDispatch::Done(response, 0);
        }
        Some(_) => return LinuxSocketDispatch::Done(invalid, 0),
        None => {}
    }
    let connecting = ctx.parked.slots.iter().flatten().any(|entry| {
        entry.caller == caller
            && matches!(entry.work, ParkedWork::TcpConnect { session: s, .. } if s == session)
    });
    if connecting || !ctx.parked.has_room() {
        if !connecting {
            PARKED_REFUSED_FULL.fetch_add(1, Ordering::Relaxed);
        }
        return LinuxSocketDispatch::Done(if connecting { invalid } else { queue_full() }, 0);
    }
    let Ok(now) = monotonic_ticks() else {
        return LinuxSocketDispatch::Done(
            NetworkResponse::Error {
                code: NetworkError::Timeout.code(),
            },
            0,
        );
    };
    let tcp = shared_tcp_transport_mut();
    tcp.stack_mut()
        .arp_cache_mut()
        .insert(dest.addr, PEER_MAC, now);
    let connection = match tcp.connect(now, plain_tcp_owner(ctx.service_generation), dest) {
        Ok(connection) => connection,
        Err(err) => {
            return LinuxSocketDispatch::Done(NetworkResponse::Error { code: err.code() }, 0)
        }
    };
    park_or_refuse(
        ctx,
        request_id,
        caller,
        ParkedWork::TcpConnect {
            session,
            dest,
            connection,
            deadline: now.saturating_add(ms_to_irq_ticks(TCP_CONNECT_TIMEOUT_MS)),
        },
    )
}

fn handle_service_plain_tcp_send(
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    payload: &[u8],
) -> Result<u32, NetworkResponse> {
    let connection = linux_tcp_connection(caller, session).ok_or(NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    })?;
    let tick = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let sent = shared_tcp_transport_mut()
        .send(
            tick,
            connection,
            plain_tcp_owner(service_generation),
            payload,
        )
        .map_err(|err| NetworkResponse::Error { code: err.code() })? as u32;
    Ok(sent)
}

/// One non-blocking receive attempt on the session's stream: bytes, `Some(0)` at end of
/// stream, or `None` while the connection has nothing buffered.
fn try_tcp_receive_once(
    service_generation: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    max_len: u32,
    response_payload: &mut [u8],
) -> Result<Option<u32>, NetworkResponse> {
    let connection = linux_tcp_connection(caller, session).ok_or(NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    })?;
    let want = (max_len as usize).min(response_payload.len());
    match shared_tcp_transport_mut().receive(
        connection,
        plain_tcp_owner(service_generation),
        &mut response_payload[..want],
    ) {
        Ok(0) => Ok(None),
        Ok(n) => Ok(Some(n as u32)),
        Err(NetworkError::Closed) => Ok(Some(0)),
        Err(err) => Err(NetworkResponse::Error { code: err.code() }),
    }
}
/// Linux UDP/TCP session requests. Anything else (M7 sessions, resolve) is `NotHandled`.
fn handle_linux_socket_data_plane(
    ctx: &mut ServiceContext<'_>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    request: NetworkRequest,
    payload: &[u8],
) -> LinuxSocketDispatch {
    let session = match request {
        NetworkRequest::Connect { session, .. }
        | NetworkRequest::Send { session, .. }
        | NetworkRequest::Receive { session, .. }
        | NetworkRequest::Close { session } => session,
        _ => return LinuxSocketDispatch::NotHandled,
    };
    let kind = match ctx.service.session_kind(caller, session) {
        Ok(kind @ (SocketKind::LinuxUdp | SocketKind::LinuxTcp)) => kind,
        _ => return LinuxSocketDispatch::NotHandled,
    };
    let invalid = NetworkResponse::Error {
        code: NetworkError::InvalidRequest.code(),
    };
    let sent = |result: Result<u32, NetworkResponse>| match result {
        Ok(bytes_sent) => LinuxSocketDispatch::Done(NetworkResponse::Send { bytes_sent }, 0),
        Err(response) => LinuxSocketDispatch::Done(response, 0),
    };
    match (request, kind) {
        (NetworkRequest::Connect { dest, .. }, SocketKind::LinuxUdp) => {
            let (response, out_len) =
                ctx.service
                    .handle_request(caller, request, payload, &mut ctx.response_payload[..]);
            if !matches!(response, NetworkResponse::Connect) {
                return LinuxSocketDispatch::Done(response, out_len);
            }
            match connect_linux_udp_endpoint(caller, session, dest) {
                Ok(()) => LinuxSocketDispatch::Done(response, out_len),
                Err(response) => LinuxSocketDispatch::Done(response, 0),
            }
        }
        (NetworkRequest::Connect { dest, .. }, _) => {
            handle_service_plain_tcp_connect(ctx, request_id, caller, session, dest)
        }
        (NetworkRequest::Send { payload_len, .. }, _) if payload.len() != payload_len as usize => {
            LinuxSocketDispatch::Done(invalid, 0)
        }
        (NetworkRequest::Send { .. }, SocketKind::LinuxUdp) => sent(handle_service_udp_send(
            ctx.service,
            caller,
            session,
            payload,
        )),
        (NetworkRequest::Send { .. }, _) => sent(handle_service_plain_tcp_send(
            ctx.service_generation,
            caller,
            session,
            payload,
        )),
        (NetworkRequest::Receive { max_len, .. }, SocketKind::LinuxUdp) => {
            let attempt =
                try_udp_receive_once(caller, session, max_len, &mut ctx.response_payload[..]);
            let work = ParkedWork::UdpReceive { session, max_len };
            receive_or_park(ctx, request_id, caller, work, attempt)
        }
        (NetworkRequest::Receive { max_len, .. }, _) => {
            let attempt = try_tcp_receive_once(
                ctx.service_generation,
                caller,
                session,
                max_len,
                &mut ctx.response_payload[..],
            );
            let work = ParkedWork::TcpReceive { session, max_len };
            receive_or_park(ctx, request_id, caller, work, attempt)
        }
        (NetworkRequest::Close { .. }, _) => {
            ctx.cancel_session(caller, session);
            if kind == SocketKind::LinuxUdp {
                close_linux_udp_endpoint(caller, session);
            } else {
                close_linux_tcp_connection(ctx.service_generation, caller, session);
            }
            let (response, out_len) =
                ctx.service
                    .handle_request(caller, request, payload, &mut ctx.response_payload[..]);
            LinuxSocketDispatch::Done(response, out_len)
        }
        _ => LinuxSocketDispatch::NotHandled,
    }
}

/// Answers `request` at once, or returns `None` when it was parked or started a TLS
/// transaction; the pumps complete those later.
fn handle_service_request<F: Future<Output = TlsJobOutput>>(
    ctx: &mut ServiceContext<'_>,
    tls: &mut TlsJob<'_, F>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    request: NetworkRequest,
    payload: &[u8],
) -> Option<(NetworkResponse, u32)> {
    if ctx.parked.contains(request_id)
        || tls
            .active
            .as_ref()
            .is_some_and(|active| active.request_id == request_id)
    {
        return None;
    }
    match handle_linux_socket_data_plane(ctx, request_id, caller, request, payload) {
        LinuxSocketDispatch::Done(response, out_len) => return Some((response, out_len)),
        LinuxSocketDispatch::Deferred => return None,
        LinuxSocketDispatch::NotHandled => {}
    }
    match request {
        NetworkRequest::Resolve { name } => handle_service_resolve(ctx, request_id, caller, name),
        NetworkRequest::Send {
            session,
            payload_len,
        } if matches!(
            ctx.service.session_kind(caller, session),
            Ok(SocketKind::Tcp)
        ) =>
        {
            if payload.len() != payload_len as usize {
                return Some((
                    NetworkResponse::Error {
                        code: NetworkError::InvalidRequest.code(),
                    },
                    0,
                ));
            }
            match start_service_tls_send(ctx, tls, request_id, caller, session, payload) {
                Ok(()) => None,
                Err(response) => Some((response, 0)),
            }
        }
        other => {
            Some(
                ctx.service
                    .handle_request(caller, other, payload, &mut ctx.response_payload[..]),
            )
        }
    }
}

fn resolve_response(
    result: Result<(Ipv4Addr, u32), clean_slate_network::dns::DnsError>,
) -> NetworkResponse {
    match result {
        Ok((addr, ttl)) => NetworkResponse::Resolve { addr, ttl },
        Err(err) => NetworkResponse::Error {
            code: NetworkError::from(err).code(),
        },
    }
}

/// Answers from the cache, or starts a query and parks the request; the resolver's own
/// deadline (enforced in `drain_ingress`) bounds the wait.
fn handle_service_resolve(
    ctx: &mut ServiceContext<'_>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    name: BoundedHostname,
) -> Option<(NetworkResponse, u32)> {
    let error = |err: NetworkError| Some((NetworkResponse::Error { code: err.code() }, 0));
    let Ok(name) = name.as_str() else {
        return error(NetworkError::InvalidRequest);
    };
    let Ok(resolver) = udp_resolver() else {
        return error(NetworkError::NotFound);
    };
    let Ok(now) = monotonic_ticks() else {
        return error(NetworkError::Timeout);
    };
    if !ctx.parked.has_room() {
        PARKED_REFUSED_FULL.fetch_add(1, Ordering::Relaxed);
        return Some((queue_full(), 0));
    }
    let query_id = match resolver.resolve(now, caller, name) {
        Ok(ResolveOutcome::Cached { addr, ttl }) => {
            return Some((NetworkResponse::Resolve { addr, ttl }, 0));
        }
        Ok(ResolveOutcome::Pending { query_id }) => query_id,
        Err(err) => return error(NetworkError::from(err)),
    };
    ctx.parked.park(ParkedRequest {
        request_id,
        caller,
        work: ParkedWork::Resolve { query_id },
    });
    None
}

/// Starts the TLS transaction for an M7 TCP `Send`: copies the request, claims the TLS
/// scratch, and installs the transaction future that `pump_tls_job` drives.
fn start_service_tls_send<F: Future<Output = TlsJobOutput>>(
    ctx: &mut ServiceContext<'_>,
    tls: &mut TlsJob<'_, F>,
    request_id: u64,
    caller: clean_slate_network::protocol::TrustedCaller,
    session: SessionId,
    payload: &[u8],
) -> Result<(), NetworkResponse> {
    if tls.active.is_some() {
        TLS_REFUSED_BUSY.fetch_add(1, Ordering::Relaxed);
        return Err(queue_full());
    }
    let scratch = TlsScratchGuard::claim()?;
    let remote = match ctx.service.connected_dest(caller, session) {
        Ok(Some(dest)) => dest,
        Ok(None) => {
            return Err(NetworkResponse::Error {
                code: NetworkError::InvalidRequest.code(),
            });
        }
        Err(response) => return Err(response),
    };
    let now = monotonic_ticks().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Timeout.code(),
    })?;
    let rng = RdrandRng::new().map_err(|_| NetworkResponse::Error {
        code: NetworkError::Protocol.code(),
    })?;
    shared_tcp_transport_mut()
        .stack_mut()
        .arp_cache_mut()
        .insert(remote.addr, PEER_MAC, now);
    let mut input = TlsJobInput {
        remote,
        owner: plain_tcp_owner(ctx.service_generation),
        budget: TlsTransactionBudget {
            handshake_ticks: ms_to_irq_ticks(TLS_HANDSHAKE_TIMEOUT_MS),
            io_ticks: ms_to_irq_ticks(TLS_IO_TIMEOUT_MS),
        },
        rng,
        request: [0u8; NETWORK_MAX_PAYLOAD_BYTES],
        request_len: payload.len(),
    };
    input
        .request
        .get_mut(..payload.len())
        .ok_or(NetworkResponse::Error {
            code: NetworkError::InvalidRequest.code(),
        })?
        .copy_from_slice(payload);
    tls.future.set(Some((tls.start)(input)));
    tls.active = Some(ActiveTls {
        request_id,
        caller,
        session,
        bytes_sent: payload.len() as u32,
        scratch,
    });
    Ok(())
}

/// Polls the in-flight TLS transaction once and completes its request when it resolves or
/// its phase deadline passes. Returns whether the request completed.
fn pump_tls_job<F: Future<Output = TlsJobOutput>>(
    ctx: &mut ServiceContext<'_>,
    tls: &mut TlsJob<'_, F>,
    now: u64,
) -> bool {
    let Some(future) = tls.future.as_mut().as_pin_mut() else {
        return false;
    };
    TLS_CLOCK.set_now(now);
    let output = match future.poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => Some(output),
        Poll::Pending if now >= TLS_CLOCK.phase_deadline() => None,
        Poll::Pending => return false,
    };
    // Dropping an unfinished transaction aborts its TCP connection.
    tls.future.set(None);
    let Some(active) = tls.active.take() else {
        return true;
    };
    let tls_error = |err| NetworkResponse::Error {
        code: map_tls_error_code(err) as u16,
    };
    let response = match output {
        None => tls_error(TlsError::Timeout),
        Some(TlsJobOutput {
            result: Ok(len),
            response,
        }) => match active.scratch.verify_reused().and_then(|()| {
            ctx.service
                .stage_response_payload(active.caller, active.session, &response[..len])
        }) {
            Ok(()) => NetworkResponse::Send {
                bytes_sent: active.bytes_sent,
            },
            Err(response) => response,
        },
        Some(TlsJobOutput {
            result: Err(err), ..
        }) => tls_error(err),
    };
    ctx.complete(active.request_id, response, 0);
    true
}

/// Drops the in-flight TLS transaction (aborting its connection) if `caller` owns it.
fn cancel_tls_job_for<F>(
    ctx: &mut ServiceContext<'_>,
    tls: &mut TlsJob<'_, F>,
    caller: clean_slate_network::protocol::TrustedCaller,
) {
    if !tls
        .active
        .as_ref()
        .is_some_and(|active| active.caller == caller)
    {
        return;
    }
    tls.future.set(None);
    if let Some(active) = tls.active.take() {
        let reset = NetworkResponse::Error {
            code: NetworkError::Reset.code(),
        };
        ctx.complete(active.request_id, reset, 0);
    }
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

fn drain_holder_exits<F>(ctx: &mut ServiceContext<'_>, tls: &mut TlsJob<'_, F>) {
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
        ctx.cancel_parked_where(|entry| entry.caller == caller);
        cancel_tls_job_for(ctx, tls, caller);
        if let Some(resolver) = unsafe { (*service_dns_resolver_slot()).as_mut() } {
            resolver.on_holder_exit(caller);
        }
        forget_linux_udp_endpoints_for_caller(caller);
        close_linux_tcp_connections_for_caller(ctx.service_generation, caller);
        let (sessions, pending) = ctx.service.on_holder_exit(caller);
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

/// One RDRAND word. `RngCore` cannot report failure, so persistent underflow ends the
/// process through the panic handler (result `ERROR`) instead of spinning.
fn rdrand_word() -> u64 {
    for _ in 0..RDRAND_RETRIES {
        let mut word = 0u64;
        if unsafe { _rdrand64_step(&mut word) } != 0 {
            return word;
        }
    }
    panic!("rdrand exhausted");
}

impl CryptoRng for RdrandRng {}

impl RngCore for RdrandRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        rdrand_word()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            chunk.copy_from_slice(&rdrand_word().to_le_bytes()[..chunk.len()]);
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

/// The kernel blocks `POLL` until the request completes; it only answers `PENDING` when
/// that wait was cancelled, which the fixtures treat as a failure rather than re-polling.
fn poll_until_done(
    handle: u64,
    request_id: u64,
    out_payload: &mut [u8],
) -> Result<NetworkResponse, u64> {
    let mut response_wire = [0u8; NETWORK_RESPONSE_BYTES];
    client_poll(handle, request_id, &mut response_wire, out_payload)?;
    NetworkResponse::decode(&response_wire).map_err(|_| 0u64)
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
    // stale-generation-denial phase.
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

/// Discard port on the fixture peer: nothing is ever sent to it, so nothing comes back.
const INFLIGHT_SILENT_PEER: SocketAddrV4 = SocketAddrV4::new(PEER_IPV4, 9);

/// Leaves exactly one request parked in the service for the kernel to fail at termination.
///
/// The receive waits on a connected UDP endpoint whose peer never sends, so only shutdown
/// can end it. The service takes pending requests lowest slot first and the receive was
/// queued first, so once the follow-up open completes the receive is already parked.
fn run_inflight_arm() -> Result<u64, u64> {
    let handle = client_handle()?;
    let session = open_session(handle, SocketKind::LinuxUdp)?;
    connect_session(handle, session, INFLIGHT_SILENT_PEER)?;
    let receive = NetworkRequest::Receive {
        session,
        max_len: 64,
    }
    .encode();
    let _ = client_submit(handle, &receive, &[])?;
    let _ = open_udp_session(handle)?;
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
