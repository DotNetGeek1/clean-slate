//! Linux socket backend (#105): pool, M7 session brokering, fd read/write.

#![allow(dead_code)]

mod broker;
mod sockaddr;
mod tcp;
mod udp;

use clean_slate_capability::{HolderId, Rights};
use clean_slate_linux_abi::{LinuxErrno, EBADF, EINVAL, SOCK_DGRAM, SOCK_STREAM};
use clean_slate_network::addr::{Ipv4Addr, SocketAddrV4};
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};
use clean_slate_network::session::{SessionId, SocketKind};
use clean_slate_service_fixtures::NETWORK_MAX_PAYLOAD_BYTES;
use clean_slate_service_lifecycle::InstanceGeneration;

use crate::capability::network::{
    authorize_network_op, grant_network_authority, NetworkGrantPolicy,
};
use crate::process::linux_fd::open_description::{OpenDescriptionId, SocketRef};
use crate::process::linux_fd::readiness::{Readiness, ReadinessSource};
use crate::sched::wait::{wake_all, WaitKey};
use crate::sync::global_cell::GlobalCell;

pub(crate) use broker::broker_sync;
pub(crate) use sockaddr::read_sockaddr_in;

/// BusyBox traces use at most three concurrent sockets; eight slots give headroom.
pub(crate) const LINUX_SOCKET_MAX: usize = 8;
pub(crate) const LINUX_UDP_MAX_DATAGRAM: usize = 512;
pub(crate) const LINUX_TCP_CONNECT_TIMEOUT_MS: u64 = 5000;
/// `sched::wait::Deadline` uses APIC timer IRQ ticks (~750/s in QEMU), not milliseconds (#103).
pub(crate) const LINUX_TCP_CONNECT_TIMEOUT_TICKS: u64 =
    LINUX_TCP_CONNECT_TIMEOUT_MS * 750 / 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxSocketId {
    pub(crate) index: u16,
    pub(crate) generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SocketKindLinux {
    Udp,
    Tcp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SocketState {
    Unbound,
    Bound,
    Connecting,
    Connected,
    Closed,
}

#[derive(Clone, Copy)]
struct RxDatagram {
    len: u16,
    bytes: [u8; LINUX_UDP_MAX_DATAGRAM],
}

#[derive(Clone, Copy)]
pub(crate) struct LinuxSocket {
    kind: SocketKindLinux,
    state: SocketState,
    session: SessionId,
    session_generation: u64,
    local: clean_slate_linux_abi::SockaddrIn,
    remote: Option<clean_slate_linux_abi::SockaddrIn>,
    m7_dest: Option<SocketAddrV4>,
    rx_queue: [Option<RxDatagram>; 2],
    rx_head: u8,
    rx_count: u8,
    tcp_rx: [u8; NETWORK_MAX_PAYLOAD_BYTES],
    tcp_rx_len: u16,
    tcp_eof: bool,
    inflight_request_id: Option<u64>,
    owner_pid: u64,
    owner_generation: u32,
    generation: u32,
}

impl LinuxSocket {
    const fn empty() -> Self {
        Self {
            kind: SocketKindLinux::Udp,
            state: SocketState::Closed,
            session: SessionId::from_raw(0),
            session_generation: 0,
            local: clean_slate_linux_abi::SockaddrIn::any_ephemeral(),
            remote: None,
            m7_dest: None,
            rx_queue: [None, None],
            rx_head: 0,
            rx_count: 0,
            tcp_rx: [0; NETWORK_MAX_PAYLOAD_BYTES],
            tcp_rx_len: 0,
            tcp_eof: false,
            inflight_request_id: None,
            owner_pid: 0,
            owner_generation: 0,
            generation: 1,
        }
    }
}

struct SocketPool {
    slots: [LinuxSocket; LINUX_SOCKET_MAX],
}

impl SocketPool {
    const fn new() -> Self {
        Self {
            slots: [LinuxSocket::empty(); LINUX_SOCKET_MAX],
        }
    }

    fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.state != SocketState::Closed)
            .count()
    }
}

static SOCKET_POOL: GlobalCell<SocketPool> = GlobalCell::new(SocketPool::new());
static REQUEST_WAKE_SLOT: GlobalCell<[Option<(u64, WaitKey)>; 16]> = GlobalCell::new([None; 16]);

pub(crate) fn linux_socket_wait_key(id: LinuxSocketId) -> WaitKey {
    WaitKey((0x53u64 << 56) | ((id.index as u64) << 32) | (id.generation as u64))
}

pub(crate) fn pool_live_count() -> usize {
    unsafe { (*SOCKET_POOL.get()).live_count() }
}

pub(crate) fn notify_request_complete(request_id: u64) -> usize {
    let mut woken = 0usize;
    let wakes = unsafe { &mut *REQUEST_WAKE_SLOT.get() };
    for entry in wakes.iter_mut() {
        if entry.map(|(id, _)| id) == Some(request_id) {
            if let Some((_, key)) = *entry {
                woken = wake_all(key);
            }
            *entry = None;
        }
    }
    woken
}

pub(crate) fn register_request_wake(request_id: u64, key: WaitKey) {
    let wakes = unsafe { &mut *REQUEST_WAKE_SLOT.get() };
    for entry in wakes.iter_mut() {
        if entry.map(|(id, _)| id) == Some(request_id) {
            *entry = Some((request_id, key));
            return;
        }
    }
    for entry in wakes.iter_mut() {
        if entry.is_none() {
            *entry = Some((request_id, key));
            return;
        }
    }
}

pub(crate) fn clear_request_wake(request_id: u64) {
    let wakes = unsafe { &mut *REQUEST_WAKE_SLOT.get() };
    for entry in wakes.iter_mut() {
        if entry.map(|(id, _)| id) == Some(request_id) {
            *entry = None;
        }
    }
}

pub(crate) fn grant_linux_network_capabilities(pid: u64) -> Result<(), &'static str> {
    let rights = Rights::NET_CONNECT
        .union(Rights::NET_SEND)
        .union(Rights::NET_RECEIVE);
    grant_network_authority(HolderId(pid), rights, NetworkGrantPolicy::Application, None)
        .map_err(|_| "linux socket network grant failed")?;
    Ok(())
}

fn ipv4_from_sockaddr(sa: &clean_slate_linux_abi::SockaddrIn) -> Ipv4Addr {
    Ipv4Addr::new(sa.addr)
}

fn socket_addr_v4(sa: &clean_slate_linux_abi::SockaddrIn) -> SocketAddrV4 {
    SocketAddrV4::new(ipv4_from_sockaddr(sa), sa.port)
}

pub(crate) fn alloc_socket_for_selftest(
    pid: u64,
    instance_generation: InstanceGeneration,
    kind: SocketKindLinux,
) -> Result<LinuxSocketId, LinuxErrno> {
    alloc_socket(pid, instance_generation, kind)
}

/// After a restart-on-wake syscall, reuse the in-flight socket instead of allocating again.
fn inflight_socket_for_restart(
    pid: u64,
    instance_generation: InstanceGeneration,
    kind: SocketKindLinux,
    state: SocketState,
) -> Option<LinuxSocketId> {
    let pool = unsafe { &*SOCKET_POOL.get() };
    for (index, slot) in pool.slots.iter().enumerate() {
        if slot.owner_pid != pid
            || slot.owner_generation != instance_generation.0
            || slot.kind != kind
            || slot.state != state
            || slot.inflight_request_id.is_none()
        {
            continue;
        }
        return Some(LinuxSocketId {
            index: index as u16,
            generation: slot.generation,
        });
    }
    None
}

fn alloc_socket(
    pid: u64,
    instance_generation: InstanceGeneration,
    kind: SocketKindLinux,
) -> Result<LinuxSocketId, LinuxErrno> {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    let index = pool
        .slots
        .iter()
        .position(|s| s.state == SocketState::Closed)
        .ok_or(clean_slate_linux_abi::ENFILE)?;
    let slot = &mut pool.slots[index];
    let generation = slot.generation;
    *slot = LinuxSocket::empty();
    slot.kind = kind;
    slot.state = SocketState::Unbound;
    slot.owner_pid = pid;
    slot.owner_generation = instance_generation.0;
    slot.generation = generation;
    Ok(LinuxSocketId {
        index: index as u16,
        generation,
    })
}

pub(crate) fn with_socket_mut<R>(
    id: LinuxSocketId,
    f: impl FnOnce(&mut LinuxSocket) -> R,
) -> Result<R, LinuxErrno> {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    let slot = pool
        .slots
        .get_mut(id.index as usize)
        .filter(|s| s.state != SocketState::Closed && s.generation == id.generation)
        .ok_or(EBADF)?;
    Ok(f(slot))
}

pub(crate) fn release_socket(id: LinuxSocketId) {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    if let Some(slot) = pool.slots.get_mut(id.index as usize) {
        if slot.generation == id.generation && slot.state != SocketState::Closed {
            close_m7_session(slot);
            slot.state = SocketState::Closed;
            slot.generation = slot.generation.saturating_add(1);
        }
    }
}

fn close_m7_session(socket: &LinuxSocket) {
    if socket.session.raw() == 0 {
        return;
    }
    let holder = HolderId(socket.owner_pid);
    let Some(handle) = broker::network_client_handle(holder) else {
        return;
    };
    if authorize_network_op(
        holder,
        handle,
        crate::capability::network::NetworkOp::Receive,
        Some(clean_slate_network::session::SessionGeneration::new(
            socket.session_generation,
        )),
    )
    .is_err()
    {
        return;
    }
    let wire = NetworkRequest::Close {
        session: socket.session,
    }
    .encode();
    if let Some(gen) =
        crate::service::instance_generation::live_instance_generation_for_pid(socket.owner_pid)
    {
        let _ = crate::service::net_bridge::net_bridge_mut().submit(
            socket.owner_pid,
            socket.owner_pid,
            u64::from(gen.0),
            &wire,
            &[],
        );
    }
}

pub(crate) fn socket_ref_to_id(socket: SocketRef) -> LinuxSocketId {
    LinuxSocketId {
        index: socket.index,
        generation: socket.generation,
    }
}

pub(crate) fn id_to_socket_ref(id: LinuxSocketId) -> SocketRef {
    SocketRef {
        index: id.index,
        generation: id.generation,
    }
}

pub(crate) mod syscalls {
    use super::*;
    use crate::syscall::linux::block::LinuxTimeoutResult;
    use crate::syscall::linux::table::LinuxSyscallContext;
    use clean_slate_linux_abi::{
        LinuxSyscallRequest, LinuxSyscallResult, AF_INET, AF_INET6, EACCES, EAFNOSUPPORT, EISCONN,
        SOCK_CLOEXEC, SOCK_NONBLOCK,
    };

    pub(crate) fn sys_socket(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        if broker::network_client_handle(HolderId(ctx.pid)).is_none() {
            return Err(EACCES);
        }
        let domain = request.args[0] as u16;
        let sock_type = request.args[1] as u32;
        let _protocol = request.args[2];
        if domain == AF_INET6 {
            return Err(EAFNOSUPPORT);
        }
        if domain != AF_INET {
            return Err(EINVAL);
        }
        let base_type = sock_type & !(SOCK_CLOEXEC | SOCK_NONBLOCK);
        let kind = match base_type {
            SOCK_DGRAM => SocketKindLinux::Udp,
            SOCK_STREAM => SocketKindLinux::Tcp,
            3 => return Err(clean_slate_linux_abi::EPROTONOSUPPORT),
            _ => return Err(EINVAL),
        };
        let id = match inflight_socket_for_restart(
            ctx.pid,
            ctx.instance_generation,
            kind,
            SocketState::Unbound,
        ) {
            Some(id) => id,
            None => alloc_socket(ctx.pid, ctx.instance_generation, kind)?,
        };
        let m7_kind = match kind {
            SocketKindLinux::Udp => SocketKind::Udp,
            SocketKindLinux::Tcp => SocketKind::Tcp,
        };
        with_socket_mut(id, |socket| -> LinuxSyscallResult {
            let outcome = match broker_sync(
                request,
                ctx,
                id,
                &mut socket.inflight_request_id,
                NetworkRequest::Open { kind: m7_kind },
                &[],
                None,
                None,
            ) {
                Ok(outcome) => outcome,
                Err(block_or_err) => return block_or_err,
            };
            let session = match outcome.response {
                NetworkResponse::Open { session } => session,
                _ => return Err(EINVAL),
            };
            socket.session = session;
            socket.session_generation = 1u64;
            socket.state = SocketState::Unbound;
            Ok(0)
        })
        .map_err(|_| EBADF)??;
        let nonblock = (sock_type & SOCK_NONBLOCK) != 0;
        let fd = crate::process::linux_fd::install_socket_fd(
            ctx.pid,
            ctx.instance_generation,
            id_to_socket_ref(id),
            nonblock,
        )?;
        Ok(fd as u64)
    }

    pub(crate) fn sys_bind(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        let fd = request.args[0];
        let addr_ptr = request.args[1];
        let socklen = request.args[2] as u32;
        let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
        let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
        let id = socket_ref_to_id(socket_ref);
        let sa = read_sockaddr_in(addr_ptr, socklen)?;
        with_socket_mut(id, |socket| {
            if socket.kind != SocketKindLinux::Udp {
                return Err(EINVAL);
            }
            socket.local = sa;
            socket.state = SocketState::Bound;
            Ok(0)
        })?
    }

    pub(crate) fn sys_connect(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        let fd = request.args[0];
        let addr_ptr = request.args[1];
        let socklen = request.args[2] as u32;
        let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
        let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
        let id = socket_ref_to_id(socket_ref);
        let sa = read_sockaddr_in(addr_ptr, socklen)?;
        let dest = socket_addr_v4(&sa);
        with_socket_mut(id, |socket| -> LinuxSyscallResult {
            if socket.state == SocketState::Connected {
                return Err(EISCONN);
            }
            socket.remote = Some(sa);
            socket.state = SocketState::Connecting;
            let outcome = match broker_sync(
                request,
                ctx,
                id,
                &mut socket.inflight_request_id,
                NetworkRequest::Connect {
                    session: socket.session,
                    dest,
                },
                &[],
                Some(clean_slate_network::session::SessionGeneration::new(
                    socket.session_generation,
                )),
                Some(LinuxTimeoutResult::Errno(clean_slate_linux_abi::ETIMEDOUT)),
            ) {
                Ok(outcome) => outcome,
                Err(block_or_err) => return block_or_err,
            };
            match outcome.response {
                NetworkResponse::Connect => {
                    socket.state = SocketState::Connected;
                    Ok(0)
                }
                NetworkResponse::Error { code } => tcp::map_network_error(code),
                _ => Err(EINVAL),
            }
        })?
    }

    pub(crate) fn sys_sendto(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        udp::sendto(request, ctx)
    }
}

pub(crate) fn read_socket(
    request: &clean_slate_linux_abi::LinuxSyscallRequest,
    ctx: &mut crate::syscall::linux::table::LinuxSyscallContext<'_>,
    _pid: u64,
    _generation: InstanceGeneration,
    _fd: u64,
    socket_ref: SocketRef,
    scratch: &mut [u8],
) -> clean_slate_linux_abi::LinuxSyscallResult {
    let id = socket_ref_to_id(socket_ref);
    if scratch.is_empty() {
        return Ok(0);
    }
    with_socket_mut(id, |socket| {
        if socket.kind == SocketKindLinux::Udp {
            udp::read_datagram(socket, request, ctx, id, scratch)
        } else {
            tcp::read_stream(socket, request, ctx, id, scratch)
        }
    })?
}

pub(crate) fn write_socket(
    request: &clean_slate_linux_abi::LinuxSyscallRequest,
    ctx: &mut crate::syscall::linux::table::LinuxSyscallContext<'_>,
    _pid: u64,
    _generation: InstanceGeneration,
    _fd: u64,
    socket_ref: SocketRef,
    bytes: &[u8],
) -> clean_slate_linux_abi::LinuxSyscallResult {
    let id = socket_ref_to_id(socket_ref);
    with_socket_mut(id, |socket| {
        if socket.kind == SocketKindLinux::Udp {
            udp::write_datagram(socket, request, ctx, id, bytes)
        } else {
            tcp::write_stream(socket, request, ctx, id, bytes)
        }
    })?
}

/// #103 consumes readiness via `notify_readiness_changed`; lane-local hook only.
/// Self-test: stale M7 session generation must fail closed (`ESTALE`).
#[cfg(feature = "m9-linux-socket-self-test")]
pub(crate) fn selftest_read_stale_session(id: LinuxSocketId) -> LinuxErrno {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    let slot = match pool
        .slots
        .get_mut(id.index as usize)
        .filter(|s| s.state != SocketState::Closed && s.generation == id.generation)
    {
        Some(s) => s,
        None => return EBADF,
    };
    slot.session_generation = slot.session_generation.saturating_sub(1);
    let handle = match broker::network_client_handle(HolderId(slot.owner_pid)) {
        Some(h) => h,
        None => return EBADF,
    };
    if let Err(clean_slate_network::error::DenialReason::StaleGeneration) = authorize_network_op(
        HolderId(slot.owner_pid),
        handle,
        crate::capability::network::NetworkOp::Receive,
        Some(clean_slate_network::session::SessionGeneration::new(
            slot.session_generation,
        )),
    ) {
        return clean_slate_linux_abi::ESTALE;
    }
    clean_slate_linux_abi::EINVAL
}

pub(crate) fn readiness_changed(open: OpenDescriptionId) {
    let _ = open;
    // ORCHESTRATOR: forward to syscall::linux::poll::notify_readiness_changed (#103)
}

pub(crate) fn readiness_for(id: LinuxSocketId) -> Readiness {
    let pool = unsafe { &*SOCKET_POOL.get() };
    let socket = pool
        .slots
        .get(id.index as usize)
        .filter(|s| s.state != SocketState::Closed && s.generation == id.generation);
    match socket {
        Some(socket) => {
            let readable = socket.rx_count > 0 || socket.tcp_rx_len > 0 || socket.tcp_eof;
            let writable =
                socket.state == SocketState::Connected || socket.kind == SocketKindLinux::Udp;
            Readiness {
                readable,
                writable,
                hangup: socket.tcp_eof,
                error: false,
            }
        }
        None => Readiness::default(),
    }
}

pub(crate) struct LinuxSocketReadiness;

impl ReadinessSource for LinuxSocketReadiness {
    fn readiness(&self, id: OpenDescriptionId) -> Readiness {
        let _ = id;
        Readiness::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_pool_exhaustion_bound() {
        let pool = SocketPool::new();
        assert_eq!(pool.slots.len(), LINUX_SOCKET_MAX);
    }
}
