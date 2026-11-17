//! Linux socket backend (#105): pool, M7 session brokering, fd read/write.

#![allow(dead_code)]

mod broker;
mod sockaddr;
mod tcp;
mod udp;

use clean_slate_capability::{HolderId, Rights};
use clean_slate_linux_abi::{LinuxErrno, EBADF, EINVAL, EIO, SOCK_DGRAM, SOCK_STREAM};
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
    rx_dropped: u8,
    tcp_rx: [u8; NETWORK_MAX_PAYLOAD_BYTES],
    tcp_rx_len: u16,
    tcp_eof: bool,
    inflight_request_id: Option<u64>,
    /// Outstanding prefetch `Receive` (see `udp` and `tcp`): lets `poll(2)` observe
    /// datagrams and stream bytes without a reader blocked in the service.
    pending_rx_req: Option<u64>,
    /// Receive failure reported by the service, returned once to the next reader.
    rx_error: Option<LinuxErrno>,
    /// Set when the network instance behind the socket went away: every later call on the
    /// socket fails with it until the socket is closed (see [`on_network_instance_gone`]).
    lost: Option<LinuxErrno>,
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
            rx_dropped: 0,
            tcp_rx: [0; NETWORK_MAX_PAYLOAD_BYTES],
            tcp_rx_len: 0,
            tcp_eof: false,
            inflight_request_id: None,
            pending_rx_req: None,
            rx_error: None,
            lost: None,
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

pub(crate) fn linux_socket_wait_key(id: LinuxSocketId) -> WaitKey {
    WaitKey((0x53u64 << 56) | ((id.index as u64) << 32) | (id.generation as u64))
}

/// One wait key per in-flight M7 bridge request (#105). Socket-scoped keys let an
/// earlier completion (e.g. Open) leave a pending wake that the next syscall
/// (Connect) consumes before its reply exists.
pub(crate) fn linux_socket_request_wait_key(request_id: u64) -> WaitKey {
    crate::service::net_request_wake::net_bridge_request_wait_key(request_id)
}

pub(crate) fn pool_live_count() -> usize {
    unsafe { (*SOCKET_POOL.get()).live_count() }
}

/// Live `kind` sockets with a prefetch `Receive` outstanding in the service.
#[cfg_attr(not(feature = "m9-userspace-self-test"), allow(dead_code))]
pub(crate) fn outstanding_prefetches(kind: SocketKindLinux) -> usize {
    let pool = unsafe { &*SOCKET_POOL.get() };
    pool.slots
        .iter()
        .filter(|slot| {
            slot.state != SocketState::Closed && slot.kind == kind && slot.pending_rx_req.is_some()
        })
        .count()
}

pub(super) fn socket_with_pending_receive(
    kind: SocketKindLinux,
    request_id: u64,
) -> Option<LinuxSocketId> {
    let pool = unsafe { &*SOCKET_POOL.get() };
    pool.slots
        .iter()
        .enumerate()
        .find(|(_, slot)| {
            slot.state != SocketState::Closed
                && slot.kind == kind
                && slot.pending_rx_req == Some(request_id)
        })
        .map(|(index, slot)| LinuxSocketId {
            index: index as u16,
            generation: slot.generation,
        })
}

/// `service_complete` hook: wakes the broker waiter for `request_id`, or delivers a UDP or
/// TCP prefetch into its socket and wakes that socket's readers and `poll(2)` waiters.
pub(crate) fn deliver_prefetch_receive(request_id: u64) -> usize {
    let mut woken = crate::service::net_request_wake::notify_net_request_complete(request_id);
    let delivered = udp::deliver_completed_prefetch(request_id)
        .or_else(|| tcp::deliver_completed_prefetch(request_id));
    if let Some((id, owner_pid)) = delivered {
        woken = woken
            .saturating_add(wake_all(linux_socket_wait_key(id)))
            .saturating_add(crate::syscall::linux::poll::wake_poll_waiters_for_pid(
                owner_pid,
            ));
    }
    woken
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

/// The open socket `id` names, or `EBADF`; a socket whose network instance is gone yields
/// its lost errno instead, so no call reaches the replacement instance.
fn usable_slot(pool: &mut SocketPool, id: LinuxSocketId) -> Result<&mut LinuxSocket, LinuxErrno> {
    let slot = pool
        .slots
        .get_mut(id.index as usize)
        .filter(|s| s.state != SocketState::Closed && s.generation == id.generation)
        .ok_or(EBADF)?;
    match slot.lost {
        Some(errno) => Err(errno),
        None => Ok(slot),
    }
}

pub(crate) fn with_socket_mut<R>(
    id: LinuxSocketId,
    f: impl FnOnce(&mut LinuxSocket) -> R,
) -> Result<R, LinuxErrno> {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    Ok(f(usable_slot(pool, id)?))
}

/// What a socket's calls return once its network instance is gone: a stream was reset by
/// its peer; a datagram socket has no peer to blame, so its calls fail with an I/O error.
const fn lost_errno(kind: SocketKindLinux) -> LinuxErrno {
    match kind {
        SocketKindLinux::Tcp => clean_slate_linux_abi::ECONNRESET,
        SocketKindLinux::Udp => EIO,
    }
}

/// Who must be woken after a socket was marked lost.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct LostSocketWake {
    /// Blocked readers wait on [`linux_socket_wait_key`].
    socket_key: WaitKey,
    /// Broker waiters wait on [`linux_socket_request_wait_key`] of these requests.
    requests: [Option<u64>; 2],
    /// `poll(2)` waiters wait on the owner's poll key.
    owner_pid: u64,
}

/// Marks `socket` lost and takes its outstanding bridge requests. A socket whose `Open` never
/// completed has no fd yet, so it is closed outright: the restarted `socket(2)` then starts
/// afresh instead of finding it. Returns `None` for a closed or already lost socket.
fn mark_lost(socket: &mut LinuxSocket, id: LinuxSocketId) -> Option<LostSocketWake> {
    if socket.state == SocketState::Closed || socket.lost.is_some() {
        return None;
    }
    let wake = LostSocketWake {
        socket_key: linux_socket_wait_key(id),
        requests: [
            socket.pending_rx_req.take(),
            socket.inflight_request_id.take(),
        ],
        owner_pid: socket.owner_pid,
    };
    socket.rx_error = None;
    if socket.session.raw() == 0 {
        socket.state = SocketState::Closed;
        socket.generation = socket.generation.saturating_add(1);
    } else {
        socket.lost = Some(lost_errno(socket.kind));
    }
    Some(wake)
}

/// #218 S7: the network instance behind every open socket went away (terminated, exited or
/// faulted). Sockets are not rebound to a replacement: each open one fails its later calls
/// with [`lost_errno`] until it is closed. Their bridge requests are dropped, and blocked readers,
/// broker waiters and `poll(2)` waiters are woken; a woken socket syscall restarts from its
/// entry and fails there. Returns the number of sockets marked lost.
pub(crate) fn on_network_instance_gone() -> usize {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    let mut lost = 0usize;
    for (index, slot) in pool.slots.iter_mut().enumerate() {
        let id = LinuxSocketId {
            index: index as u16,
            generation: slot.generation,
        };
        let Some(wake) = mark_lost(slot, id) else {
            continue;
        };
        lost += 1;
        let bridge = crate::service::net_bridge::net_bridge_mut();
        for request_id in wake.requests.into_iter().flatten() {
            bridge.drop_request_for_lost_instance(
                slot.owner_pid,
                slot.owner_pid,
                u64::from(slot.owner_generation),
                request_id,
            );
            wake_all(linux_socket_request_wait_key(request_id));
        }
        wake_all(wake.socket_key);
        crate::syscall::linux::poll::wake_poll_waiters_for_pid(wake.owner_pid);
    }
    if lost > 0 {
        crate::diagnostics::log::kernel_log_fmt(format_args!(
            "[NET ] linux sockets lost count={} reason=instance-gone\n",
            lost
        ));
    }
    lost
}

pub(crate) fn release_socket(id: LinuxSocketId) {
    let pool = unsafe { &mut *SOCKET_POOL.get() };
    if let Some(slot) = pool.slots.get_mut(id.index as usize) {
        if slot.generation == id.generation && slot.state != SocketState::Closed {
            if slot.lost.is_none() {
                abandon_outstanding_requests(slot);
                close_m7_session(slot);
            }
            slot.state = SocketState::Closed;
            wake_all(linux_socket_wait_key(id));
            slot.generation = slot.generation.saturating_add(1);
        }
    }
}

/// The socket is going away: nobody will poll its outstanding bridge requests.
fn abandon_outstanding_requests(socket: &mut LinuxSocket) {
    let generation = u64::from(socket.owner_generation);
    for request_id in [
        socket.pending_rx_req.take(),
        socket.inflight_request_id.take(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = crate::service::net_bridge::net_bridge_mut().discard_result(
            socket.owner_pid,
            socket.owner_pid,
            generation,
            request_id,
        );
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
        let bridge = crate::service::net_bridge::net_bridge_mut();
        if let Ok(request_id) = bridge.submit(
            socket.owner_pid,
            socket.owner_pid,
            u64::from(gen.0),
            &wire,
            &[],
        ) {
            let _ = bridge.discard_result(
                socket.owner_pid,
                socket.owner_pid,
                u64::from(gen.0),
                request_id,
            );
        }
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
            crate::service::net_bridge::log_network_denied(ctx.pid);
            #[cfg(feature = "m9-userspace-self-test")]
            crate::selftest::m9_userspace::observe_network_denial();
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
            SocketKindLinux::Udp => SocketKind::LinuxUdp,
            SocketKindLinux::Tcp => SocketKind::LinuxTcp,
        };
        let opened = with_socket_mut(id, |socket| -> LinuxSyscallResult {
            let outcome = match broker_sync(
                request,
                ctx,
                id,
                &mut socket.inflight_request_id,
                NetworkRequest::Open { kind: m7_kind },
                &[],
                &mut [],
                None,
                None,
            ) {
                Ok(outcome) => outcome,
                Err(block_or_err) => return block_or_err,
            };
            let session = match outcome.response {
                NetworkResponse::Open { session } => session,
                _ => return Err(EIO),
            };
            socket.session = session;
            socket.session_generation = session.generation().get();
            socket.state = SocketState::Unbound;
            Ok(0)
        })
        .map_err(|_| EBADF)?;
        if let Err(errno) = opened {
            release_socket(id);
            return Err(errno);
        }
        let fd = crate::process::linux_fd::install_socket_fd(
            ctx.pid,
            ctx.instance_generation,
            id_to_socket_ref(id),
            (sock_type & SOCK_NONBLOCK) != 0,
            (sock_type & SOCK_CLOEXEC) != 0,
        )
        .inspect_err(|_| release_socket(id))?;
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
                &mut [],
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
                NetworkResponse::Error { code } => tcp::map_connect_error(code),
                _ => Err(EINVAL),
            }
        })?
    }

    pub(crate) fn sys_sendto(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        let fd = request.args[0];
        let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
        let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
        let id = socket_ref_to_id(socket_ref);
        let kind = with_socket_mut(id, |socket| socket.kind)?;
        match kind {
            SocketKindLinux::Tcp => tcp::sendto(request, ctx),
            SocketKindLinux::Udp => udp::sendto(request, ctx),
        }
    }

    pub(crate) fn sys_recvmsg(
        request: &LinuxSyscallRequest,
        ctx: &mut LinuxSyscallContext<'_>,
    ) -> LinuxSyscallResult {
        let fd = request.args[0];
        let nonblock = super::socket_recv_nonblock(ctx, fd, request.args[2])?;
        udp::recvmsg(request, ctx, nonblock)
    }
}

pub(super) fn socket_recv_nonblock(
    ctx: &crate::syscall::linux::table::LinuxSyscallContext<'_>,
    fd: u64,
    msg_flags: u64,
) -> Result<bool, clean_slate_linux_abi::LinuxErrno> {
    let status =
        crate::process::linux_fd::open_description_status(ctx.pid, ctx.instance_generation, fd)?;
    Ok(status.nonblock || (msg_flags & u64::from(clean_slate_linux_abi::MSG_DONTWAIT)) != 0)
}

pub(crate) fn refresh_readiness_for_fd(
    ctx: &mut crate::syscall::linux::table::LinuxSyscallContext<'_>,
    fd: u64,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    use crate::process::linux_fd::open_description::DescriptorKind;
    let open =
        crate::process::linux_fd::open_description_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
    let kind =
        crate::process::linux_fd::open_description_kind(ctx.pid, ctx.instance_generation, fd)?;
    if !matches!(kind, DescriptorKind::Socket(_)) {
        return Ok(());
    }
    let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
    let id = socket_ref_to_id(socket_ref);
    let changed = match with_socket_mut(id, |socket| socket.kind)? {
        SocketKindLinux::Udp => udp::refresh_receive(id)?,
        SocketKindLinux::Tcp => tcp::refresh_receive(id)?,
    };
    if changed {
        crate::syscall::linux::poll::notify_readiness_changed(open);
    }
    Ok(())
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
    let nonblock = socket_recv_nonblock(ctx, _fd, 0)?;
    match with_socket_mut(id, |socket| socket.kind)? {
        SocketKindLinux::Udp => udp::read_datagram(id, request, ctx, scratch, nonblock),
        SocketKindLinux::Tcp => with_socket_mut(id, |socket| {
            tcp::read_stream(socket, request, ctx, id, _fd, scratch)
        })?,
    }
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
    crate::syscall::linux::poll::notify_readiness_changed(open);
}

pub(crate) fn readiness_for(id: LinuxSocketId) -> Readiness {
    let pool = unsafe { &*SOCKET_POOL.get() };
    let socket = pool
        .slots
        .get(id.index as usize)
        .filter(|s| s.state != SocketState::Closed && s.generation == id.generation);
    socket.map(socket_readiness).unwrap_or_default()
}

/// A lost socket is readable and writable (each call returns its error at once), reports
/// `POLLERR`, and a lost stream also reports `POLLHUP`.
fn socket_readiness(socket: &LinuxSocket) -> Readiness {
    if socket.lost.is_some() {
        return Readiness {
            readable: true,
            writable: true,
            hangup: socket.kind == SocketKindLinux::Tcp,
            error: true,
        };
    }
    let stream_error = socket.kind == SocketKindLinux::Tcp && socket.rx_error.is_some();
    let readable = socket.rx_count > 0 || socket.tcp_rx_len > 0 || socket.tcp_eof || stream_error;
    let writable = socket.state == SocketState::Connected || socket.kind == SocketKindLinux::Udp;
    Readiness {
        readable,
        writable,
        hangup: socket.tcp_eof,
        error: false,
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

    const OWNER: u64 = 4;

    /// A pool whose slot 2 is an opened `kind` socket with a prefetch (request 5) and a
    /// broker request (request 6) outstanding, like a reader blocked in `read(2)` or a
    /// `poll(2)` waiter with the prefetch armed.
    fn pool_with_open_socket(kind: SocketKindLinux) -> (SocketPool, LinuxSocketId) {
        use clean_slate_network::session::SessionGeneration;
        let mut pool = SocketPool::new();
        let slot = &mut pool.slots[2];
        slot.kind = kind;
        slot.state = SocketState::Connected;
        slot.session = SessionId::new(SessionGeneration::new(1), 3);
        slot.session_generation = 1;
        slot.pending_rx_req = Some(5);
        slot.inflight_request_id = Some(6);
        slot.owner_pid = OWNER;
        slot.owner_generation = 1;
        let id = LinuxSocketId {
            index: 2,
            generation: slot.generation,
        };
        (pool, id)
    }

    #[test]
    fn a_lost_stream_fails_with_connection_reset_and_wakes_every_waiter() {
        let (mut pool, id) = pool_with_open_socket(SocketKindLinux::Tcp);
        let wake = mark_lost(&mut pool.slots[2], id).expect("open socket is marked");
        assert_eq!(
            wake,
            LostSocketWake {
                socket_key: linux_socket_wait_key(id),
                requests: [Some(5), Some(6)],
                owner_pid: OWNER,
            }
        );
        assert_eq!(
            usable_slot(&mut pool, id).err(),
            Some(clean_slate_linux_abi::ECONNRESET)
        );
        assert_eq!(
            socket_readiness(&pool.slots[2]),
            Readiness {
                readable: true,
                writable: true,
                hangup: true,
                error: true,
            }
        );
        let slot = &pool.slots[2];
        assert_eq!(slot.pending_rx_req, None);
        assert_eq!(slot.inflight_request_id, None);
        // Still open: only `close` releases it, and it is never handed to a new instance.
        assert_ne!(slot.state, SocketState::Closed);
    }

    #[test]
    fn a_lost_datagram_socket_fails_with_an_io_error_and_is_marked_once() {
        let (mut pool, id) = pool_with_open_socket(SocketKindLinux::Udp);
        pool.slots[2].rx_error = Some(clean_slate_linux_abi::EAGAIN);
        assert!(mark_lost(&mut pool.slots[2], id).is_some());
        assert_eq!(usable_slot(&mut pool, id).err(), Some(EIO));
        assert_eq!(
            socket_readiness(&pool.slots[2]),
            Readiness {
                readable: true,
                writable: true,
                hangup: false,
                error: true,
            }
        );
        assert_eq!(pool.slots[2].rx_error, None);
        assert_eq!(mark_lost(&mut pool.slots[2], id), None);
    }

    #[test]
    fn a_socket_lost_before_its_open_completed_is_closed() {
        let (mut pool, id) = pool_with_open_socket(SocketKindLinux::Udp);
        pool.slots[2].session = SessionId::from_raw(0);
        pool.slots[2].state = SocketState::Unbound;
        pool.slots[2].pending_rx_req = None;
        let wake = mark_lost(&mut pool.slots[2], id).expect("half-open socket is marked");
        assert_eq!(wake.requests, [None, Some(6)]);
        assert_eq!(pool.slots[2].state, SocketState::Closed);
        assert_eq!(usable_slot(&mut pool, id).err(), Some(EBADF));
        assert_eq!(pool.live_count(), 0);
    }

    #[test]
    fn closed_sockets_are_not_marked_and_open_ones_stay_usable() {
        let (mut pool, id) = pool_with_open_socket(SocketKindLinux::Tcp);
        let closed = LinuxSocketId {
            index: 0,
            generation: pool.slots[0].generation,
        };
        assert_eq!(mark_lost(&mut pool.slots[0], closed), None);
        assert!(usable_slot(&mut pool, id).is_ok());
        assert!(!socket_readiness(&pool.slots[2]).error);
    }
}
