//! The port state machine. Rings and pools are updated in place; nothing large moves by value.
//!
//! Rollback is by ordering: every check runs first, installing a transfer child is the last
//! fallible step of SEND, and the enqueue after it cannot fail.

use clean_slate_capability::{
    CapabilityError, CapabilityHandle, CapabilityTable, HolderId, ResourceClass, ResourceRef,
    Rights,
};
use clean_slate_native_abi::port::{
    PORT_FRAME_BYTES, PORT_MAX_EVENT_QUEUE_DEPTH, PORT_MAX_REQUEST_QUEUE_DEPTH,
    PORT_MAX_TRANSFERS_IN_FLIGHT, PORT_MAX_TRANSFERS_IN_FLIGHT_PER_CONNECTION, PORT_ROLE_CONNECT,
    PORT_ROLE_SERVE,
};
use clean_slate_native_abi::work_set::WORK_SET_BITS;
use clean_slate_native_abi::{
    port_rights_for, ConnectionId, EventKind, PortEventRecord, PortParamError, PortParams,
    PortRecvRecord, PortRights, RecvKind, TransferredCap, TrustedEnvelope,
};

use crate::effects::{Effect, Effects, EFFECTS_CAPACITY};
use crate::transfer::{self, capability_error, Transfer};
use crate::{Caller, PortError, PortKey};

type Frame = [u8; PORT_FRAME_BYTES];

const PLACEHOLDER_CONNECTION: ConnectionId = match ConnectionId::new(0, 1) {
    Ok(id) => id,
    Err(_) => panic!("generation 1 is valid"),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistrationError {
    ClassHasNoPort,
    Params(PortParamError),
    AlreadyRegistered,
    RegistryFull,
    ServerNotLive,
}

/// The server's work set and the bits its requests and notices set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeBinding<B> {
    pub target: B,
    pub request_bit: u32,
    pub notice_bit: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortReleaseCounts {
    pub served_ports: usize,
    pub client_connections: usize,
}

/// Port resources attributed to one holder, as `ResourceSnapshot` counts them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HolderPortCounts {
    pub ports_served: usize,
    /// Connections this holder still holds as client (`Open`, `ServerClosed`, `ServerGone`).
    /// A `ClosePending` connection belongs to the server until it receives the notice.
    pub port_connections: usize,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PortCounts {
    pub ports: usize,
    pub connections: usize,
    pub queued_requests: usize,
    pub queued_events: usize,
    pub undelivered_transfers: usize,
}

#[derive(Clone, Copy)]
struct Request {
    /// 0 marks a free entry.
    seq: u64,
    connection: ConnectionId,
    pid: u64,
    domain: u64,
    generation: u64,
    rights: u32,
    transfer: Option<TransferredCap>,
    frame: Frame,
}

impl Request {
    const EMPTY: Self = Self {
        seq: 0,
        connection: PLACEHOLDER_CONNECTION,
        pid: 0,
        domain: 0,
        generation: 0,
        rights: 0,
        transfer: None,
        frame: [0; PORT_FRAME_BYTES],
    };

    const fn is_live(&self) -> bool {
        self.seq != 0
    }
}

#[derive(Clone, Copy)]
struct Event {
    seq: u64,
    frame: Frame,
}

impl Event {
    const EMPTY: Self = Self {
        seq: 0,
        frame: [0; PORT_FRAME_BYTES],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnState {
    Free,
    Open,
    /// The client closed, exited or lost its capability; the slot is the server's notice.
    ClosePending {
        kind: RecvKind,
        reason: u32,
    },
    /// The server disconnected; queued events stay deliverable before `Disconnected`.
    ServerClosed {
        reason: u32,
    },
    ServerGone,
}

#[derive(Clone, Copy)]
struct Connection {
    /// Bumped on allocation; a `Free` slot at `u32::MAX` is retired.
    generation: u32,
    state: ConnState,
    port: PortKey,
    client: HolderId,
    client_generation: u64,
    client_domain: u64,
    client_cap: CapabilityHandle,
    outstanding: u16,
    transfers_in_flight: u8,
    close_seq: u64,
    event_head: u8,
    event_len: u8,
    events: [Event; PORT_MAX_EVENT_QUEUE_DEPTH],
}

const NO_PORT: PortKey = PortKey {
    slot: 0,
    generation: 0,
};

impl Connection {
    const EMPTY: Self = Self {
        generation: 0,
        state: ConnState::Free,
        port: NO_PORT,
        client: HolderId::KERNEL,
        client_generation: 0,
        client_domain: 0,
        client_cap: CapabilityHandle::INVALID,
        outstanding: 0,
        transfers_in_flight: 0,
        close_seq: 0,
        event_head: 0,
        event_len: 0,
        events: [Event::EMPTY; PORT_MAX_EVENT_QUEUE_DEPTH],
    };

    fn clear_events(&mut self) {
        self.event_head = 0;
        self.event_len = 0;
    }

    fn push_event(&mut self, seq: u64, frame: &Frame) {
        let index = (usize::from(self.event_head) + usize::from(self.event_len))
            % PORT_MAX_EVENT_QUEUE_DEPTH;
        self.events[index].seq = seq;
        self.events[index].frame = *frame;
        self.event_len += 1;
    }

    fn pop_event(&mut self) -> Option<Event> {
        if self.event_len == 0 {
            return None;
        }
        let event = self.events[usize::from(self.event_head)];
        self.event_head = ((usize::from(self.event_head) + 1) % PORT_MAX_EVENT_QUEUE_DEPTH) as u8;
        self.event_len -= 1;
        Some(event)
    }
}

#[derive(Clone, Copy)]
struct Port<B> {
    /// Bumped on registration; a free slot at `u32::MAX` is retired.
    generation: u32,
    live: bool,
    resource: ResourceRef,
    rights: PortRights,
    server: HolderId,
    server_generation: u64,
    params: PortParams,
    next_seq: u64,
    transfers_in_flight: u8,
    wake: Option<WakeBinding<B>>,
    requests: [Request; PORT_MAX_REQUEST_QUEUE_DEPTH],
}

impl<B: Copy> Port<B> {
    const EMPTY: Self = Self {
        generation: 0,
        live: false,
        resource: ResourceRef::graphics(0, 0),
        rights: PortRights {
            connect: Rights::empty(),
            serve: Rights::empty(),
        },
        server: HolderId::KERNEL,
        server_generation: 0,
        params: PortParams {
            event_depth: 0,
            request_depth: 0,
            max_connections: 0,
            max_outstanding: 0,
            max_connections_per_holder: 0,
        },
        next_seq: 0,
        transfers_in_flight: 0,
        wake: None,
        requests: [Request::EMPTY; PORT_MAX_REQUEST_QUEUE_DEPTH],
    };

    fn queued_requests(&self) -> usize {
        self.requests
            .iter()
            .filter(|request| request.is_live())
            .count()
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1).max(1);
        seq
    }
}

/// `PORTS` registry slots and one pool of `CONNS` connections shared by every port.
pub struct PortCore<const PORTS: usize, const CONNS: usize, B> {
    ports: [Port<B>; PORTS],
    connections: [Connection; CONNS],
}

impl<const PORTS: usize, const CONNS: usize, B: Copy + PartialEq> Default
    for PortCore<PORTS, CONNS, B>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const PORTS: usize, const CONNS: usize, B: Copy + PartialEq> PortCore<PORTS, CONNS, B> {
    pub const fn new() -> Self {
        assert!(PORTS > 0 && PORTS <= u8::MAX as usize);
        assert!(CONNS > 0 && CONNS <= u16::MAX as usize);
        assert!(4 * PORTS + CONNS <= EFFECTS_CAPACITY);
        Self {
            ports: [Port::EMPTY; PORTS],
            connections: [Connection::EMPTY; CONNS],
        }
    }

    // ---- registration (launch policy only) ----

    pub fn register(
        &mut self,
        resource: ResourceRef,
        server: HolderId,
        server_generation: u64,
        params: PortParams,
    ) -> Result<PortKey, RegistrationError> {
        let rights = port_rights_for(resource.class).ok_or(RegistrationError::ClassHasNoPort)?;
        params.validate().map_err(RegistrationError::Params)?;
        if self.port_for(resource.class, resource.id).is_some() {
            return Err(RegistrationError::AlreadyRegistered);
        }
        let index = self
            .ports
            .iter()
            .position(|port| !port.live && port.generation != u32::MAX)
            .ok_or(RegistrationError::RegistryFull)?;
        if server == HolderId::KERNEL || server_generation == 0 {
            return Err(RegistrationError::ServerNotLive);
        }
        let port = &mut self.ports[index];
        port.generation += 1;
        port.live = true;
        port.resource = resource;
        port.rights = rights;
        port.server = server;
        port.server_generation = server_generation;
        port.params = params;
        port.next_seq = 1;
        port.transfers_in_flight = 0;
        port.wake = None;
        Ok(self.key(index))
    }

    /// Launch rollback, and server teardown: `ServerGone` for every connection.
    pub fn unregister<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        key: PortKey,
        effects: &mut Effects<B>,
    ) -> bool {
        match self.port_index(key) {
            Some(index) => {
                self.teardown_port(table, index, effects);
                true
            }
            None => false,
        }
    }

    // ---- client operations ----

    /// The caller's live handle on the live port for `(class, id)` carrying the role right.
    pub fn find_handle<const N: usize>(
        &self,
        table: &CapabilityTable<N>,
        caller: Caller,
        class: u64,
        id: u64,
        role: u64,
    ) -> Result<u64, PortError> {
        let (class, rights) = decode_class(class)?;
        let required = match role {
            PORT_ROLE_CONNECT => rights.connect,
            PORT_ROLE_SERVE => rights.serve,
            _ => return Err(PortError::Invalid),
        };
        if !caller.is_process() {
            return Err(PortError::Denied);
        }
        let port = &self.ports[self.port_for(class, id).ok_or(PortError::Refused)?];
        (0..N)
            .filter_map(|slot| table.handle_at(slot))
            .find(|handle| {
                table
                    .authorize(caller.holder, *handle, port.resource, required)
                    .is_ok()
            })
            .map(|handle| handle.encode())
            .ok_or(PortError::Denied)
    }

    /// Check order per plan §2.8; nothing is mutated before the slot is allocated.
    pub fn connect<const N: usize>(
        &mut self,
        table: &CapabilityTable<N>,
        caller: Caller,
        handle: u64,
        class: u64,
        id: u64,
    ) -> Result<ConnectionId, PortError> {
        let (class, rights) = decode_class(class)?;
        if !caller.is_process() {
            return Err(PortError::Denied);
        }
        let handle = CapabilityHandle::decode(handle).map_err(|_| PortError::Invalid)?;
        let record = table.record(handle).map_err(capability_error)?;
        let port_index = self.port_for(class, id).ok_or(PortError::Refused)?;
        let port = &self.ports[port_index];
        if record.resource.class != class || record.resource.id != id {
            return Err(PortError::Denied);
        }
        if record.resource.instance_generation != port.resource.instance_generation {
            return Err(PortError::Stale);
        }
        table
            .authorize(caller.holder, handle, port.resource, rights.connect)
            .map_err(capability_error)?;
        let key = self.key(port_index);
        let bound = |conn: &&Connection| conn.state != ConnState::Free && conn.port == key;
        let per_holder = self
            .connections
            .iter()
            .filter(bound)
            .filter(|conn| conn.client == caller.holder)
            .count();
        if per_holder >= usize::from(port.params.max_connections_per_holder) {
            return Err(PortError::NoSpace);
        }
        if self.connections.iter().filter(bound).count() >= usize::from(port.params.max_connections)
        {
            return Err(PortError::NoSpace);
        }
        let index = self
            .connections
            .iter()
            .position(|conn| conn.state == ConnState::Free && conn.generation != u32::MAX)
            .ok_or(PortError::NoSpace)?;
        let conn = &mut self.connections[index];
        conn.generation += 1;
        conn.state = ConnState::Open;
        conn.port = key;
        conn.client = caller.holder;
        conn.client_generation = caller.generation;
        conn.client_domain = caller.domain;
        conn.client_cap = handle;
        conn.outstanding = 0;
        conn.transfers_in_flight = 0;
        conn.close_seq = 0;
        conn.clear_events();
        Ok(self.connection_id(index))
    }

    /// Check order per plan §2.8. With a transfer, the child install is the last fallible
    /// step; before it, only a revoked client capability changes any state.
    pub fn send<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        caller: Caller,
        connection: u64,
        frame: &Frame,
        transfer: Option<Transfer>,
        effects: &mut Effects<B>,
    ) -> Result<(), PortError> {
        let index = self.client_connection(caller, connection)?;
        match self.connections[index].state {
            ConnState::Open => {}
            ConnState::ServerClosed { .. } => return Err(PortError::PeerClosed),
            ConnState::Free | ConnState::ClosePending { .. } | ConnState::ServerGone => {
                return Err(PortError::Stale)
            }
        }
        let port_index = self.connection_port(index)?;
        let rights = self.reauthorize_client(table, index, port_index, effects)?;

        let conn = &self.connections[index];
        let port = &self.ports[port_index];
        if conn.outstanding >= port.params.max_outstanding
            || port.queued_requests() >= usize::from(port.params.request_depth)
        {
            return Err(PortError::WouldBlock);
        }
        if transfer.is_some()
            && (usize::from(conn.transfers_in_flight)
                >= PORT_MAX_TRANSFERS_IN_FLIGHT_PER_CONNECTION
                || usize::from(port.transfers_in_flight) >= PORT_MAX_TRANSFERS_IN_FLIGHT)
        {
            return Err(PortError::WouldBlock);
        }
        let entry = port
            .requests
            .iter()
            .position(|request| !request.is_live())
            .ok_or(PortError::WouldBlock)?;
        let server = port.server;
        let validated = match &transfer {
            Some(transfer) => Some(transfer::validate(table, caller.holder, transfer)?),
            None => None,
        };
        let child = match validated {
            Some(validated) => Some(transfer::install_child(table, server, &validated)?),
            None => None,
        };

        let id = self.connection_id(index);
        let key = self.key(port_index);
        let port = &mut self.ports[port_index];
        let seq = port.next_seq();
        let request = &mut port.requests[entry];
        request.seq = seq;
        request.connection = id;
        request.pid = caller.holder.0;
        request.domain = caller.domain;
        request.generation = caller.generation;
        request.rights = rights;
        request.transfer = child;
        request.frame = *frame;
        if child.is_some() {
            port.transfers_in_flight += 1;
        }
        let wake = port.wake;
        let conn = &mut self.connections[index];
        conn.outstanding += 1;
        if child.is_some() {
            conn.transfers_in_flight += 1;
        }
        effects.push(Effect::WakeServer(key));
        if let Some(wake) = wake {
            effects.push(Effect::Signal(wake.target, wake.request_bit));
        }
        Ok(())
    }

    pub fn recv_event<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        caller: Caller,
        connection: u64,
        effects: &mut Effects<B>,
    ) -> Result<PortEventRecord, PortError> {
        let index = self.client_connection(caller, connection)?;
        match self.connections[index].state {
            ConnState::Open => {
                if let Some(event) = self.connections[index].pop_event() {
                    return Ok(frame_event(event));
                }
                let port_index = self.connection_port(index)?;
                self.reauthorize_client(table, index, port_index, effects)?;
                Err(PortError::WouldBlock)
            }
            ConnState::ServerClosed { reason } => {
                if let Some(event) = self.connections[index].pop_event() {
                    return Ok(frame_event(event));
                }
                let seq = self.connections[index].close_seq;
                self.consume_terminal(index, effects);
                Ok(terminal_event(EventKind::Disconnected, reason, seq))
            }
            ConnState::ServerGone => {
                let seq = self.connections[index].close_seq;
                self.consume_terminal(index, effects);
                Ok(terminal_event(EventKind::ServerGone, 0, seq))
            }
            ConnState::Free | ConnState::ClosePending { .. } => Err(PortError::Stale),
        }
    }

    pub fn close<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        caller: Caller,
        connection: u64,
        reason: u32,
        effects: &mut Effects<B>,
    ) -> Result<(), PortError> {
        let index = self.client_connection(caller, connection)?;
        match self.connections[index].state {
            ConnState::Open => {
                self.close_pending(table, index, RecvKind::ClientClosed, reason, effects);
                Ok(())
            }
            ConnState::ServerClosed { .. } | ConnState::ServerGone => {
                self.consume_terminal(index, effects);
                Ok(())
            }
            ConnState::Free | ConnState::ClosePending { .. } => Err(PortError::Stale),
        }
    }

    // ---- server operations (serve authorisation per plan §2.9) ----

    pub fn serve_port_key<const N: usize>(
        &self,
        table: &CapabilityTable<N>,
        caller: Caller,
        serve: u64,
    ) -> Result<PortKey, PortError> {
        self.authorize_serve(table, caller, serve)
            .map(|index| self.key(index))
    }

    /// The oldest notice wins over requests; otherwise the lowest-`seq` request (FIFO across
    /// connections). A delivered transfer child now belongs to the server.
    pub fn recv<const N: usize>(
        &mut self,
        table: &CapabilityTable<N>,
        caller: Caller,
        serve: u64,
        effects: &mut Effects<B>,
    ) -> Result<PortRecvRecord, PortError> {
        let port_index = self.authorize_serve(table, caller, serve)?;
        let key = self.key(port_index);
        let notice = self
            .connections
            .iter()
            .enumerate()
            .filter(|(_, conn)| {
                conn.port == key && matches!(conn.state, ConnState::ClosePending { .. })
            })
            .min_by_key(|(_, conn)| conn.close_seq)
            .map(|(index, _)| index);
        if let Some(index) = notice {
            let record = self.notice_record(index);
            self.free_connection(index);
            return Ok(record);
        }
        let port = &mut self.ports[port_index];
        let entry = (0..PORT_MAX_REQUEST_QUEUE_DEPTH)
            .filter(|&entry| port.requests[entry].is_live())
            .min_by_key(|&entry| port.requests[entry].seq)
            .ok_or(PortError::WouldBlock)?;
        let request = port.requests[entry];
        port.requests[entry] = Request::EMPTY;
        if request.transfer.is_some() {
            port.transfers_in_flight = port.transfers_in_flight.saturating_sub(1);
        }
        if let Some(conn) = self
            .connections
            .get_mut(usize::from(request.connection.slot()))
        {
            if conn.generation == request.connection.generation() {
                conn.outstanding = conn.outstanding.saturating_sub(1);
                if request.transfer.is_some() {
                    conn.transfers_in_flight = conn.transfers_in_flight.saturating_sub(1);
                }
            }
        }
        effects.push(Effect::WakeSendSpace(key));
        Ok(PortRecvRecord {
            kind: RecvKind::Request,
            reason: 0,
            envelope: TrustedEnvelope {
                connection: request.connection,
                pid: request.pid,
                domain: request.domain,
                instance_generation: request.generation,
                kernel_seq: request.seq,
                rights: request.rights,
                transfer: request.transfer,
            },
            frame: request.frame,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn post<const N: usize>(
        &mut self,
        table: &CapabilityTable<N>,
        caller: Caller,
        serve: u64,
        connection: u64,
        frame: &Frame,
        effects: &mut Effects<B>,
    ) -> Result<(), PortError> {
        let port_index = self.authorize_serve(table, caller, serve)?;
        let index = self.served_connection(port_index, connection)?;
        let depth = self.ports[port_index].params.event_depth;
        match self.connections[index].state {
            ConnState::Open => {}
            ConnState::ClosePending { .. } => return Err(PortError::PeerClosed),
            ConnState::Free | ConnState::ServerClosed { .. } | ConnState::ServerGone => {
                return Err(PortError::Stale)
            }
        }
        if u16::from(self.connections[index].event_len) >= depth {
            return Err(PortError::WouldBlock);
        }
        let seq = self.ports[port_index].next_seq();
        self.connections[index].push_event(seq, frame);
        effects.push(Effect::WakeConnection(self.connection_id(index)));
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn disconnect<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        caller: Caller,
        serve: u64,
        connection: u64,
        reason: u32,
        effects: &mut Effects<B>,
    ) -> Result<(), PortError> {
        let port_index = self.authorize_serve(table, caller, serve)?;
        let index = self.served_connection(port_index, connection)?;
        match self.connections[index].state {
            ConnState::Open => {}
            ConnState::ClosePending { .. } => return Err(PortError::PeerClosed),
            ConnState::Free | ConnState::ServerClosed { .. } | ConnState::ServerGone => {
                return Err(PortError::Stale)
            }
        }
        self.purge_connection(table, port_index, index);
        let seq = self.ports[port_index].next_seq();
        let conn = &mut self.connections[index];
        conn.close_seq = seq;
        conn.state = ConnState::ServerClosed { reason };
        effects.push(Effect::WakeConnection(self.connection_id(index)));
        effects.push(Effect::WakeSendSpace(self.key(port_index)));
        Ok(())
    }

    /// Replaces any earlier binding and signals at once for each source already pending.
    #[allow(clippy::too_many_arguments)]
    pub fn bind_wake<const N: usize>(
        &mut self,
        table: &CapabilityTable<N>,
        caller: Caller,
        serve: u64,
        target: B,
        request_bit: u32,
        notice_bit: u32,
        effects: &mut Effects<B>,
    ) -> Result<(), PortError> {
        if request_bit >= WORK_SET_BITS || notice_bit >= WORK_SET_BITS {
            return Err(PortError::Invalid);
        }
        let port_index = self.authorize_serve(table, caller, serve)?;
        self.ports[port_index].wake = Some(WakeBinding {
            target,
            request_bit,
            notice_bit,
        });
        if self.ports[port_index].queued_requests() != 0 {
            effects.push(Effect::Signal(target, request_bit));
        }
        let key = self.key(port_index);
        if self
            .connections
            .iter()
            .any(|conn| conn.port == key && matches!(conn.state, ConnState::ClosePending { .. }))
        {
            effects.push(Effect::Signal(target, notice_bit));
        }
        Ok(())
    }

    // ---- teardown and accounting ----

    /// P4 step 1: ports served by `holder` go away (`ServerGone`), then its client connections
    /// become exit notices or are freed.
    pub fn on_holder_exit<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        holder: HolderId,
        effects: &mut Effects<B>,
    ) -> PortReleaseCounts {
        let mut counts = PortReleaseCounts::default();
        for index in 0..PORTS {
            if self.ports[index].live && self.ports[index].server == holder {
                self.teardown_port(table, index, effects);
                counts.served_ports += 1;
            }
        }
        for index in 0..CONNS {
            if self.connections[index].client != holder {
                continue;
            }
            match self.connections[index].state {
                ConnState::Open => {
                    self.close_pending(table, index, RecvKind::ClientExited, 0, effects);
                    counts.client_connections += 1;
                }
                ConnState::ServerClosed { .. } | ConnState::ServerGone => {
                    self.consume_terminal(index, effects);
                    counts.client_connections += 1;
                }
                ConnState::Free | ConnState::ClosePending { .. } => {}
            }
        }
        counts
    }

    pub fn counts_for(&self, holder: HolderId) -> HolderPortCounts {
        HolderPortCounts {
            ports_served: self
                .ports
                .iter()
                .filter(|port| port.live && port.server == holder)
                .count(),
            port_connections: self
                .connections
                .iter()
                .filter(|conn| {
                    conn.client == holder
                        && matches!(
                            conn.state,
                            ConnState::Open
                                | ConnState::ServerClosed { .. }
                                | ConnState::ServerGone
                        )
                })
                .count(),
        }
    }

    pub fn global_counts(&self) -> PortCounts {
        let live_requests = || {
            self.ports
                .iter()
                .filter(|port| port.live)
                .flat_map(|port| port.requests.iter())
                .filter(|request| request.is_live())
        };
        PortCounts {
            ports: self.ports.iter().filter(|port| port.live).count(),
            connections: self
                .connections
                .iter()
                .filter(|conn| conn.state != ConnState::Free)
                .count(),
            queued_requests: live_requests().count(),
            queued_events: self
                .connections
                .iter()
                .map(|conn| usize::from(conn.event_len))
                .sum(),
            undelivered_transfers: live_requests()
                .filter(|request| request.transfer.is_some())
                .count(),
        }
    }

    /// Whether `RECV_EVENT` on `connection` would complete without blocking.
    pub fn event_ready(&self, connection: u64) -> bool {
        match self.connection_index(connection) {
            Ok(index) => {
                let conn = &self.connections[index];
                conn.state != ConnState::Open || conn.event_len != 0
            }
            Err(_) => true,
        }
    }

    /// The port a connection is bound to, for the send-space wait key.
    pub fn connection_port_key(&self, connection: u64) -> Result<PortKey, PortError> {
        self.connection_index(connection)
            .map(|index| self.connections[index].port)
    }

    #[cfg(test)]
    pub(crate) fn set_connection_generation_for_test(&mut self, index: usize, generation: u32) {
        self.connections[index].generation = generation;
    }

    #[cfg(test)]
    pub(crate) fn set_port_generation_for_test(&mut self, index: usize, generation: u32) {
        self.ports[index].generation = generation;
    }

    #[cfg(test)]
    pub(crate) fn undelivered_children_for_test(&self) -> Vec<CapabilityHandle> {
        self.ports
            .iter()
            .flat_map(|port| port.requests.iter())
            .filter(|request| request.is_live())
            .filter_map(|request| request.transfer)
            .filter_map(|cap| CapabilityHandle::decode(cap.handle).ok())
            .collect()
    }

    /// Structural invariants the property test checks after every operation.
    #[cfg(test)]
    pub(crate) fn check_invariants(&self) -> Result<(), String> {
        for (port_index, port) in self.ports.iter().enumerate() {
            if !port.live {
                if port.requests.iter().any(Request::is_live) {
                    return Err(format!("dead port {port_index} holds requests"));
                }
                continue;
            }
            if port.queued_requests() > usize::from(port.params.request_depth) {
                return Err(format!("port {port_index} request pool over depth"));
            }
            let transfers = port
                .requests
                .iter()
                .filter(|request| request.is_live() && request.transfer.is_some())
                .count();
            if transfers != usize::from(port.transfers_in_flight)
                || transfers > PORT_MAX_TRANSFERS_IN_FLIGHT
            {
                return Err(format!("port {port_index} in-flight count {transfers}"));
            }
        }
        for (index, conn) in self.connections.iter().enumerate() {
            if conn.state == ConnState::Free {
                continue;
            }
            let id = self.connection_id(index);
            let requests: Vec<&Request> = self
                .ports
                .iter()
                .flat_map(|port| port.requests.iter())
                .filter(|request| request.is_live() && request.connection == id)
                .collect();
            if !requests.is_empty() && conn.state != ConnState::Open {
                return Err(format!(
                    "connection {index} in {:?} holds requests",
                    conn.state
                ));
            }
            if requests.len() != usize::from(conn.outstanding) {
                return Err(format!("connection {index} outstanding mismatch"));
            }
            let transfers = requests.iter().filter(|r| r.transfer.is_some()).count();
            if transfers != usize::from(conn.transfers_in_flight)
                || transfers > PORT_MAX_TRANSFERS_IN_FLIGHT_PER_CONNECTION
            {
                return Err(format!("connection {index} in-flight mismatch"));
            }
            if let Some(port_index) = self.port_index(conn.port) {
                let params = self.ports[port_index].params;
                if conn.outstanding > params.max_outstanding
                    || u16::from(conn.event_len) > params.event_depth
                {
                    return Err(format!("connection {index} over its limits"));
                }
            } else if !matches!(conn.state, ConnState::ServerGone) {
                return Err(format!("connection {index} bound to a dead port"));
            }
        }
        Ok(())
    }

    // ---- internals ----

    fn key(&self, index: usize) -> PortKey {
        PortKey {
            slot: index as u8,
            generation: self.ports[index].generation,
        }
    }

    fn port_index(&self, key: PortKey) -> Option<usize> {
        let index = usize::from(key.slot);
        let port = self.ports.get(index)?;
        (port.live && port.generation == key.generation).then_some(index)
    }

    fn port_for(&self, class: ResourceClass, id: u64) -> Option<usize> {
        self.ports
            .iter()
            .position(|port| port.live && port.resource.class == class && port.resource.id == id)
    }

    fn connection_id(&self, index: usize) -> ConnectionId {
        // Allocated slots always carry a nonzero generation.
        ConnectionId::new(index as u16, self.connections[index].generation)
            .unwrap_or(PLACEHOLDER_CONNECTION)
    }

    fn connection_index(&self, raw: u64) -> Result<usize, PortError> {
        let id = ConnectionId::decode(raw).map_err(|_| PortError::Invalid)?;
        let index = usize::from(id.slot());
        let conn = self.connections.get(index).ok_or(PortError::Stale)?;
        if conn.state == ConnState::Free || conn.generation != id.generation() {
            return Err(PortError::Stale);
        }
        Ok(index)
    }

    fn client_connection(&self, caller: Caller, raw: u64) -> Result<usize, PortError> {
        if !caller.is_process() {
            return Err(PortError::Denied);
        }
        let index = self.connection_index(raw)?;
        let conn = &self.connections[index];
        if conn.client != caller.holder {
            return Err(PortError::Denied);
        }
        if conn.client_generation != caller.generation {
            return Err(PortError::Stale);
        }
        Ok(index)
    }

    fn served_connection(&self, port_index: usize, raw: u64) -> Result<usize, PortError> {
        let index = self.connection_index(raw)?;
        if self.connections[index].port != self.key(port_index) {
            return Err(PortError::Stale);
        }
        Ok(index)
    }

    fn connection_port(&self, index: usize) -> Result<usize, PortError> {
        self.port_index(self.connections[index].port)
            .ok_or(PortError::Stale)
    }

    fn authorize_serve<const N: usize>(
        &self,
        table: &CapabilityTable<N>,
        caller: Caller,
        serve: u64,
    ) -> Result<usize, PortError> {
        let handle = CapabilityHandle::decode(serve).map_err(|_| PortError::Invalid)?;
        let record = table.record(handle).map_err(capability_error)?;
        let Some(index) = self
            .ports
            .iter()
            .position(|port| port.live && port.resource == record.resource)
        else {
            return Err(
                if self
                    .port_for(record.resource.class, record.resource.id)
                    .is_some()
                {
                    PortError::Stale
                } else {
                    PortError::Denied
                },
            );
        };
        let port = &self.ports[index];
        if !caller.is_process()
            || caller.holder != port.server
            || caller.generation != port.server_generation
        {
            return Err(PortError::Denied);
        }
        table
            .authorize(caller.holder, handle, port.resource, port.rights.serve)
            .map_err(capability_error)?;
        Ok(index)
    }

    /// Re-authorises the client's connect capability; a revoked one closes the connection.
    fn reauthorize_client<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        index: usize,
        port_index: usize,
        effects: &mut Effects<B>,
    ) -> Result<u32, PortError> {
        let conn = &self.connections[index];
        let port = &self.ports[port_index];
        match table.authorize(
            conn.client,
            conn.client_cap,
            port.resource,
            port.rights.connect,
        ) {
            Ok(record) => Ok(record.rights.bits()),
            Err(CapabilityError::Revoked | CapabilityError::StaleHandle) => {
                self.close_pending(table, index, RecvKind::ClientRevoked, 0, effects);
                Err(PortError::Stale)
            }
            Err(_) => Err(PortError::Denied),
        }
    }

    /// Open → `ClosePending`: purge, discard events, notify the server.
    fn close_pending<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        index: usize,
        kind: RecvKind,
        reason: u32,
        effects: &mut Effects<B>,
    ) {
        let Some(port_index) = self.port_index(self.connections[index].port) else {
            return;
        };
        self.purge_connection(table, port_index, index);
        let port = &mut self.ports[port_index];
        let seq = port.next_seq();
        let wake = port.wake;
        let conn = &mut self.connections[index];
        conn.clear_events();
        conn.close_seq = seq;
        conn.state = ConnState::ClosePending { kind, reason };
        let key = self.key(port_index);
        effects.push(Effect::WakeServer(key));
        if let Some(wake) = wake {
            effects.push(Effect::Signal(wake.target, wake.notice_bit));
        }
        effects.push(Effect::WakeSendSpace(key));
        effects.push(Effect::WakeConnection(self.connection_id(index)));
    }

    /// Drops the connection's undelivered requests, revoking and releasing their children.
    fn purge_connection<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        port_index: usize,
        index: usize,
    ) {
        let id = self.connection_id(index);
        let port = &mut self.ports[port_index];
        for request in port.requests.iter_mut() {
            if !request.is_live() || request.connection != id {
                continue;
            }
            if let Some(child) = request.transfer {
                transfer::release_child(table, &child);
                port.transfers_in_flight = port.transfers_in_flight.saturating_sub(1);
            }
            *request = Request::EMPTY;
        }
        let conn = &mut self.connections[index];
        conn.outstanding = 0;
        conn.transfers_in_flight = 0;
    }

    fn teardown_port<const N: usize>(
        &mut self,
        table: &mut CapabilityTable<N>,
        port_index: usize,
        effects: &mut Effects<B>,
    ) {
        let key = self.key(port_index);
        let port = &mut self.ports[port_index];
        for request in port.requests.iter_mut() {
            if let Some(child) = request.transfer.filter(|_| request.is_live()) {
                transfer::release_child(table, &child);
            }
            *request = Request::EMPTY;
        }
        port.transfers_in_flight = 0;
        for index in 0..CONNS {
            if self.connections[index].state == ConnState::Free
                || self.connections[index].port != key
            {
                continue;
            }
            match self.connections[index].state {
                ConnState::Open | ConnState::ServerClosed { .. } => {
                    let seq = self.ports[port_index].next_seq();
                    let conn = &mut self.connections[index];
                    conn.clear_events();
                    conn.outstanding = 0;
                    conn.transfers_in_flight = 0;
                    conn.close_seq = seq;
                    conn.state = ConnState::ServerGone;
                    effects.push(Effect::WakeConnection(self.connection_id(index)));
                }
                ConnState::ClosePending { .. } => self.free_connection(index),
                ConnState::Free | ConnState::ServerGone => {}
            }
        }
        effects.push(Effect::WakeSendSpace(key));
        effects.push(Effect::WakeServer(key));
        let port = &mut self.ports[port_index];
        port.live = false;
        port.wake = None;
        port.server = HolderId::KERNEL;
        port.server_generation = 0;
    }

    /// The client consumed a terminal state (or closed or exited after it): free the slot and
    /// wake any other waiter on it so it sees `ESTALE`.
    fn consume_terminal(&mut self, index: usize, effects: &mut Effects<B>) {
        let id = self.connection_id(index);
        self.free_connection(index);
        effects.push(Effect::WakeConnection(id));
    }

    fn free_connection(&mut self, index: usize) {
        let conn = &mut self.connections[index];
        conn.state = ConnState::Free;
        conn.port = NO_PORT;
        conn.client = HolderId::KERNEL;
        conn.client_generation = 0;
        conn.client_domain = 0;
        conn.client_cap = CapabilityHandle::INVALID;
        conn.outstanding = 0;
        conn.transfers_in_flight = 0;
        conn.close_seq = 0;
        conn.clear_events();
    }

    fn notice_record(&self, index: usize) -> PortRecvRecord {
        let conn = &self.connections[index];
        let (kind, reason) = match conn.state {
            ConnState::ClosePending { kind, reason } => (kind, reason),
            _ => (RecvKind::ClientExited, 0),
        };
        PortRecvRecord {
            kind,
            reason,
            envelope: TrustedEnvelope {
                connection: self.connection_id(index),
                pid: conn.client.0,
                domain: conn.client_domain,
                instance_generation: conn.client_generation,
                kernel_seq: conn.close_seq,
                rights: 0,
                transfer: None,
            },
            frame: [0; PORT_FRAME_BYTES],
        }
    }
}

fn decode_class(raw: u64) -> Result<(ResourceClass, PortRights), PortError> {
    let class = u8::try_from(raw)
        .ok()
        .and_then(ResourceClass::from_u8)
        .ok_or(PortError::Invalid)?;
    let rights = port_rights_for(class).ok_or(PortError::Invalid)?;
    Ok((class, rights))
}

fn frame_event(event: Event) -> PortEventRecord {
    PortEventRecord {
        kind: EventKind::Frame,
        reason: 0,
        kernel_seq: event.seq,
        frame: event.frame,
    }
}

fn terminal_event(kind: EventKind, reason: u32, seq: u64) -> PortEventRecord {
    PortEventRecord {
        kind,
        reason,
        kernel_seq: seq,
        frame: [0; PORT_FRAME_BYTES],
    }
}
