//! The fake kernel's network (#353): syscall 14 hands out the client capability, and syscall 15
//! runs a scripted network service: names it resolves, destinations its policy refuses, TCP
//! peers that answer a request, TLS peers, UDP peers that echo, and peers that connect in to a
//! listener (#359).

extern crate std;

use std::collections::VecDeque;
use std::string::{String, ToString};
use std::vec::Vec;

use clean_slate_native_abi::net::{
    NetAddr, NetResponse, NETWORK_CAPABILITY_VERSION, NETWORK_CLIENT_DEVICE_ID,
    NET_ERROR_ADDRESS_IN_USE, NET_ERROR_CLOSED, NET_ERROR_DESTINATION_DENIED,
    NET_ERROR_INVALID_REQUEST, NET_ERROR_NOT_FOUND, NET_ERROR_RESET, NET_ERROR_STALE_GENERATION,
    NET_ERROR_TIMEOUT, NET_FRAME_BYTES, NET_KIND_ACCEPT, NET_KIND_CLOSE, NET_KIND_CONNECT,
    NET_KIND_LISTEN, NET_KIND_OPEN, NET_KIND_RECEIVE, NET_KIND_RESOLVE, NET_KIND_SEND,
    NET_MAX_PAYLOAD_BYTES, NET_SOCKET_DATAGRAM, NET_SOCKET_STREAM, NET_SOCKET_TLS_EXCHANGE,
    NET_SUBOP_DISCARD, NET_SUBOP_POLL, NET_SUBOP_SUBMIT, NET_SUBOP_WAIT,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_ETIMEDOUT};

/// How a scripted TCP peer behaves.
struct TcpPeer {
    addr: NetAddr,
    /// Sent once the peer has received `after` bytes.
    answer: Vec<u8>,
    after: usize,
    /// Whether the peer closes after answering.
    close: bool,
}

struct Session {
    id: u64,
    kind: u8,
    peer: Option<NetAddr>,
    /// Bytes the client sent, all of them.
    sent: Vec<u8>,
    /// Stream bytes, or datagrams, waiting for a receive.
    inbound: VecDeque<Vec<u8>>,
    peer_closed: bool,
    answered: bool,
    /// The local port a listening stream listens on.
    listening: Option<u16>,
}

impl Session {
    fn new(id: u64, kind: u8) -> Self {
        Self {
            id,
            kind,
            peer: None,
            sent: Vec::new(),
            inbound: VecDeque::new(),
            peer_closed: false,
            answered: false,
            listening: None,
        }
    }
}

/// A peer that connects in to a local port (#359).
struct Incoming {
    port: u16,
    peer: NetAddr,
    bytes: Vec<u8>,
    close: bool,
}

enum Request {
    Done(NetResponse, Vec<u8>),
    Receive { session: u64, max_len: usize },
    Accept { session: u64 },
}

#[derive(Default)]
pub(crate) struct FakeNet {
    handle: Option<u64>,
    /// Bumped by a service restart: sessions of an older one are stale.
    generation: u64,
    names: Vec<(String, [u8; 4])>,
    may_resolve: bool,
    denied: Vec<NetAddr>,
    tcp: Vec<TcpPeer>,
    tls: Vec<(NetAddr, Vec<u8>)>,
    udp_echo: Vec<NetAddr>,
    sessions: Vec<Session>,
    requests: Vec<(u64, Request)>,
    next_request: u64,
    next_session: u64,
    refusals: Vec<Option<NetAddr>>,
    listen_denied: Vec<u16>,
    incoming: VecDeque<Incoming>,
    /// What closed sessions sent, and to whom.
    closed_sent: Vec<(NetAddr, Vec<u8>)>,
}

fn session_of(frame: &[u8; NET_FRAME_BYTES]) -> u64 {
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&frame[8..16]);
    u64::from_le_bytes(raw)
}

fn word(frame: &[u8; NET_FRAME_BYTES], at: usize) -> u32 {
    u32::from_le_bytes([frame[at], frame[at + 1], frame[at + 2], frame[at + 3]])
}

fn error(code: u16) -> Request {
    Request::Done(NetResponse::Error { code }, Vec::new())
}

impl FakeNet {
    pub(crate) fn grant(&mut self, handle: u64) {
        self.handle = Some(handle);
        self.may_resolve = true;
        self.generation = self.generation.max(1);
    }

    pub(crate) fn name(&mut self, name: &str, ip: [u8; 4]) {
        self.names.push((name.to_string(), ip));
    }

    pub(crate) fn forbid_resolve(&mut self) {
        self.may_resolve = false;
    }

    pub(crate) fn deny(&mut self, addr: NetAddr) {
        self.denied.push(addr);
    }

    pub(crate) fn tcp_peer(&mut self, addr: NetAddr, after: usize, answer: &[u8], close: bool) {
        self.tcp.push(TcpPeer {
            addr,
            answer: answer.to_vec(),
            after,
            close,
        });
    }

    pub(crate) fn tls_peer(&mut self, addr: NetAddr, answer: &[u8]) {
        self.tls.push((addr, answer.to_vec()));
    }

    pub(crate) fn udp_echo(&mut self, addr: NetAddr) {
        self.udp_echo.push(addr);
    }

    /// Bytes `addr` sends on every stream connected to it.
    pub(crate) fn push(&mut self, addr: NetAddr, bytes: &[u8]) {
        for session in self
            .sessions
            .iter_mut()
            .filter(|s| s.peer == Some(addr) && s.kind == NET_SOCKET_STREAM)
        {
            session.inbound.push_back(bytes.to_vec());
        }
    }

    pub(crate) fn forbid_listen(&mut self, port: u16) {
        self.listen_denied.push(port);
    }

    pub(crate) fn connect_in(&mut self, port: u16, peer: NetAddr, bytes: &[u8], close: bool) {
        self.incoming.push_back(Incoming {
            port,
            peer,
            bytes: bytes.to_vec(),
            close,
        });
    }

    /// The service restarts: open sessions are stale and the client capability changes.
    pub(crate) fn restart(&mut self, new_handle: u64) {
        self.generation += 1;
        self.handle = Some(new_handle);
        let stale: Vec<u64> = self.sessions.iter().map(|s| s.id).collect();
        for (_, request) in &mut self.requests {
            if let Request::Receive { session, .. } | Request::Accept { session } = request {
                if stale.contains(session) {
                    *request = error(NET_ERROR_RESET);
                }
            }
        }
    }

    /// Everything sent to `addr`, on closed sessions first.
    pub(crate) fn sent_to(&self, addr: NetAddr) -> Vec<u8> {
        let closed = self
            .closed_sent
            .iter()
            .filter(|(peer, _)| *peer == addr)
            .flat_map(|(_, sent)| sent.iter().copied());
        let open = self
            .sessions
            .iter()
            .filter(|s| s.peer == Some(addr))
            .flat_map(|s| s.sent.iter().copied());
        closed.chain(open).collect()
    }

    pub(crate) fn open_sessions(&self) -> usize {
        self.sessions.len()
    }

    pub(crate) fn outstanding_requests(&self) -> usize {
        self.requests.len()
    }

    pub(crate) fn refusals(&self) -> &[Option<NetAddr>] {
        &self.refusals
    }

    pub(crate) fn capability_call(&mut self, args: [u64; 6]) -> u64 {
        if args[0] != NETWORK_CLIENT_DEVICE_ID || args[1] != u64::from(NETWORK_CAPABILITY_VERSION) {
            return STATUS_EINVAL;
        }
        self.handle.unwrap_or(STATUS_EACCES)
    }

    pub(crate) fn request_call(&mut self, args: [u64; 6]) -> u64 {
        if Some(args[1]) != self.handle {
            return STATUS_EACCES;
        }
        match args[0] {
            NET_SUBOP_SUBMIT => {
                // SAFETY: the client passes a live frame and `args[4]` live payload bytes.
                let frame: [u8; NET_FRAME_BYTES] =
                    unsafe { *(args[2] as *const [u8; NET_FRAME_BYTES]) };
                if args[4] as usize > NET_MAX_PAYLOAD_BYTES {
                    return STATUS_EINVAL;
                }
                let payload = if args[4] == 0 {
                    Vec::new()
                } else {
                    unsafe { std::slice::from_raw_parts(args[3] as *const u8, args[4] as usize) }
                        .to_vec()
                };
                let request = self.serve(&frame, &payload);
                self.next_request += 1;
                self.requests.push((self.next_request, request));
                self.next_request
            }
            NET_SUBOP_WAIT => {
                self.advance();
                match self.requests.iter().find(|(id, _)| *id == args[2]) {
                    None => STATUS_EINVAL,
                    Some((_, Request::Done(..))) => 0,
                    // The fake has no time: an unanswered request reaches any deadline at once.
                    Some((_, Request::Receive { .. } | Request::Accept { .. })) => STATUS_ETIMEDOUT,
                }
            }
            NET_SUBOP_POLL => {
                self.advance();
                let Some(index) = self.requests.iter().position(|(id, _)| *id == args[2]) else {
                    return STATUS_EINVAL;
                };
                let Request::Done(_, payload) = &self.requests[index].1 else {
                    // The real kernel blocks here; a fake test that polls early is wrong.
                    panic!("polled a request that has not completed");
                };
                if payload.len() > args[5] as usize {
                    return STATUS_EINVAL;
                }
                let (_, Request::Done(response, payload)) = self.requests.remove(index) else {
                    unreachable!();
                };
                // SAFETY: the client passes a live frame and `args[5]` writable bytes.
                unsafe {
                    *(args[3] as *mut [u8; NET_FRAME_BYTES]) = response.encode();
                    std::ptr::copy_nonoverlapping(
                        payload.as_ptr(),
                        args[4] as *mut u8,
                        payload.len(),
                    );
                }
                0
            }
            NET_SUBOP_DISCARD => {
                let before = self.requests.len();
                self.requests.retain(|(id, _)| *id != args[2]);
                if self.requests.len() == before {
                    STATUS_EINVAL
                } else {
                    0
                }
            }
            _ => STATUS_EINVAL,
        }
    }

    /// Completes receives that have something to return, and accepts with a peer waiting.
    fn advance(&mut self) {
        for index in 0..self.requests.len() {
            if let Request::Accept { session } = self.requests[index].1 {
                self.requests[index].1 = match self.sessions.iter().find(|s| s.id == session) {
                    None => error(NET_ERROR_RESET),
                    Some(listener) => match self.take_incoming(listener.listening) {
                        Some(done) => done,
                        None => continue,
                    },
                };
                continue;
            }
            let Request::Receive { session, max_len } = self.requests[index].1 else {
                continue;
            };
            let Some(s) = self.sessions.iter_mut().find(|s| s.id == session) else {
                self.requests[index].1 = error(NET_ERROR_RESET);
                continue;
            };
            if let Some(mut bytes) = s.inbound.pop_front() {
                if bytes.len() > max_len {
                    let rest = bytes.split_off(max_len);
                    if s.kind == NET_SOCKET_STREAM {
                        s.inbound.push_front(rest);
                    }
                }
                let len = bytes.len() as u32;
                self.requests[index].1 = Request::Done(NetResponse::Receive { len }, bytes);
            } else if s.peer_closed {
                self.requests[index].1 = Request::Done(NetResponse::Receive { len: 0 }, Vec::new());
            }
        }
    }

    /// The oldest peer connecting in to `port`, as a new stream session.
    fn take_incoming(&mut self, port: Option<u16>) -> Option<Request> {
        let at = self.incoming.iter().position(|i| Some(i.port) == port)?;
        let incoming = self.incoming.remove(at)?;
        self.next_session += 1;
        let id = (self.generation << 32) | self.next_session;
        let mut session = Session::new(id, NET_SOCKET_STREAM);
        session.peer = Some(incoming.peer);
        if !incoming.bytes.is_empty() {
            session.inbound.push_back(incoming.bytes);
        }
        if incoming.close && session.inbound.is_empty() {
            // It sent nothing: it gave up and closes at once.
            session.peer_closed = true;
        } else if incoming.close {
            // It closes its side once it has had as many bytes back as it sent: an echo client.
            self.tcp.push(TcpPeer {
                addr: incoming.peer,
                answer: Vec::new(),
                after: session.inbound.iter().map(Vec::len).sum(),
                close: true,
            });
        }
        self.sessions.push(session);
        Some(Request::Done(
            NetResponse::Accept {
                session: id,
                peer: incoming.peer,
            },
            Vec::new(),
        ))
    }

    fn refuse(&mut self, addr: Option<NetAddr>) -> Request {
        self.refusals.push(addr);
        error(NET_ERROR_DESTINATION_DENIED)
    }

    fn serve(&mut self, frame: &[u8; NET_FRAME_BYTES], payload: &[u8]) -> Request {
        let generation = self.generation;
        let session_id = session_of(frame);
        let stale = frame[6] != NET_KIND_RESOLVE
            && frame[6] != NET_KIND_OPEN
            && session_id >> 32 != generation;
        if stale {
            return error(NET_ERROR_STALE_GENERATION);
        }
        let index = self.sessions.iter().position(|s| s.id == session_id);
        match frame[6] {
            NET_KIND_RESOLVE => {
                if !self.may_resolve {
                    return self.refuse(None);
                }
                let name = &frame[9..9 + usize::from(frame[8]).min(55)];
                match self.names.iter().find(|(n, _)| n.as_bytes() == name) {
                    Some(&(_, ip)) => {
                        Request::Done(NetResponse::Resolve { ip, ttl: 300 }, Vec::new())
                    }
                    None => error(NET_ERROR_NOT_FOUND),
                }
            }
            NET_KIND_OPEN => {
                let kind = frame[8];
                if ![
                    NET_SOCKET_STREAM,
                    NET_SOCKET_DATAGRAM,
                    NET_SOCKET_TLS_EXCHANGE,
                ]
                .contains(&kind)
                {
                    return error(NET_ERROR_INVALID_REQUEST);
                }
                self.next_session += 1;
                let id = (generation << 32) | self.next_session;
                self.sessions.push(Session::new(id, kind));
                Request::Done(NetResponse::Open { session: id }, Vec::new())
            }
            NET_KIND_LISTEN => {
                let Some(index) = index else {
                    return error(NET_ERROR_INVALID_REQUEST);
                };
                let port = u16::from_le_bytes([frame[16], frame[17]]);
                let session = &self.sessions[index];
                if session.kind != NET_SOCKET_STREAM
                    || session.peer.is_some()
                    || session.listening.is_some()
                    || port == 0
                {
                    return error(NET_ERROR_INVALID_REQUEST);
                }
                if self.listen_denied.contains(&port) {
                    return self.refuse(Some(NetAddr::new([0; 4], port)));
                }
                if self.sessions.iter().any(|s| s.listening == Some(port)) {
                    return error(NET_ERROR_ADDRESS_IN_USE);
                }
                self.sessions[index].listening = Some(port);
                Request::Done(NetResponse::Listen, Vec::new())
            }
            NET_KIND_ACCEPT => match index {
                Some(index) if self.sessions[index].listening.is_some() => Request::Accept {
                    session: session_id,
                },
                _ => error(NET_ERROR_INVALID_REQUEST),
            },
            NET_KIND_CONNECT => {
                let Some(index) = index else {
                    return error(NET_ERROR_INVALID_REQUEST);
                };
                let addr = NetAddr::new(
                    [frame[16], frame[17], frame[18], frame[19]],
                    u16::from_le_bytes([frame[20], frame[21]]),
                );
                if self.denied.contains(&addr) {
                    return self.refuse(Some(addr));
                }
                let kind = self.sessions[index].kind;
                let reachable = match kind {
                    NET_SOCKET_STREAM => self.tcp.iter().any(|p| p.addr == addr),
                    NET_SOCKET_DATAGRAM | NET_SOCKET_TLS_EXCHANGE => true,
                    _ => false,
                };
                if !reachable {
                    return error(NET_ERROR_TIMEOUT);
                }
                self.sessions[index].peer = Some(addr);
                Request::Done(NetResponse::Connect, Vec::new())
            }
            NET_KIND_SEND => {
                let Some(index) = index else {
                    return error(NET_ERROR_INVALID_REQUEST);
                };
                if word(frame, 16) as usize != payload.len() {
                    return error(NET_ERROR_INVALID_REQUEST);
                }
                let session = &mut self.sessions[index];
                let Some(peer) = session.peer else {
                    return error(NET_ERROR_INVALID_REQUEST);
                };
                if session.peer_closed && session.kind == NET_SOCKET_STREAM {
                    return error(NET_ERROR_CLOSED);
                }
                session.sent.extend_from_slice(payload);
                match session.kind {
                    NET_SOCKET_STREAM => {
                        if let Some(p) = self.tcp.iter().find(|p| p.addr == peer) {
                            if !session.answered && session.sent.len() >= p.after {
                                session.answered = true;
                                if !p.answer.is_empty() {
                                    session.inbound.push_back(p.answer.clone());
                                }
                                session.peer_closed = p.close;
                            }
                        }
                    }
                    NET_SOCKET_DATAGRAM => {
                        if self.udp_echo.contains(&peer) {
                            session.inbound.push_back(payload.to_vec());
                        }
                    }
                    _ => match self.tls.iter().find(|(addr, _)| *addr == peer) {
                        Some((_, answer)) => session.inbound.push_back(answer.clone()),
                        None => return error(NET_ERROR_TIMEOUT),
                    },
                }
                Request::Done(
                    NetResponse::Send {
                        accepted: payload.len() as u32,
                    },
                    Vec::new(),
                )
            }
            NET_KIND_RECEIVE => {
                if index.is_none() {
                    return error(NET_ERROR_INVALID_REQUEST);
                }
                let max_len = (word(frame, 16) as usize).min(NET_MAX_PAYLOAD_BYTES);
                Request::Receive {
                    session: session_id,
                    max_len,
                }
            }
            NET_KIND_CLOSE => {
                let Some(index) = index else {
                    return error(NET_ERROR_INVALID_REQUEST);
                };
                let closed = self.sessions.remove(index);
                if let Some(peer) = closed.peer {
                    self.closed_sent.push((peer, closed.sent));
                }
                for (_, request) in &mut self.requests {
                    if matches!(request, Request::Receive { session, .. } | Request::Accept { session } if *session == session_id)
                    {
                        *request = error(NET_ERROR_RESET);
                    }
                }
                Request::Done(NetResponse::Close, Vec::new())
            }
            _ => error(NET_ERROR_INVALID_REQUEST),
        }
    }
}
