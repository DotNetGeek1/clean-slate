//! M7.3 userspace network service state machine (host-testable, `no_std`-friendly).

use clean_slate_network::addr::SocketAddrV4;
use clean_slate_network::device::{LinkProperties, NetworkLink};
use clean_slate_network::error::{DenialReason, NetworkError};
use clean_slate_network::limits::{
    MAX_APPLICATION_PAYLOAD_BYTES, MAX_PENDING_REQUESTS_PER_SESSION, MAX_SESSIONS,
};
use clean_slate_network::protocol::{
    NetworkRequest, NetworkRequestKind, NetworkResponse, TrustedCaller,
};
use clean_slate_network::session::{SessionGeneration, SessionId, SessionState, SocketKind};

/// Operation surface for capability authorization (#87 implements against this).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkOp {
    Resolve,
    Open,
    Connect,
    Send,
    Receive,
    Close,
    RawDevice,
}

pub trait NetworkAuthorizer {
    fn authorize(&self, caller: &TrustedCaller, op: NetworkOp) -> Result<(), DenialReason>;
}

pub struct AllowAllAuthorizer;

impl NetworkAuthorizer for AllowAllAuthorizer {
    fn authorize(&self, _caller: &TrustedCaller, _op: NetworkOp) -> Result<(), DenialReason> {
        Ok(())
    }
}

pub struct DenyAllAuthorizer;

impl NetworkAuthorizer for DenyAllAuthorizer {
    fn authorize(&self, _caller: &TrustedCaller, _op: NetworkOp) -> Result<(), DenialReason> {
        Err(DenialReason::NoCapability)
    }
}

#[derive(Clone, Copy)]
struct PendingSlot {
    active: bool,
    request_id: u64,
    kind: NetworkRequestKind,
}

impl PendingSlot {
    const fn empty() -> Self {
        Self {
            active: false,
            request_id: 0,
            kind: NetworkRequestKind::Open,
        }
    }
}

#[derive(Clone, Copy)]
struct SessionEntry {
    in_use: bool,
    owner: TrustedCaller,
    kind: SocketKind,
    state: SessionState,
    connected_dest: Option<SocketAddrV4>,
    staged_len: u32,
    staged_payload: [u8; MAX_APPLICATION_PAYLOAD_BYTES],
    pending: [PendingSlot; MAX_PENDING_REQUESTS_PER_SESSION as usize],
    pending_count: u32,
}

impl SessionEntry {
    const fn empty() -> Self {
        Self {
            in_use: false,
            owner: TrustedCaller::new(0, 0, 0),
            kind: SocketKind::Udp,
            state: SessionState::Closed,
            connected_dest: None,
            staged_len: 0,
            staged_payload: [0; MAX_APPLICATION_PAYLOAD_BYTES],
            pending: [PendingSlot::empty(); MAX_PENDING_REQUESTS_PER_SESSION as usize],
            pending_count: 0,
        }
    }
}

pub struct NetworkService<L, A> {
    generation: SessionGeneration,
    sessions: [SessionEntry; MAX_SESSIONS as usize],
    next_session_index: u32,
    total_pending: u32,
    authorizer: A,
    link: Option<L>,
}

impl<L, A> NetworkService<L, A>
where
    A: NetworkAuthorizer,
{
    pub fn new(generation: SessionGeneration, authorizer: A) -> Self {
        Self {
            generation,
            sessions: [SessionEntry::empty(); MAX_SESSIONS as usize],
            next_session_index: 0,
            total_pending: 0,
            authorizer,
            link: None,
        }
    }

    pub const fn generation(&self) -> SessionGeneration {
        self.generation
    }

    pub fn attach_backend(&mut self, link: L) {
        self.link = Some(link);
    }

    pub fn detach_backend(&mut self) -> Option<L> {
        self.link.take()
    }

    pub fn sessions_in_use(&self) -> u32 {
        self.sessions.iter().filter(|s| s.in_use).count() as u32
    }

    pub fn pending_requests(&self) -> u32 {
        self.total_pending
    }

    pub fn link_properties(&self) -> Option<LinkProperties>
    where
        L: NetworkLink,
    {
        self.link.as_ref().map(NetworkLink::link)
    }

    fn error_response(error: NetworkError) -> NetworkResponse {
        NetworkResponse::Error { code: error.code() }
    }

    fn op_for_request(request: &NetworkRequest) -> NetworkOp {
        match request {
            NetworkRequest::Resolve { .. } => NetworkOp::Resolve,
            NetworkRequest::Open { .. } => NetworkOp::Open,
            NetworkRequest::Connect { .. } => NetworkOp::Connect,
            NetworkRequest::Send { .. } => NetworkOp::Send,
            NetworkRequest::Receive { .. } => NetworkOp::Receive,
            NetworkRequest::Close { .. } => NetworkOp::Close,
        }
    }

    fn validate_session(
        &self,
        caller: &TrustedCaller,
        session: SessionId,
    ) -> Result<usize, NetworkResponse> {
        if !session.matches_generation(self.generation) {
            return Err(Self::error_response(NetworkError::Denied(
                DenialReason::StaleGeneration,
            )));
        }
        let index = session.index() as usize;
        if index >= MAX_SESSIONS as usize {
            return Err(Self::error_response(NetworkError::InvalidRequest));
        }
        let entry = &self.sessions[index];
        if !entry.in_use {
            return Err(Self::error_response(NetworkError::Closed));
        }
        if entry.owner != *caller {
            return Err(Self::error_response(NetworkError::Denied(
                DenialReason::NoCapability,
            )));
        }
        Ok(index)
    }

    fn alloc_session(
        &mut self,
        caller: TrustedCaller,
        kind: SocketKind,
    ) -> Result<SessionId, NetworkResponse> {
        if self.sessions_in_use() >= MAX_SESSIONS {
            return Err(Self::error_response(NetworkError::SessionExhausted));
        }
        let index = self.next_session_index as usize;
        for offset in 0..MAX_SESSIONS as usize {
            let slot = (index + offset) % MAX_SESSIONS as usize;
            if !self.sessions[slot].in_use {
                self.sessions[slot] = SessionEntry {
                    in_use: true,
                    owner: caller,
                    kind,
                    state: SessionState::Open,
                    connected_dest: None,
                    staged_len: 0,
                    staged_payload: [0; MAX_APPLICATION_PAYLOAD_BYTES],
                    pending: [PendingSlot::empty(); MAX_PENDING_REQUESTS_PER_SESSION as usize],
                    pending_count: 0,
                };
                self.next_session_index = ((slot as u32) + 1) % MAX_SESSIONS;
                return Ok(SessionId::new(self.generation, slot as u32));
            }
        }
        Err(Self::error_response(NetworkError::SessionExhausted))
    }

    pub(crate) fn push_pending(
        &mut self,
        session_index: usize,
        request_id: u64,
        kind: NetworkRequestKind,
    ) -> Result<(), NetworkResponse> {
        let entry = &mut self.sessions[session_index];
        if entry.pending_count >= MAX_PENDING_REQUESTS_PER_SESSION {
            return Err(Self::error_response(NetworkError::QueueFull));
        }
        for slot in &mut entry.pending {
            if !slot.active {
                slot.active = true;
                slot.request_id = request_id;
                slot.kind = kind;
                entry.pending_count += 1;
                self.total_pending += 1;
                return Ok(());
            }
        }
        Err(Self::error_response(NetworkError::QueueFull))
    }

    fn pop_pending(&mut self, session_index: usize, request_id: u64) {
        let entry = &mut self.sessions[session_index];
        for slot in &mut entry.pending {
            if slot.active && slot.request_id == request_id {
                slot.active = false;
                entry.pending_count = entry.pending_count.saturating_sub(1);
                self.total_pending = self.total_pending.saturating_sub(1);
                return;
            }
        }
    }

    fn clear_session(&mut self, session_index: usize) {
        let entry = &mut self.sessions[session_index];
        if entry.in_use {
            self.total_pending = self.total_pending.saturating_sub(entry.pending_count);
        }
        *entry = SessionEntry::empty();
    }

    fn stage_session_payload(
        &mut self,
        session_index: usize,
        payload: &[u8],
    ) -> Result<(), NetworkResponse> {
        if payload.len() > MAX_APPLICATION_PAYLOAD_BYTES {
            return Err(Self::error_response(NetworkError::InvalidRequest));
        }
        let entry = &mut self.sessions[session_index];
        entry.staged_payload[..payload.len()].copy_from_slice(payload);
        entry.staged_len = payload.len() as u32;
        Ok(())
    }

    pub fn session_kind(
        &self,
        caller: TrustedCaller,
        session: SessionId,
    ) -> Result<SocketKind, NetworkResponse> {
        let index = self.validate_session(&caller, session)?;
        Ok(self.sessions[index].kind)
    }

    pub fn connected_dest(
        &self,
        caller: TrustedCaller,
        session: SessionId,
    ) -> Result<Option<SocketAddrV4>, NetworkResponse> {
        let index = self.validate_session(&caller, session)?;
        Ok(self.sessions[index].connected_dest)
    }

    pub fn stage_response_payload(
        &mut self,
        caller: TrustedCaller,
        session: SessionId,
        payload: &[u8],
    ) -> Result<(), NetworkResponse> {
        let index = self.validate_session(&caller, session)?;
        self.stage_session_payload(index, payload)
    }

    pub fn take_staged_payload(
        &mut self,
        caller: TrustedCaller,
        session: SessionId,
        out: &mut [u8],
    ) -> Result<Option<u32>, NetworkResponse> {
        let index = self.validate_session(&caller, session)?;
        let entry = &mut self.sessions[index];
        if entry.staged_len == 0 {
            return Ok(None);
        }
        let len = (entry.staged_len as usize)
            .min(out.len())
            .min(MAX_APPLICATION_PAYLOAD_BYTES);
        out[..len].copy_from_slice(&entry.staged_payload[..len]);
        entry.staged_len = 0;
        Ok(Some(len as u32))
    }

    pub fn handle_request(
        &mut self,
        caller: TrustedCaller,
        request: NetworkRequest,
        payload: &[u8],
        response_payload: &mut [u8],
    ) -> (NetworkResponse, u32)
    where
        L: NetworkLink,
    {
        let op = Self::op_for_request(&request);
        if let Err(reason) = self.authorizer.authorize(&caller, op) {
            return (Self::error_response(NetworkError::Denied(reason)), 0);
        }

        match request {
            NetworkRequest::Resolve { .. } => (Self::error_response(NetworkError::NotFound), 0),
            NetworkRequest::Open { kind } => match self.alloc_session(caller, kind) {
                Ok(session) => (NetworkResponse::Open { session }, 0),
                Err(response) => (response, 0),
            },
            NetworkRequest::Close { session } => {
                let index = match self.validate_session(&caller, session) {
                    Ok(index) => index,
                    Err(response) => return (response, 0),
                };
                self.clear_session(index);
                (NetworkResponse::Close, 0)
            }
            NetworkRequest::Connect { session, dest } => {
                let index = match self.validate_session(&caller, session) {
                    Ok(index) => index,
                    Err(response) => return (response, 0),
                };
                self.sessions[index].connected_dest = Some(dest);
                self.sessions[index].state = SessionState::Open;
                (NetworkResponse::Connect, 0)
            }
            NetworkRequest::Send {
                session,
                payload_len,
            } => {
                if payload.len() != payload_len as usize
                    || payload.len() > MAX_APPLICATION_PAYLOAD_BYTES
                {
                    return (Self::error_response(NetworkError::InvalidRequest), 0);
                }
                let index = match self.validate_session(&caller, session) {
                    Ok(index) => index,
                    Err(response) => return (response, 0),
                };
                if self
                    .push_pending(index, 0, NetworkRequestKind::Send)
                    .is_err()
                {
                    return (Self::error_response(NetworkError::QueueFull), 0);
                }
                let result = self.stage_session_payload(index, payload);
                self.pop_pending(index, 0);
                match result {
                    Ok(()) => (
                        NetworkResponse::Send {
                            bytes_sent: payload_len,
                        },
                        0,
                    ),
                    Err(response) => (response, 0),
                }
            }
            NetworkRequest::Receive { session, max_len } => {
                let index = match self.validate_session(&caller, session) {
                    Ok(index) => index,
                    Err(response) => return (response, 0),
                };
                if self
                    .push_pending(index, 0, NetworkRequestKind::Receive)
                    .is_err()
                {
                    return (Self::error_response(NetworkError::QueueFull), 0);
                }
                let result = {
                    let entry = &mut self.sessions[index];
                    let max_len = max_len as usize;
                    if max_len > MAX_APPLICATION_PAYLOAD_BYTES || max_len > response_payload.len() {
                        Err(NetworkError::InvalidRequest)
                    } else {
                        let len = (entry.staged_len as usize).min(max_len);
                        response_payload[..len].copy_from_slice(&entry.staged_payload[..len]);
                        entry.staged_len = 0;
                        Ok(len as u32)
                    }
                };
                self.pop_pending(index, 0);
                match result {
                    Ok(len) => (NetworkResponse::Receive { payload_len: len }, len),
                    Err(error) => (Self::error_response(error), 0),
                }
            }
        }
    }

    pub fn on_holder_exit(&mut self, caller: TrustedCaller) -> (u32, u32) {
        let mut reclaimed_sessions = 0u32;
        for (index, entry) in self.sessions.iter_mut().enumerate() {
            if entry.in_use && entry.owner == caller {
                reclaimed_sessions += 1;
                self.total_pending = self.total_pending.saturating_sub(entry.pending_count);
                *entry = SessionEntry::empty();
                let _ = index;
            }
        }
        (reclaimed_sessions, 0)
    }

    pub fn shutdown(mut self) -> L
    where
        L: NetworkLink,
    {
        for entry in &mut self.sessions {
            if entry.in_use {
                entry.state = SessionState::Failed;
                entry.pending_count = 0;
                for slot in &mut entry.pending {
                    slot.active = false;
                }
            }
            entry.in_use = false;
        }
        self.total_pending = 0;
        let mut link = self
            .link
            .take()
            .expect("shutdown requires an attached backend");
        let _ = link.reset();
        link
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_network::addr::MacAddr;
    use clean_slate_network::device::DeviceState;
    use clean_slate_network::fake::FakeLink;

    fn caller(pid: u64) -> TrustedCaller {
        TrustedCaller::new(pid, 1, 1)
    }

    fn test_mac() -> MacAddr {
        MacAddr([0x02, 0, 0, 0, 0, 1])
    }

    fn service_with_link(
        generation: u64,
        link: FakeLink,
    ) -> NetworkService<FakeLink, AllowAllAuthorizer> {
        let mut service =
            NetworkService::new(SessionGeneration::new(generation), AllowAllAuthorizer);
        service.attach_backend(link);
        service
    }

    #[test]
    fn open_close_round_trip() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = [0u8; MAX_APPLICATION_PAYLOAD_BYTES];
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let (close, _) =
            service.handle_request(caller(1), NetworkRequest::Close { session }, &[], &mut out);
        assert!(matches!(close, NetworkResponse::Close));
        assert_eq!(service.sessions_in_use(), 0);
    }

    fn mut_buf() -> [u8; MAX_APPLICATION_PAYLOAD_BYTES] {
        [0u8; MAX_APPLICATION_PAYLOAD_BYTES]
    }

    #[test]
    fn session_exhaustion() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        for _ in 0..MAX_SESSIONS {
            let (resp, _) = service.handle_request(
                caller(1),
                NetworkRequest::Open {
                    kind: SocketKind::Udp,
                },
                &[],
                &mut out,
            );
            assert!(matches!(resp, NetworkResponse::Open { .. }));
        }
        let (resp, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::SessionExhausted.code()
        ));
    }

    #[test]
    fn pending_queue_exhaustion() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let index = session.index() as usize;
        for id in 0..MAX_PENDING_REQUESTS_PER_SESSION {
            assert!(service
                .push_pending(index, id as u64, NetworkRequestKind::Send)
                .is_ok());
        }
        let (resp, _) = service.handle_request(
            caller(1),
            NetworkRequest::Send {
                session,
                payload_len: 1,
            },
            &[0xAA],
            &mut out,
        );
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::QueueFull.code()
        ));
    }

    #[test]
    fn wrong_owner_denied() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let (resp, _) =
            service.handle_request(caller(2), NetworkRequest::Close { session }, &[], &mut out);
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::Denied(DenialReason::NoCapability).code()
        ));
    }

    #[test]
    fn stale_generation_denied() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let stale = SessionId::new(SessionGeneration::new(0), 0);
        let (resp, _) = service.handle_request(
            caller(1),
            NetworkRequest::Close { session: stale },
            &[],
            &mut out,
        );
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::Denied(DenialReason::StaleGeneration).code()
        ));
    }

    #[test]
    fn deny_all_authorizer() {
        let mut service = NetworkService::new(SessionGeneration::new(1), DenyAllAuthorizer);
        service.attach_backend(FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (resp, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::Denied(DenialReason::NoCapability).code()
        ));
    }

    #[test]
    fn oversized_payload_rejected() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let payload = vec![0xAB; MAX_APPLICATION_PAYLOAD_BYTES + 1];
        let (resp, _) = service.handle_request(
            caller(1),
            NetworkRequest::Send {
                session,
                payload_len: (MAX_APPLICATION_PAYLOAD_BYTES + 1) as u32,
            },
            &payload,
            &mut out,
        );
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::InvalidRequest.code()
        ));
    }

    #[test]
    fn holder_exit_reclaims_capacity() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let _session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        assert_eq!(service.sessions_in_use(), 1);
        let (reclaimed, pending) = service.on_holder_exit(caller(1));
        assert_eq!((reclaimed, pending), (1, 0));
        assert_eq!(service.sessions_in_use(), 0);
    }

    #[test]
    fn shutdown_returns_reset_backend() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let index = session.index() as usize;
        let _ = service.push_pending(index, 1, NetworkRequestKind::Send);
        assert_eq!(service.pending_requests(), 1);
        let link = service.shutdown();
        assert_eq!(link.state(), DeviceState::Ready);
    }

    #[test]
    fn replacement_service_rejects_old_sessions() {
        let mut old = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = old.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let old_session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let _ = old.shutdown();
        let mut new_service = service_with_link(2, FakeLink::new(test_mac(), true));
        let (resp, _) = new_service.handle_request(
            caller(1),
            NetworkRequest::Close {
                session: old_session,
            },
            &[],
            &mut out,
        );
        assert!(matches!(
            resp,
            NetworkResponse::Error {
                code: c
            } if c == NetworkError::Denied(DenialReason::StaleGeneration).code()
        ));
    }

    #[test]
    fn application_send_receive_stays_out_of_raw_link() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        let (open, _) = service.handle_request(
            caller(1),
            NetworkRequest::Open {
                kind: SocketKind::Udp,
            },
            &[],
            &mut out,
        );
        let session = match open {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let msg = b"hello-net";
        let (send, _) = service.handle_request(
            caller(1),
            NetworkRequest::Send {
                session,
                payload_len: msg.len() as u32,
            },
            msg,
            &mut out,
        );
        assert!(matches!(send, NetworkResponse::Send { bytes_sent: 9 }));
        let (recv, len) = service.handle_request(
            caller(1),
            NetworkRequest::Receive {
                session,
                max_len: 64,
            },
            &[],
            &mut out,
        );
        let payload_len = match recv {
            NetworkResponse::Receive { payload_len } => payload_len,
            _ => panic!("expected receive"),
        };
        assert_eq!(payload_len, len);
        assert_eq!(len as usize, msg.len());
        assert_eq!(&out[..len as usize], msg);
        assert_eq!(service.link.as_ref().expect("backend").tx_depth(), 0);
    }

    #[test]
    fn capacity_loop_never_exhausts() {
        let mut service = service_with_link(1, FakeLink::new(test_mac(), true));
        let mut out = mut_buf();
        for _ in 0..(MAX_SESSIONS * 4) {
            let (open, _) = service.handle_request(
                caller(1),
                NetworkRequest::Open {
                    kind: SocketKind::Udp,
                },
                &[],
                &mut out,
            );
            let session = match open {
                NetworkResponse::Open { session } => session,
                _ => panic!("expected open"),
            };
            let _ =
                service.handle_request(caller(1), NetworkRequest::Close { session }, &[], &mut out);
            service.on_holder_exit(caller(1));
        }
        assert_eq!(service.sessions_in_use(), 0);
        assert_eq!(service.pending_requests(), 0);
    }
}
