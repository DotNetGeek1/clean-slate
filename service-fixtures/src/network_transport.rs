//! Bounded network-service IPC subops and bootstrap metadata (M7.3).

use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};

pub const NETWORK_UNAUTHORIZED_PROBE_SERVICE_ID_VALUE: u32 = 0x0000_5201;
/// The client-facing half of the transport is the native network ABI (#353).
pub use clean_slate_native_abi::net::{
    NETWORK_CAPABILITY_VERSION, NETWORK_CLIENT_DEVICE_ID, NETWORK_DEVICE_ID, NET_SUBOP_DISCARD,
    NET_SUBOP_POLL, NET_SUBOP_SUBMIT, NET_SUBOP_WAIT,
};

pub const NETWORK_STATUS_PENDING: u64 = 0xFFFF_FFFF_FFFF_FFF0;

pub const NETWORK_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0020_0000;
/// Byte offset of the [`NetworkServiceLaunch`] block inside the bootstrap page.
pub const NETWORK_SERVICE_LAUNCH_OFFSET: u64 = 1024;
/// User address of the [`NetworkServiceLaunch`] block.
pub const NETWORK_SERVICE_LAUNCH_ADDRESS: u64 =
    NETWORK_SERVICE_BOOTSTRAP_ADDRESS + NETWORK_SERVICE_LAUNCH_OFFSET;
/// User address of the service's trust anchors: a `clean_slate_network::config::TrustAnchors`
/// store on [`NETWORK_SERVICE_TRUST_PAGES`] read-only pages of their own (#221), clear of the
/// bootstrap page and the stack above it.
pub const NETWORK_SERVICE_TRUST_ADDRESS: u64 = 0x0000_4000_0030_0000;
pub const NETWORK_SERVICE_TRUST_PAGES: usize = clean_slate_network::config::TRUST_STORE_PAGES;

pub const NETWORK_SERVICE_MODE_ACCEPTANCE: u64 = 1;
pub const NETWORK_SERVICE_MODE_UNAUTHORIZED_PROBE: u64 = 2;
pub const NETWORK_SERVICE_MODE_CLIENT: u64 = 3;
pub const NETWORK_SERVICE_MODE_INFLIGHT_ARM: u64 = 4;
pub const NETWORK_SERVICE_MODE_STALE_CLOSE: u64 = 5;
pub const NETWORK_SERVICE_MODE_CAPACITY_LOOP: u64 = 6;
pub const NETWORK_SERVICE_MODE_CONVERGED_CLIENT: u64 = 7;

pub const NETWORK_SERVICE_RESULT_PENDING: u64 = 0;
pub const NETWORK_SERVICE_RESULT_OK: u64 = 1;
pub const NETWORK_SERVICE_RESULT_ERROR: u64 = 2;
/// #221: `aux_status` of an acceptance-mode service that failed closed before it was ready
/// because it could not seed its CSPRNG. The low byte is the
/// `clean_slate_network::rng::SeedError` code.
pub const NETWORK_SERVICE_AUX_NO_ENTROPY: u64 = 0x4e45_0000;
pub const NETWORK_SERVICE_AUX_NO_ENTROPY_REASON_MASK: u64 = 0xff;
/// #221: `aux_status` of an acceptance-mode service whose launch block (network
/// configuration or trust anchors) did not check out; it stopped before it was ready.
pub const NETWORK_SERVICE_AUX_BAD_LAUNCH: u64 = 0x4e4c_0000;

pub const NET_SUBOP_SERVICE_NEXT: u64 = 3;
pub const NET_SUBOP_SERVICE_COMPLETE: u64 = 4;
pub const NET_SUBOP_RAW_GEOMETRY: u64 = 5;
pub const NET_SUBOP_RAW_TRANSMIT: u64 = 6;
pub const NET_SUBOP_RAW_RECEIVE: u64 = 7;
pub const NET_SUBOP_POP_HOLDER_EXIT: u64 = 8;
pub const NET_SUBOP_ACK_HOLDER_EXIT: u64 = 9;
/// Returns calibrated TSC time in whole [`NET_SUBOP_TICK_PERIOD_NS`] periods (EINVAL if
/// the TSC is uncalibrated). Not a count of delivered IRQs.
pub const NET_SUBOP_MONOTONIC_TICKS: u64 = 10;
/// Returns LAPIC IRQ period in nanoseconds (0 if uncalibrated).
pub const NET_SUBOP_TICK_PERIOD_NS: u64 = 11;
/// Net-service idle block (#167): `rsi` = raw-device handle, `rdx` = non-empty subset of
/// [`NET_WAIT_WORK_MASK`], `r10` = relative timeout in ns (0 = no timeout, requires a
/// calibrated TSC otherwise). Returns 0 when a selected source is already ready, else the
/// #145 native wait outcome after blocking (woken / timed out / cancelled); callers re-check
/// state either way. Errors: `EINVAL` (bad mask, TSC uncalibrated), `EACCES`, `ESTALE`.
pub const NET_SUBOP_WAIT_WORK: u64 = 12;
/// The live service reports a per-app policy refusal (#221 stage E) for the audit log:
/// `rsi` = raw-device handle, `rdx` = the refused caller's pid, `r10` = its instance
/// generation, `r8` = the `clean_slate_capability::NetDestination` encoding, `r9` = the
/// rights the request needed (a non-empty subset of `NET_RESOLVE | NET_CONNECT | NET_SEND`).
/// The kernel records it against the caller, who must be a holder the service is serving.
/// Allowed decisions are not reported: the kernel already records each client's use of its
/// capability. Returns 0, or `EINVAL` / `EACCES` / `ESTALE`.
pub const NET_SUBOP_AUDIT_REFUSAL: u64 = 13;
/// The live service publishes the resolver it uses (#354), so Linux programs read it from
/// `/etc/resolv.conf`: `rsi` = raw-device handle, `rdx` = 1 with a resolver or 0 for none,
/// `r10` = its IPv4 address (big-endian octets in the low 32 bits), `r8` = its port. The
/// service sends it once its network is up (after a DHCP lease, when there is one) and again
/// whenever the resolver changes. The kernel keeps it while that service instance is live.
/// Returns 0, or `EINVAL` / `EACCES` / `ESTALE`.
pub const NET_SUBOP_PUBLISH_RESOLVER: u64 = 14;
/// Wake for a queued client request or a pending holder-exit notification.
pub const NET_WAIT_WORK_REQUESTS: u64 = 1 << 0;
/// Wake when `NET_SUBOP_RAW_RECEIVE` would return a frame.
pub const NET_WAIT_WORK_RX: u64 = 1 << 1;
pub const NET_WAIT_WORK_MASK: u64 = NET_WAIT_WORK_REQUESTS | NET_WAIT_WORK_RX;

pub const NET_SERVICE_ROLE_ID: u64 = 1;

pub const NETWORK_MAX_PAYLOAD_BYTES: usize =
    clean_slate_network::limits::MAX_APPLICATION_PAYLOAD_BYTES;
pub const NETWORK_SERVICE_NEXT_METADATA_BYTES: usize = 28;
pub const NETWORK_SERVICE_NEXT_WIRE_BYTES: usize =
    NETWORK_SERVICE_NEXT_METADATA_BYTES + NETWORK_MAX_PAYLOAD_BYTES;

pub const NETWORK_REQUEST_SLOTS: usize = 64;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkServiceBootstrap {
    pub mode: u64,
    pub service_generation: u64,
    pub result_code: u64,
    pub aux_status: u64,
    pub net_role_handle: u64,
    pub session_id_raw: u64,
    pub echo_len: u64,
    pub reclaimed_sessions: u64,
    pub reclaimed_pending: u64,
    pub inflight_failed: u64,
    pub tls_transactions: u64,
    pub tls_heap_checkpoint: u64,
    pub tls_heap_after_last: u64,
    pub occupancy: NetworkServiceOccupancy,
}

/// Occupancy of the service's bounded tables, counted from the tables themselves each time
/// the service loop goes idle, immediately before its `NET_SUBOP_WAIT_WORK` that includes
/// [`NET_WAIT_WORK_REQUESTS`]. The kernel reads it only from inside that call, when the
/// single-threaded service cannot be changing it and has already drained every client
/// request and holder-exit notification queued before the call.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkServiceOccupancy {
    /// Idle points published so far (strictly increasing).
    pub publications: u64,
    /// Open application sessions (`NetworkService` session table).
    pub sessions: u64,
    /// Requests parked on those sessions.
    pub session_pending: u64,
    /// Live connections in the shared TCP transport.
    pub tcp_connections: u64,
    /// Linux TCP session -> shared-transport connection rows.
    pub tcp_mappings: u64,
    /// Open endpoints in the UDP table.
    pub udp_endpoints: u64,
    /// Linux UDP session -> datagram endpoint rows.
    pub udp_mappings: u64,
    /// Datagrams queued on UDP endpoints.
    pub udp_queued: u64,
    /// Parked requests (their bridge slots stay in service), by kind: Linux TCP
    /// connects waiting for the handshake,
    pub parked_connects: u64,
    /// Linux TCP receives (the kernel's per-socket prefetch),
    pub parked_tcp_receives: u64,
    /// Linux UDP receives (the kernel's per-socket prefetch),
    pub parked_udp_receives: u64,
    /// and cache-miss resolves.
    pub parked_resolves: u64,
    /// In-flight TLS transactions (at most one).
    pub tls_jobs: u64,
    /// In-flight DNS queries.
    pub dns_queries: u64,
    /// Bump-heap bytes allocated (the heap never frees).
    pub heap_bytes: u64,
}

impl NetworkServiceOccupancy {
    pub const fn zero() -> Self {
        Self {
            publications: 0,
            sessions: 0,
            session_pending: 0,
            tcp_connections: 0,
            tcp_mappings: 0,
            udp_endpoints: 0,
            udp_mappings: 0,
            udp_queued: 0,
            parked_connects: 0,
            parked_tcp_receives: 0,
            parked_udp_receives: 0,
            parked_resolves: 0,
            tls_jobs: 0,
            dns_queries: 0,
            heap_bytes: 0,
        }
    }
}

impl NetworkServiceBootstrap {
    pub const fn new(mode: u64, service_generation: u64) -> Self {
        Self {
            mode,
            service_generation,
            result_code: NETWORK_SERVICE_RESULT_PENDING,
            aux_status: 0,
            net_role_handle: 0,
            session_id_raw: 0,
            echo_len: 0,
            reclaimed_sessions: 0,
            reclaimed_pending: 0,
            inflight_failed: 0,
            tls_transactions: 0,
            tls_heap_checkpoint: 0,
            tls_heap_after_last: 0,
            occupancy: NetworkServiceOccupancy::zero(),
        }
    }
}

/// Most request or response bytes a [`NetworkProbe`] carries.
pub const NETWORK_PROBE_PAYLOAD_BYTES: usize = 64;

/// What a client-mode instance of the network image (a kernel self-test's probe, never the
/// serving instance) resolves, connects to and expects back. The test harness that spawns the
/// probe fills it, so the image itself carries no fixture addresses or names (#221).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkProbe {
    pub resolve_name_len: u8,
    pub resolve_name: [u8; clean_slate_network::limits::MAX_REQUEST_HOSTNAME_LEN],
    /// The A record and TTL the resolve must answer.
    pub expect_ipv4: [u8; 4],
    pub expect_ttl: u32,
    /// TLS port on the resolved address.
    pub tls_port: u16,
    /// A UDP port on [`Self::silent_ipv4`] that never answers (the in-flight-arm probe).
    pub silent_port: u16,
    pub silent_ipv4: [u8; 4],
    pub request_len: u16,
    pub response_len: u16,
    pub request: [u8; NETWORK_PROBE_PAYLOAD_BYTES],
    pub response: [u8; NETWORK_PROBE_PAYLOAD_BYTES],
}

const _: () = assert!(core::mem::size_of::<NetworkProbe>() == 204);

impl NetworkProbe {
    pub const NONE: Self = Self {
        resolve_name_len: 0,
        resolve_name: [0; clean_slate_network::limits::MAX_REQUEST_HOSTNAME_LEN],
        expect_ipv4: [0; 4],
        expect_ttl: 0,
        tls_port: 0,
        silent_port: 0,
        silent_ipv4: [0; 4],
        request_len: 0,
        response_len: 0,
        request: [0; NETWORK_PROBE_PAYLOAD_BYTES],
        response: [0; NETWORK_PROBE_PAYLOAD_BYTES],
    };

    pub fn resolve_name(&self) -> &[u8] {
        let len = usize::from(self.resolve_name_len).min(self.resolve_name.len());
        &self.resolve_name[..len]
    }

    pub fn request(&self) -> &[u8] {
        &self.request[..usize::from(self.request_len).min(NETWORK_PROBE_PAYLOAD_BYTES)]
    }

    pub fn response(&self) -> &[u8] {
        &self.response[..usize::from(self.response_len).min(NETWORK_PROBE_PAYLOAD_BYTES)]
    }
}

/// What the launcher hands the network image beside its [`NetworkServiceBootstrap`], at
/// [`NETWORK_SERVICE_LAUNCH_OFFSET`] in the same page (#221 stage D): the network to bring
/// up and, for client-mode probes, what to probe. The certificate authorities to trust are on
/// their own pages ([`NETWORK_SERVICE_TRUST_ADDRESS`]).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkServiceLaunch {
    pub network: clean_slate_network::config::NetworkConfig,
    pub probe: NetworkProbe,
}

const _: () = assert!(
    core::mem::size_of::<NetworkServiceLaunch>() == 88 + 204,
    "no padding: the launch block crosses the user/kernel boundary as bytes"
);
const _: () = assert!(
    core::mem::size_of::<NetworkServiceBootstrap>() as u64 <= NETWORK_SERVICE_LAUNCH_OFFSET
        && NETWORK_SERVICE_LAUNCH_OFFSET as usize + core::mem::size_of::<NetworkServiceLaunch>()
            <= 4096,
    "bootstrap and launch block share one page"
);
const _: () = assert!(NETWORK_SERVICE_LAUNCH_OFFSET % 8 == 0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkServiceWorkItem {
    pub request_id: u64,
    pub request: NetworkRequest,
    pub payload_len: u32,
    pub payload: [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

impl NetworkServiceWorkItem {
    pub const fn empty() -> Self {
        Self {
            request_id: 0,
            request: NetworkRequest::Close {
                session: clean_slate_network::session::SessionId::from_raw(0),
            },
            payload_len: 0,
            payload: [0; NETWORK_MAX_PAYLOAD_BYTES],
        }
    }
}

pub fn encode_request(request: &NetworkRequest) -> [u8; NETWORK_REQUEST_BYTES] {
    request.encode()
}

pub fn encode_response(response: &NetworkResponse) -> [u8; NETWORK_RESPONSE_BYTES] {
    response.encode()
}

/// The native network ABI (#353) restates the service's frames for clients that do not link
/// `clean-slate-network`; this crate sees both, so they are proven equal here.
#[cfg(test)]
mod native_abi_mirrors_the_service_protocol {
    use clean_slate_native_abi::net::{
        net_error_status, NetAddr, NetRequest, NetResponse, NET_ERROR_CLOSED,
        NET_ERROR_DESTINATION_DENIED, NET_ERROR_INVALID_REQUEST, NET_ERROR_NOT_FOUND,
        NET_ERROR_PROTOCOL, NET_ERROR_QUEUE_FULL, NET_ERROR_RESET, NET_ERROR_SESSION_EXHAUSTED,
        NET_ERROR_TIMEOUT, NET_ERROR_UNREACHABLE, NET_FRAME_BYTES, NET_FRAME_MAGIC,
        NET_FRAME_VERSION, NET_MAX_HOSTNAME_BYTES, NET_MAX_PAYLOAD_BYTES, NET_SOCKET_DATAGRAM,
        NET_SOCKET_STREAM, NET_SOCKET_TLS_EXCHANGE,
    };
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ESTALE};
    use clean_slate_network::addr::{BoundedHostname, Ipv4Addr, SocketAddrV4};

    #[test]
    fn every_network_subop_has_its_own_number() {
        let subops = [
            super::NET_SUBOP_SUBMIT,
            super::NET_SUBOP_POLL,
            super::NET_SUBOP_SERVICE_NEXT,
            super::NET_SUBOP_SERVICE_COMPLETE,
            super::NET_SUBOP_RAW_GEOMETRY,
            super::NET_SUBOP_RAW_TRANSMIT,
            super::NET_SUBOP_RAW_RECEIVE,
            super::NET_SUBOP_POP_HOLDER_EXIT,
            super::NET_SUBOP_ACK_HOLDER_EXIT,
            super::NET_SUBOP_MONOTONIC_TICKS,
            super::NET_SUBOP_TICK_PERIOD_NS,
            super::NET_SUBOP_WAIT_WORK,
            super::NET_SUBOP_AUDIT_REFUSAL,
            super::NET_SUBOP_PUBLISH_RESOLVER,
            super::NET_SUBOP_WAIT,
            super::NET_SUBOP_DISCARD,
        ];
        for (index, subop) in subops.iter().enumerate() {
            assert!(
                !subops[index + 1..].contains(subop),
                "sub-operation {subop} is used twice"
            );
        }
    }
    use clean_slate_network::error::{DenialReason, NetworkError};
    use clean_slate_network::limits::{MAX_APPLICATION_PAYLOAD_BYTES, MAX_REQUEST_HOSTNAME_LEN};
    use clean_slate_network::protocol::{
        NetworkRequest, NetworkResponse, NETWORK_PROTOCOL_MAGIC, NETWORK_PROTOCOL_VERSION,
        NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
    };
    use clean_slate_network::session::{SessionId, SocketKind};

    #[test]
    fn sizes_and_kinds_match() {
        assert_eq!(NET_FRAME_BYTES, NETWORK_REQUEST_BYTES);
        assert_eq!(NET_FRAME_BYTES, NETWORK_RESPONSE_BYTES);
        assert_eq!(NET_FRAME_MAGIC, NETWORK_PROTOCOL_MAGIC);
        assert_eq!(NET_FRAME_VERSION, NETWORK_PROTOCOL_VERSION);
        assert_eq!(NET_MAX_PAYLOAD_BYTES, MAX_APPLICATION_PAYLOAD_BYTES);
        assert_eq!(NET_MAX_HOSTNAME_BYTES, MAX_REQUEST_HOSTNAME_LEN);
        assert_eq!(NET_SOCKET_STREAM, SocketKind::LinuxTcp as u8);
        assert_eq!(NET_SOCKET_DATAGRAM, SocketKind::LinuxUdp as u8);
        assert_eq!(NET_SOCKET_TLS_EXCHANGE, SocketKind::Tcp as u8);
        assert_eq!(
            super::NETWORK_STATUS_PENDING,
            clean_slate_native_abi::NETWORK_STATUS_PENDING
        );
    }

    #[test]
    fn native_requests_decode_as_the_service_reads_them() {
        let session = SessionId::from_raw(0x0003_0000_0009);
        let peer = SocketAddrV4::new(Ipv4Addr::new([10, 77, 0, 1]), 4443);
        let cases = [
            (
                NetRequest::Resolve {
                    name: b"m7.fixture.test",
                },
                NetworkRequest::Resolve {
                    name: BoundedHostname::try_from_str("m7.fixture.test").unwrap(),
                },
            ),
            (
                NetRequest::Open {
                    kind: NET_SOCKET_STREAM,
                },
                NetworkRequest::Open {
                    kind: SocketKind::LinuxTcp,
                },
            ),
            (
                NetRequest::Connect {
                    session: session.raw(),
                    peer: NetAddr::new([10, 77, 0, 1], 4443),
                },
                NetworkRequest::Connect {
                    session,
                    dest: peer,
                },
            ),
            (
                NetRequest::Send {
                    session: session.raw(),
                    len: 30,
                },
                NetworkRequest::Send {
                    session,
                    payload_len: 30,
                },
            ),
            (
                NetRequest::Receive {
                    session: session.raw(),
                    max_len: 4096,
                },
                NetworkRequest::Receive {
                    session,
                    max_len: 4096,
                },
            ),
            (
                NetRequest::Close {
                    session: session.raw(),
                },
                NetworkRequest::Close { session },
            ),
        ];
        for (native, service) in cases {
            let frame = native.encode().unwrap();
            assert_eq!(NetworkRequest::decode(&frame), Ok(service));
            assert_eq!(frame, service.encode());
        }
    }

    #[test]
    fn service_responses_decode_natively() {
        let session = SessionId::from_raw(0x0003_0000_0009);
        let cases = [
            (
                NetworkResponse::Resolve {
                    addr: Ipv4Addr::new([10, 77, 0, 1]),
                    ttl: 300,
                },
                NetResponse::Resolve {
                    ip: [10, 77, 0, 1],
                    ttl: 300,
                },
            ),
            (
                NetworkResponse::Open { session },
                NetResponse::Open {
                    session: session.raw(),
                },
            ),
            (NetworkResponse::Connect, NetResponse::Connect),
            (
                NetworkResponse::Send { bytes_sent: 12 },
                NetResponse::Send { accepted: 12 },
            ),
            (
                NetworkResponse::Receive { payload_len: 31 },
                NetResponse::Receive { len: 31 },
            ),
            (NetworkResponse::Close, NetResponse::Close),
            (
                NetworkResponse::Error { code: 8 },
                NetResponse::Error { code: 8 },
            ),
        ];
        for (service, native) in cases {
            assert_eq!(NetResponse::decode(&service.encode()), Ok(native));
            assert_eq!(native.encode(), service.encode());
        }
    }

    #[test]
    fn error_codes_match() {
        assert_eq!(
            NET_ERROR_DESTINATION_DENIED,
            NetworkError::Denied(DenialReason::Destination).code()
        );
        assert_eq!(
            net_error_status(NetworkError::Denied(DenialReason::StaleGeneration).code()),
            STATUS_ESTALE
        );
        for reason in [
            DenialReason::NoCapability,
            DenialReason::MissingRight,
            DenialReason::Revoked,
            DenialReason::Destination,
        ] {
            assert_eq!(
                net_error_status(NetworkError::Denied(reason).code()),
                STATUS_EACCES
            );
        }
        let named = [
            (NET_ERROR_INVALID_REQUEST, NetworkError::InvalidRequest),
            (NET_ERROR_UNREACHABLE, NetworkError::Unreachable),
            (NET_ERROR_TIMEOUT, NetworkError::Timeout),
            (NET_ERROR_RESET, NetworkError::Reset),
            (NET_ERROR_PROTOCOL, NetworkError::Protocol),
            (NET_ERROR_QUEUE_FULL, NetworkError::QueueFull),
            (NET_ERROR_SESSION_EXHAUSTED, NetworkError::SessionExhausted),
            (NET_ERROR_NOT_FOUND, NetworkError::NotFound),
            (NET_ERROR_CLOSED, NetworkError::Closed),
        ];
        for (code, error) in named {
            assert_eq!(code, error.code(), "{error:?}");
        }
    }
}
