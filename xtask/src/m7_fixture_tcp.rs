//! TCP echo and TLS termination for the M7 hermetic peer.

use std::io::{Cursor, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, TCP_ECHO_PORT, TLS_PORT,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::ServerConfig;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

pub enum FixtureTlsCert {
    Correct,
    WrongName,
}

/// Listening sockets per fixture port. After a passive close a served connection's socket
/// sits in LAST-ACK until the guest acks our FIN and cannot listen meanwhile; a guest that
/// connects again in that window must still find a listener, or smoltcp answers its SYN
/// with RST.
const LISTEN_BACKLOG: usize = 4;

/// The listening sockets of one fixture service.
struct ListenerPool {
    handles: [SocketHandle; LISTEN_BACKLOG],
    endpoint: IpListenEndpoint,
}

impl ListenerPool {
    fn new(sockets: &mut SocketSet<'_>, buffer_bytes: usize, endpoint: IpListenEndpoint) -> Self {
        let handles = core::array::from_fn(|_| {
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; buffer_bytes]),
                tcp::SocketBuffer::new(vec![0u8; buffer_bytes]),
            );
            socket.listen(endpoint).expect("fixture listen");
            sockets.add(socket)
        });
        Self { handles, endpoint }
    }

    /// Puts every socket whose connection is over back in LISTEN. TIME-WAIT (after an
    /// active close) is cut short: the guest reuses source ports, and smoltcp would swallow
    /// a new SYN on the old 4-tuple instead of reopening the connection.
    fn relisten_closed(&self, sockets: &mut SocketSet<'_>) {
        for handle in self.handles {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            if matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait) {
                let _ = socket.listen(self.endpoint);
            }
        }
    }

    /// A socket holding a connection no service call has taken yet. Services close a
    /// connection before releasing it, so these states only occur before it is taken.
    fn accept(&self, sockets: &SocketSet<'_>) -> Option<SocketHandle> {
        self.handles.into_iter().find(|&handle| {
            matches!(
                sockets.get::<tcp::Socket>(handle).state(),
                tcp::State::SynReceived | tcp::State::Established | tcp::State::CloseWait
            )
        })
    }
}

pub struct TcpEchoService {
    pool: ListenerPool,
    active: Option<SocketHandle>,
    recv_len: usize,
    echoed: bool,
}

impl TcpEchoService {
    pub fn new(sockets: &mut SocketSet<'_>) -> Self {
        Self {
            pool: ListenerPool::new(sockets, 4096, TCP_ECHO_PORT.into()),
            active: None,
            recv_len: 0,
            echoed: false,
        }
    }

    pub fn poll(&mut self, sockets: &mut SocketSet<'_>) {
        self.pool.relisten_closed(sockets);
        if self.active.is_none() {
            let Some(handle) = self.pool.accept(sockets) else {
                return;
            };
            println!("[FIX ] tcp echo connect");
            self.active = Some(handle);
            self.recv_len = 0;
            self.echoed = false;
        }
        let active = self.active.expect("active handle");
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if !socket.is_active() {
            self.release_active();
            return;
        }
        if socket.may_recv() {
            let mut buf = [0u8; 256];
            if let Ok(n) = socket.recv_slice(&mut buf) {
                let take = n.min(buf.len());
                self.recv_len = (self.recv_len + take).min(APP_REQUEST_BYTES.len());
                if !self.echoed
                    && self.recv_len >= APP_REQUEST_BYTES.len()
                    && socket.send_slice(APP_RESPONSE_BYTES).is_ok()
                {
                    self.echoed = true;
                    println!("[FIX ] tcp echo");
                }
            }
        }
        if socket.state() == tcp::State::CloseWait {
            socket.close();
            self.release_active();
        }
    }

    /// Forgets the served connection; its socket listens again once it reaches CLOSED.
    fn release_active(&mut self) {
        self.active = None;
        self.recv_len = 0;
        self.echoed = false;
    }
}

pub struct TlsService {
    pool: ListenerPool,
    active: Option<SocketHandle>,
    server_config: Arc<ServerConfig>,
    connection: Option<ServerConnection>,
    recv_acc: Vec<u8>,
    sni_logged: bool,
}

impl TlsService {
    pub fn new(sockets: &mut SocketSet<'_>, cert: FixtureTlsCert) -> Self {
        Self {
            pool: ListenerPool::new(sockets, 8192, TLS_PORT.into()),
            active: None,
            server_config: Arc::new(load_server_config(cert)),
            connection: None,
            recv_acc: Vec::new(),
            sni_logged: false,
        }
    }

    pub fn poll(&mut self, sockets: &mut SocketSet<'_>) {
        self.pool.relisten_closed(sockets);
        if self.active.is_none() {
            if let Some(handle) = self.pool.accept(sockets) {
                self.active = Some(handle);
                self.connection = Some(
                    ServerConnection::new(self.server_config.clone())
                        .expect("tls server connection"),
                );
                self.recv_acc.clear();
                self.sni_logged = false;
            }
            return;
        }
        let active = self.active.expect("tls active");
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if !socket.is_active() {
            self.release_active();
            return;
        }
        let Some(conn) = self.connection.as_mut() else {
            return;
        };
        while socket.may_recv() {
            let mut buf = [0u8; 2048];
            match socket.recv_slice(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let mut cursor = Cursor::new(&buf[..n]);
                    let _ = conn.read_tls(&mut cursor);
                    let _ = conn.process_new_packets();
                }
                Err(_) => break,
            }
        }
        if !self.sni_logged && !conn.is_handshaking() {
            println!("[FIX ] tls handshake sni=m7.fixture.test");
            self.sni_logged = true;
        }
        while conn.wants_write() {
            let mut tls_out = [0u8; 2048];
            let mut cursor = Cursor::new(&mut tls_out[..]);
            if conn.write_tls(&mut cursor).is_err() {
                break;
            }
            let written = cursor.position() as usize;
            if written > 0 {
                let _ = socket.send_slice(&tls_out[..written]);
            }
        }
        {
            let mut reader = conn.reader();
            let mut app = [0u8; 256];
            match reader.read(&mut app) {
                Ok(n) if n > 0 => {
                    self.recv_acc.extend_from_slice(&app[..n]);
                    if self.recv_acc.len() >= APP_REQUEST_BYTES.len() {
                        let _ = conn.writer().write_all(APP_RESPONSE_BYTES);
                        conn.writer().flush().ok();
                        println!("[FIX ] tls app bytes");
                    }
                }
                _ => {}
            }
        }
        if socket.state() == tcp::State::CloseWait {
            socket.close();
            self.release_active();
        }
    }

    /// Forgets the served connection; its socket listens again once it reaches CLOSED.
    fn release_active(&mut self) {
        self.active = None;
        self.connection = None;
        self.recv_acc.clear();
        self.sni_logged = false;
    }
}

const M9_SERVICE_ADDR: IpAddress = IpAddress::v4(10, 77, 0, 50);
const M9_HTTP_PORT: u16 = 4001;
/// Longest request head (request line, headers, blank line) the HTTP endpoint reads.
const M9_HTTP_MAX_REQUEST_BYTES: usize = 2048;
/// How long a connection may take to deliver its whole request head.
const M9_HTTP_REQUEST_WAIT: Duration = Duration::from_secs(5);
const M9_HTTP_RESPONSE: &str = concat!(
    "HTTP/1.0 200 OK\r\n",
    "Content-Length: 16\r\n",
    "Connection: close\r\n\r\n",
    "M9-FIXTURE-HTTP\n"
);

/// What the HTTP endpoint did with each connection, read by the lanes after the run.
#[derive(Debug, Default)]
pub struct HttpRequestCounters {
    /// Connections that delivered a well-formed `GET /` request head and were answered.
    pub answered: AtomicU64,
    /// Connections closed without a response: malformed, oversized or missing request.
    pub refused: AtomicU64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpRequestHead {
    /// No blank line yet, and the head is still within bounds.
    Incomplete,
    /// `GET / HTTP/1.x`, then `name: value` header lines, then the blank line.
    Complete,
    Malformed(&'static str),
}

/// Classifies the bytes a client has sent so far. Only a request for `/` is answered.
pub fn parse_http_request_head(bytes: &[u8]) -> HttpRequestHead {
    let Some(end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
        return if bytes.len() >= M9_HTTP_MAX_REQUEST_BYTES {
            HttpRequestHead::Malformed("no blank line within the request bound")
        } else {
            HttpRequestHead::Incomplete
        };
    };
    if end + 4 > M9_HTTP_MAX_REQUEST_BYTES {
        return HttpRequestHead::Malformed("request head over the bound");
    }
    let Ok(head) = std::str::from_utf8(&bytes[..end]) else {
        return HttpRequestHead::Malformed("request head is not UTF-8");
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    if request_line != "GET / HTTP/1.0" && request_line != "GET / HTTP/1.1" {
        return HttpRequestHead::Malformed("request line is not GET / HTTP/1.x");
    }
    for header in lines {
        let well_formed = header.split_once(':').is_some_and(|(name, _)| {
            !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_graphic())
        });
        if !well_formed {
            return HttpRequestHead::Malformed("header line is not name: value");
        }
    }
    HttpRequestHead::Complete
}

/// `GET /` on 10.77.0.50:4001. The response goes out only after the client's whole
/// request head has arrived, so a guest whose request never leaves it gets no body.
pub struct M9HttpService {
    pool: ListenerPool,
    active: Option<SocketHandle>,
    connected_at: Instant,
    request: Vec<u8>,
    sent: bool,
    closed: bool,
    counters: Arc<HttpRequestCounters>,
}

impl M9HttpService {
    pub fn new(sockets: &mut SocketSet<'_>, counters: Arc<HttpRequestCounters>) -> Self {
        let endpoint = IpListenEndpoint {
            addr: Some(M9_SERVICE_ADDR),
            port: M9_HTTP_PORT,
        };
        Self {
            pool: ListenerPool::new(sockets, 8192, endpoint),
            active: None,
            connected_at: Instant::now(),
            request: Vec::new(),
            sent: false,
            closed: false,
            counters,
        }
    }

    pub fn poll(&mut self, sockets: &mut SocketSet<'_>) {
        self.pool.relisten_closed(sockets);
        if self.active.is_none() {
            if let Some(handle) = self.pool.accept(sockets) {
                self.active = Some(handle);
                self.connected_at = Instant::now();
                self.request.clear();
                self.sent = false;
                self.closed = false;
                println!("[FIX ] m9 http connect");
            }
            return;
        }
        let active = self.active.expect("m9 http active");
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if !socket.is_active() {
            if !self.sent && !self.closed {
                self.refuse(None, "connection ended before a request");
            }
            self.release_active();
            return;
        }
        while socket.can_recv() {
            let mut buf = [0u8; 512];
            match socket.recv_slice(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => self.request.extend_from_slice(&buf[..n]),
            }
        }
        if !self.sent && !self.closed {
            match parse_http_request_head(&self.request) {
                HttpRequestHead::Complete if socket.may_send() => {
                    let request_line = self.request_line();
                    if socket.send_slice(M9_HTTP_RESPONSE.as_bytes()).is_ok() {
                        self.sent = true;
                        let answered = self.counters.answered.fetch_add(1, Ordering::SeqCst) + 1;
                        println!(
                            "[FIX ] m9 http request {request_line:?} ({} bytes) answered={answered}",
                            self.request.len()
                        );
                        println!("[FIX ] m9 http response");
                    }
                }
                HttpRequestHead::Complete => {
                    self.refuse(Some(socket), "client closed its receive side")
                }
                HttpRequestHead::Malformed(reason) => self.refuse(Some(socket), reason),
                HttpRequestHead::Incomplete if socket.state() == tcp::State::CloseWait => {
                    self.refuse(Some(socket), "client closed before a complete request")
                }
                HttpRequestHead::Incomplete
                    if self.connected_at.elapsed() >= M9_HTTP_REQUEST_WAIT =>
                {
                    self.refuse(Some(socket), "no complete request within the wait")
                }
                HttpRequestHead::Incomplete => {}
            }
        }
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if self.sent && !self.closed && socket.send_queue() == 0 {
            socket.close();
            self.closed = true;
        }
        if self.closed && socket.state() == tcp::State::CloseWait {
            socket.close();
            self.release_active();
        }
    }

    fn request_line(&self) -> String {
        let end = self
            .request
            .windows(2)
            .position(|window| window == b"\r\n")
            .unwrap_or(self.request.len());
        String::from_utf8_lossy(&self.request[..end]).into_owned()
    }

    /// Closes the connection without a response and counts it.
    fn refuse(&mut self, socket: Option<&mut tcp::Socket<'_>>, reason: &str) {
        let refused = self.counters.refused.fetch_add(1, Ordering::SeqCst) + 1;
        println!(
            "[FIX ] m9 http refused: {reason} ({} bytes received) refused={refused}",
            self.request.len()
        );
        if let Some(socket) = socket {
            socket.close();
        }
        self.closed = true;
    }

    /// Forgets the served connection; its socket listens again once it reaches CLOSED.
    fn release_active(&mut self) {
        self.active = None;
        self.request.clear();
        self.sent = false;
        self.closed = false;
    }
}

const M9_BANNER_PORT: u16 = 4002;
const M9_BANNER_BYTES: &[u8] = b"M9-BANNER-FIX\n";

pub struct M9BannerService {
    pool: ListenerPool,
    active: Option<SocketHandle>,
    sent: bool,
}

impl M9BannerService {
    pub fn new(sockets: &mut SocketSet<'_>) -> Self {
        let endpoint = IpListenEndpoint {
            addr: Some(M9_SERVICE_ADDR),
            port: M9_BANNER_PORT,
        };
        Self {
            pool: ListenerPool::new(sockets, 4096, endpoint),
            active: None,
            sent: false,
        }
    }

    pub fn poll(&mut self, sockets: &mut SocketSet<'_>) {
        self.pool.relisten_closed(sockets);
        if self.active.is_none() {
            if let Some(handle) = self.pool.accept(sockets) {
                self.active = Some(handle);
                self.sent = false;
                println!("[FIX ] m9 banner connect");
            }
            return;
        }
        let active = self.active.expect("m9 banner active");
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if !socket.is_active() {
            self.release_active();
            return;
        }
        if !self.sent && socket.may_send() && socket.send_slice(M9_BANNER_BYTES).is_ok() {
            self.sent = true;
            println!("[FIX ] m9 banner sent");
        }
        if self.sent && socket.state() == tcp::State::CloseWait {
            socket.close();
            self.release_active();
        }
    }

    /// Forgets the served connection; its socket listens again once it reaches CLOSED.
    fn release_active(&mut self) {
        self.active = None;
        self.sent = false;
    }
}

fn load_server_config(cert: FixtureTlsCert) -> ServerConfig {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace");
    let stem = match cert {
        FixtureTlsCert::Correct => "server",
        FixtureTlsCert::WrongName => "server-wrong-name",
    };
    let cert_path = root.join(format!("xtask/fixtures/m7/{stem}.crt"));
    let key_path = root.join(format!("xtask/fixtures/m7/{stem}.key"));
    let cert_der = std::fs::read(&cert_path).expect("fixture cert");
    let key_der = std::fs::read(&key_path).expect("fixture key");
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(key_der.into());
    let provider = rustls::crypto::ring::default_provider();
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("tls13")
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server config")
}

#[cfg(test)]
mod tests {
    use super::{parse_http_request_head, HttpRequestHead, M9_HTTP_MAX_REQUEST_BYTES};

    /// BusyBox `wget`'s request (`fixtures/busybox/frozen/traces/wget-fixture-http.strace`).
    const WGET_REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: m7.fixture.test:4001\r\nUser-Agent: Wget\r\nConnection: close\r\n\r\n";
    /// The socket probe's request (`fixtures/linux-socket-probe/probe.S`).
    const PROBE_REQUEST: &[u8] = b"GET / HTTP/1.0\r\nHost: m7.fixture.test\r\n\r\n";

    #[test]
    fn the_guest_clients_requests_are_complete() {
        assert_eq!(
            parse_http_request_head(WGET_REQUEST),
            HttpRequestHead::Complete
        );
        assert_eq!(
            parse_http_request_head(PROBE_REQUEST),
            HttpRequestHead::Complete
        );
        assert_eq!(
            parse_http_request_head(b"GET / HTTP/1.0\r\n\r\n"),
            HttpRequestHead::Complete
        );
    }

    #[test]
    fn nothing_or_a_partial_head_is_not_a_request() {
        assert_eq!(parse_http_request_head(b""), HttpRequestHead::Incomplete);
        for cut in 1..WGET_REQUEST.len() {
            assert_eq!(
                parse_http_request_head(&WGET_REQUEST[..cut]),
                HttpRequestHead::Incomplete,
                "{cut}"
            );
        }
    }

    #[test]
    fn a_wrong_request_line_or_header_is_malformed() {
        for head in [
            &b"POST / HTTP/1.1\r\n\r\n"[..],
            b"GET /other HTTP/1.1\r\n\r\n",
            b"GET / HTTP/2\r\n\r\n",
            b"get / http/1.1\r\n\r\n",
            b"\r\n\r\n",
            b"GET / HTTP/1.1\r\nno-colon\r\n\r\n",
            b"GET / HTTP/1.1\r\n: empty-name\r\n\r\n",
            b"GET / HTTP/1.1\r\nbad name: v\r\n\r\n",
        ] {
            assert!(
                matches!(parse_http_request_head(head), HttpRequestHead::Malformed(_)),
                "{:?}",
                String::from_utf8_lossy(head)
            );
        }
    }

    #[test]
    fn a_head_without_a_blank_line_is_bounded() {
        let mut endless = b"GET / HTTP/1.1\r\n".to_vec();
        endless.resize(M9_HTTP_MAX_REQUEST_BYTES, b'a');
        assert!(matches!(
            parse_http_request_head(&endless),
            HttpRequestHead::Malformed(_)
        ));
        let mut long = b"GET / HTTP/1.1\r\nX: ".to_vec();
        long.resize(M9_HTTP_MAX_REQUEST_BYTES, b'a');
        long.extend_from_slice(b"\r\n\r\n");
        assert!(matches!(
            parse_http_request_head(&long),
            HttpRequestHead::Malformed(_)
        ));
    }
}
