//! TCP echo and TLS termination for the M7 hermetic peer.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, TCP_ECHO_PORT, TLS_PORT,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::ServerConfig;
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::{IpAddress, IpListenEndpoint};

pub enum FixtureTlsCert {
    Correct,
    WrongName,
}

pub struct TcpEchoService {
    listen: SocketHandle,
    active: Option<SocketHandle>,
    recv_len: usize,
    echoed: bool,
}

impl TcpEchoService {
    pub fn new(sockets: &mut smoltcp::iface::SocketSet, listen: SocketHandle) -> Self {
        let socket = sockets.get_mut::<tcp::Socket>(listen);
        socket.listen(TCP_ECHO_PORT).expect("tcp echo listen");
        Self {
            listen,
            active: None,
            recv_len: 0,
            echoed: false,
        }
    }

    pub fn poll(&mut self, sockets: &mut smoltcp::iface::SocketSet) {
        if self.active.is_none() {
            let socket = sockets.get_mut::<tcp::Socket>(self.listen);
            if socket.is_active() {
                println!("[FIX ] tcp echo connect");
                self.active = Some(self.listen);
                self.recv_len = 0;
                self.echoed = false;
            } else if socket.is_listening() {
                return;
            }
        }
        let active = self.active.expect("active handle");
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if !socket.is_active() {
            self.relisten(sockets);
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
            self.relisten(sockets);
        }
    }

    fn relisten(&mut self, sockets: &mut smoltcp::iface::SocketSet) {
        self.active = None;
        self.recv_len = 0;
        self.echoed = false;
        let socket = sockets.get_mut::<tcp::Socket>(self.listen);
        if !socket.is_listening() {
            let _ = socket.listen(TCP_ECHO_PORT);
        }
    }
}

pub struct TlsService {
    listen: SocketHandle,
    active: Option<SocketHandle>,
    server_config: Arc<ServerConfig>,
    connection: Option<ServerConnection>,
    recv_acc: Vec<u8>,
    sni_logged: bool,
}

impl TlsService {
    pub fn new(
        sockets: &mut smoltcp::iface::SocketSet,
        listen: SocketHandle,
        cert: FixtureTlsCert,
    ) -> Self {
        let socket = sockets.get_mut::<tcp::Socket>(listen);
        socket.listen(TLS_PORT).expect("tls listen");
        let server_config = Arc::new(load_server_config(cert));
        Self {
            listen,
            active: None,
            server_config,
            connection: None,
            recv_acc: Vec::new(),
            sni_logged: false,
        }
    }

    pub fn poll(&mut self, sockets: &mut smoltcp::iface::SocketSet) {
        if self.active.is_none() {
            let socket = sockets.get_mut::<tcp::Socket>(self.listen);
            if socket.is_active() {
                self.active = Some(self.listen);
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
            self.reset_listen(sockets);
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
            self.reset_listen(sockets);
        }
    }

    fn reset_listen(&mut self, sockets: &mut smoltcp::iface::SocketSet) {
        self.active = None;
        self.connection = None;
        self.recv_acc.clear();
        self.sni_logged = false;
        let socket = sockets.get_mut::<tcp::Socket>(self.listen);
        if !socket.is_listening() {
            let _ = socket.listen(TLS_PORT);
        }
    }
}

const M9_HTTP_PORT: u16 = 4001;

pub struct M9HttpService {
    listen: SocketHandle,
    active: Option<SocketHandle>,
    sent: bool,
    closed: bool,
}

impl M9HttpService {
    pub fn new(sockets: &mut smoltcp::iface::SocketSet, listen: SocketHandle) -> Self {
        let socket = sockets.get_mut::<tcp::Socket>(listen);
        let endpoint = IpListenEndpoint {
            addr: Some(IpAddress::v4(10, 77, 0, 50)),
            port: M9_HTTP_PORT,
        };
        socket.listen(endpoint).expect("m9 http listen");
        Self {
            listen,
            active: None,
            sent: false,
            closed: false,
        }
    }

    pub fn poll(&mut self, sockets: &mut smoltcp::iface::SocketSet) {
        if self.active.is_none() {
            let socket = sockets.get_mut::<tcp::Socket>(self.listen);
            if socket.is_active() {
                self.active = Some(self.listen);
                self.sent = false;
                println!("[FIX ] m9 http connect");
            }
            return;
        }
        let active = self.active.expect("m9 http active");
        let socket = sockets.get_mut::<tcp::Socket>(active);
        if !socket.is_active() {
            self.relisten(sockets);
            return;
        }
        if socket.may_recv() {
            let mut buf = [0u8; 256];
            let _ = socket.recv_slice(&mut buf);
        }
        if !self.sent && socket.may_send() {
            let resp = concat!(
                "HTTP/1.0 200 OK\r\n",
                "Content-Length: 16\r\n",
                "Connection: close\r\n\r\n",
                "M9-FIXTURE-HTTP\n"
            );
            if socket.send_slice(resp.as_bytes()).is_ok() {
                self.sent = true;
                println!("[FIX ] m9 http response");
            }
        }
        if self.sent && !self.closed && socket.send_queue() == 0 {
            socket.close();
            self.closed = true;
        }
        if self.sent && socket.state() == tcp::State::CloseWait {
            socket.close();
            self.relisten(sockets);
        }
    }

    fn relisten(&mut self, sockets: &mut smoltcp::iface::SocketSet) {
        self.active = None;
        self.sent = false;
        self.closed = false;
        let socket = sockets.get_mut::<tcp::Socket>(self.listen);
        if !socket.is_listening() {
            let endpoint = IpListenEndpoint {
                addr: Some(IpAddress::v4(10, 77, 0, 50)),
                port: M9_HTTP_PORT,
            };
            let _ = socket.listen(endpoint);
        }
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
