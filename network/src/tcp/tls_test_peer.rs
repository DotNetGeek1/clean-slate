//! rustls TLS responder on [`TLS_PORT`] for host integration tests.

use std::io::{Cursor, Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::ServerConnection;
use rustls::ServerConfig;

use crate::addr::{IpProtocol, Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::fixture::{APP_REQUEST_BYTES, APP_RESPONSE_BYTES, PEER_IPV4, TLS_PORT};
use crate::stack::{Inbound, L3Stack};
use crate::tcp::conn::write_tcp_to_buf;
use crate::tcp::segment::{parse as parse_tcp, TcpFlags, TcpSegment, OUR_TCP_MSS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PeerState {
    Listen,
    SynReceived,
    Established,
    CloseWait,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPeerCert {
    FixtureCorrect,
    FixtureWrongName,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum TlsPeerFault {
    #[default]
    None,
    GarbageTlsRecord,
    SilentAfterTcp,
}

pub struct TlsTestPeer<L: NetworkLink> {
    stack: L3Stack<L>,
    state: PeerState,
    local: SocketAddrV4,
    remote: Option<SocketAddrV4>,
    iss: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    server_config: Arc<ServerConfig>,
    tls: Option<ServerConnection>,
    app_acc: Vec<u8>,
    fault: TlsPeerFault,
    garbage_sent: bool,
}

impl<L: NetworkLink> TlsTestPeer<L> {
    pub fn with_fixture_cert(stack: L3Stack<L>, cert: TlsPeerCert) -> Self {
        Self::new(stack, load_fixture_server_config(cert), TlsPeerFault::None)
    }

    pub fn with_custom_config(stack: L3Stack<L>, config: Arc<ServerConfig>) -> Self {
        Self::new(stack, config, TlsPeerFault::None)
    }

    pub fn set_fault(&mut self, fault: TlsPeerFault) {
        self.fault = fault;
    }

    fn new(stack: L3Stack<L>, server_config: Arc<ServerConfig>, fault: TlsPeerFault) -> Self {
        Self {
            stack,
            state: PeerState::Listen,
            local: SocketAddrV4::new(PEER_IPV4, TLS_PORT),
            remote: None,
            iss: 2_000,
            snd_nxt: 2_000,
            rcv_nxt: 0,
            server_config,
            tls: None,
            app_acc: Vec::new(),
            fault,
            garbage_sent: false,
        }
    }

    pub fn poll(&mut self, now: u64) -> Result<(), NetworkError> {
        while let Some(inbound) = self.stack.poll(now)? {
            if let Inbound::Ipv4(ip) = inbound {
                if ip.header.protocol != IpProtocol::TCP {
                    continue;
                }
                let src = ip.header.src;
                let dst = ip.header.dst;
                if dst != self.local.addr || ip.header.dst != PEER_IPV4 {
                    continue;
                }
                let (seg, payload) = parse_tcp(src, dst, ip.payload())?;
                self.handle_segment(now, src, &seg, payload)?;
            }
        }
        self.drive_tls_outbound(now)?;
        Ok(())
    }

    fn handle_segment(
        &mut self,
        now: u64,
        src: Ipv4Addr,
        seg: &TcpSegment,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let remote = SocketAddrV4::new(src, seg.src_port);
        match self.state {
            PeerState::Listen => {
                if seg.flags.contains(TcpFlags::SYN) && !seg.flags.contains(TcpFlags::ACK) {
                    self.remote = Some(remote);
                    self.rcv_nxt = seg.seq.wrapping_add(1);
                    self.state = PeerState::SynReceived;
                    self.send_syn_ack(now, remote, seg.src_port)?;
                }
            }
            PeerState::SynReceived => {
                if seg.flags.contains(TcpFlags::ACK) {
                    self.state = PeerState::Established;
                    if self.fault != TlsPeerFault::SilentAfterTcp {
                        self.tls = Some(
                            ServerConnection::new(self.server_config.clone())
                                .map_err(|_| NetworkError::Protocol)?,
                        );
                    }
                    self.app_acc.clear();
                    self.garbage_sent = false;
                    if !payload.is_empty() {
                        self.handle_tls_payload(now, remote, seg, payload)?;
                    }
                } else if seg.flags.contains(TcpFlags::SYN) {
                    self.send_syn_ack(now, remote, seg.src_port)?;
                }
            }
            PeerState::Established => {
                if seg.flags.contains(TcpFlags::RST) {
                    self.state = PeerState::Listen;
                    self.remote = None;
                    self.tls = None;
                    self.app_acc.clear();
                    return Ok(());
                }
                if !payload.is_empty() && seg.seq == self.rcv_nxt {
                    self.handle_tls_payload(now, remote, seg, payload)?;
                }
                if seg.flags.contains(TcpFlags::FIN) && seg.seq == self.rcv_nxt {
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(1);
                    self.state = PeerState::CloseWait;
                    let fin = TcpSegment {
                        src_port: self.local.port,
                        dst_port: seg.src_port,
                        seq: self.snd_nxt,
                        ack: self.rcv_nxt,
                        data_offset: 5,
                        flags: TcpFlags::FIN.union(TcpFlags::ACK),
                        window: 4096,
                        checksum: 0,
                        urgent: 0,
                        mss_option: None,
                    };
                    self.snd_nxt = self.snd_nxt.wrapping_add(1);
                    self.transmit(now, remote, &fin, &[])?;
                    self.tls = None;
                }
            }
            PeerState::CloseWait => {
                if seg.flags.contains(TcpFlags::ACK) {
                    self.state = PeerState::Listen;
                    self.remote = None;
                    self.app_acc.clear();
                }
            }
        }
        Ok(())
    }

    fn handle_tls_payload(
        &mut self,
        now: u64,
        remote: SocketAddrV4,
        seg: &TcpSegment,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        if self.fault == TlsPeerFault::GarbageTlsRecord && !self.garbage_sent {
            self.garbage_sent = true;
            self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
            self.send_ack(now, remote)?;
            self.transmit(
                now,
                remote,
                &data_segment(seg, self.snd_nxt, self.rcv_nxt),
                &[0x16, 0x03, 0x01, 0x00, 0x05, 0xff, 0xff, 0xff],
            )?;
            self.snd_nxt = self.snd_nxt.wrapping_add(8);
            return Ok(());
        }
        self.rcv_nxt = self.rcv_nxt.wrapping_add(payload.len() as u32);
        self.send_ack(now, remote)?;
        if let Some(conn) = self.tls.as_mut() {
            let mut cursor = Cursor::new(payload);
            let _ = conn.read_tls(&mut cursor);
            let _ = conn.process_new_packets();
            loop {
                let mut reader = conn.reader();
                let mut buf = [0u8; 256];
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        self.app_acc.extend_from_slice(&buf[..n]);
                        if self.app_acc.len() >= APP_REQUEST_BYTES.len()
                            && self.app_acc.starts_with(APP_REQUEST_BYTES)
                        {
                            let _ = conn.writer().write_all(APP_RESPONSE_BYTES);
                            conn.writer().flush().ok();
                            let _ = conn.process_new_packets();
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        self.drive_tls_outbound(now)?;
        Ok(())
    }

    fn drive_tls_outbound(&mut self, now: u64) -> Result<(), NetworkError> {
        let remote = self.remote;
        let Some(conn) = self.tls.as_mut() else {
            return Ok(());
        };
        let Some(remote) = remote else {
            return Ok(());
        };
        let mut chunks = Vec::new();
        while conn.wants_write() {
            let mut tls_out = [0u8; 4096];
            let mut cursor = Cursor::new(&mut tls_out[..]);
            if conn.write_tls(&mut cursor).is_err() {
                break;
            }
            let written = cursor.position() as usize;
            if written == 0 {
                break;
            }
            chunks.push(tls_out[..written].to_vec());
        }
        for chunk in chunks {
            let written = chunk.len();
            self.transmit(
                now,
                remote,
                &data_segment(
                    &TcpSegment {
                        src_port: self.local.port,
                        dst_port: remote.port,
                        seq: 0,
                        ack: 0,
                        data_offset: 5,
                        flags: TcpFlags(0),
                        window: 4096,
                        checksum: 0,
                        urgent: 0,
                        mss_option: None,
                    },
                    self.snd_nxt,
                    self.rcv_nxt,
                ),
                &chunk,
            )?;
            self.snd_nxt = self.snd_nxt.wrapping_add(written as u32);
        }
        Ok(())
    }

    fn send_syn_ack(
        &mut self,
        now: u64,
        remote: SocketAddrV4,
        dst_port: u16,
    ) -> Result<(), NetworkError> {
        let syn_ack = TcpSegment {
            src_port: self.local.port,
            dst_port,
            seq: self.iss,
            ack: self.rcv_nxt,
            data_offset: 6,
            flags: TcpFlags::SYN.union(TcpFlags::ACK),
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: Some(OUR_TCP_MSS),
        };
        self.snd_nxt = self.iss.wrapping_add(1);
        self.transmit(now, remote, &syn_ack, &[])
    }

    fn send_ack(&mut self, now: u64, remote: SocketAddrV4) -> Result<(), NetworkError> {
        let seg = TcpSegment {
            src_port: self.local.port,
            dst_port: remote.port,
            seq: self.snd_nxt,
            ack: self.rcv_nxt,
            data_offset: 5,
            flags: TcpFlags::ACK,
            window: 4096,
            checksum: 0,
            urgent: 0,
            mss_option: None,
        };
        self.transmit(now, remote, &seg, &[])
    }

    fn transmit(
        &mut self,
        now: u64,
        remote: SocketAddrV4,
        seg: &TcpSegment,
        payload: &[u8],
    ) -> Result<(), NetworkError> {
        let src = PEER_IPV4;
        let dst = remote.addr;
        let len = seg.header_len() + payload.len();
        self.stack
            .send_ipv4(now, dst, IpProtocol::TCP, len, |buf| {
                write_tcp_to_buf(src, dst, seg, payload, buf)?;
                Ok(())
            })?;
        Ok(())
    }
}

fn data_segment(template: &TcpSegment, seq: u32, ack: u32) -> TcpSegment {
    TcpSegment {
        src_port: template.src_port,
        dst_port: template.dst_port,
        seq,
        ack,
        data_offset: 5,
        flags: TcpFlags::ACK.union(TcpFlags::PSH),
        window: 4096,
        checksum: 0,
        urgent: 0,
        mss_option: None,
    }
}

fn fixture_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace")
        .join("xtask/fixtures/m7")
}

pub fn load_fixture_server_config(cert: TlsPeerCert) -> Arc<ServerConfig> {
    let stem = match cert {
        TlsPeerCert::FixtureCorrect => "server",
        TlsPeerCert::FixtureWrongName => "server-wrong-name",
    };
    let dir = fixture_dir();
    let cert_der = std::fs::read(dir.join(format!("{stem}.crt"))).expect("fixture cert der");
    let key_der = std::fs::read(dir.join(format!("{stem}.key"))).expect("fixture key der");
    server_config_from_der(cert_der, key_der)
}

pub fn server_config_from_der(cert_der: Vec<u8>, key_der: Vec<u8>) -> Arc<ServerConfig> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(key_der.into());
    let provider = rustls::crypto::ring::default_provider();
    Arc::new(
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .expect("tls13")
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config"),
    )
}
