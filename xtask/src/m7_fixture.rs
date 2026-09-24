//! Hermetic M7 QEMU raw-Ethernet peer (host-side smoltcp stack).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use clean_slate_network::fixture::{
    DNS_SERVER_PORT, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS, FIXTURE_HOSTNAME, PEER_IPV4, PEER_MAC,
    UDP_ECHO_PORT,
};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};

use crate::m7_fixture_tcp::{FixtureTlsCert, M9HttpService, TcpEchoService, TlsService};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

const MAX_FRAME_BYTES: usize = 1514;

#[derive(Clone, Copy, Debug)]
pub enum WhichCert {
    Correct,
    WrongName,
}

#[derive(Clone, Copy, Debug)]
pub struct FixtureOptions {
    pub tls_cert: WhichCert,
    pub dns_reply_delay: StdDuration,
    /// M9 #105: DNS A → 10.77.0.50, HTTP on 10.77.0.50:4001 (M7 tests keep default false).
    pub m9_profile: bool,
}

impl Default for FixtureOptions {
    fn default() -> Self {
        Self {
            tls_cert: WhichCert::Correct,
            dns_reply_delay: StdDuration::ZERO,
            m9_profile: false,
        }
    }
}

pub struct M7FixturePeer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl M7FixturePeer {
    pub fn start() -> std::io::Result<Self> {
        Self::start_with(FixtureOptions::default())
    }

    pub fn start_with(options: FixtureOptions) -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || run_peer(listener, stop_flag, options));
        Ok(Self {
            port,
            stop,
            handle: Some(handle),
        })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn run_peer(listener: TcpListener, stop: Arc<AtomicBool>, options: FixtureOptions) {
    listener
        .set_nonblocking(true)
        .expect("fixture listener nonblocking");
    let deadline = std::time::Instant::now() + StdDuration::from_secs(120);
    let mut stream = None;
    while std::time::Instant::now() < deadline && !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((client, _)) => {
                stream = Some(client);
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(StdDuration::from_millis(10));
            }
            Err(error) => {
                eprintln!("[FIX ] accept error: {error}");
                return;
            }
        }
    }
    let Some(stream) = stream else {
        return;
    };
    if stream.set_nonblocking(true).is_err() {
        return;
    }

    let mut device = QemuSocketDevice::new(stream);
    let peer_octets = PEER_IPV4.octets();
    let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress(
        PEER_MAC.octets(),
    )));
    config.random_seed = 0x4d37_0001;
    let mut iface = Interface::new(config, &mut device, Instant::from_millis(0));
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                IpAddress::v4(
                    peer_octets[0],
                    peer_octets[1],
                    peer_octets[2],
                    peer_octets[3],
                ),
                24,
            ))
            .expect("fixture IPv4");
        if options.m9_profile {
            addrs
                .push(IpCidr::new(IpAddress::v4(10, 77, 0, 50), 24))
                .expect("fixture M9 IPv4");
        }
    });

    let mut sockets = SocketSet::new(vec![]);
    let udp_echo = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
    );
    let udp_handle = sockets.add(udp_echo);
    let udp_dns = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
    );
    let dns_handle = sockets.add(udp_dns);

    let mut tcp_echo_service = if options.m9_profile {
        None
    } else {
        let tcp_echo = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        );
        let tcp_echo_handle = sockets.add(tcp_echo);
        Some(TcpEchoService::new(&mut sockets, tcp_echo_handle))
    };

    let tls_listen = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; 8192]),
        tcp::SocketBuffer::new(vec![0u8; 8192]),
    );
    let tls_handle = sockets.add(tls_listen);
    let tls_cert = match options.tls_cert {
        WhichCert::Correct => FixtureTlsCert::Correct,
        WhichCert::WrongName => FixtureTlsCert::WrongName,
    };
    let mut tls_service = TlsService::new(&mut sockets, tls_handle, tls_cert);

    let mut m9_http_service = None;
    if options.m9_profile {
        let m9_tcp = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        );
        let m9_handle = sockets.add(m9_tcp);
        m9_http_service = Some(M9HttpService::new(&mut sockets, m9_handle));
    }

    let mut timestamp = Instant::from_millis(0);
    while !stop.load(Ordering::SeqCst) {
        timestamp += Duration::from_millis(1);
        iface.poll(timestamp, &mut device, &mut sockets);

        let socket = sockets.get_mut::<udp::Socket>(udp_handle);
        if !socket.is_open() {
            socket.bind(UDP_ECHO_PORT).expect("bind udp echo");
        }
        if let Ok((payload, endpoint)) = socket.recv() {
            let len = payload.len();
            let echoed = payload.to_vec();
            if socket.send_slice(&echoed, endpoint).is_ok() {
                println!("[FIX ] udp echo len={len}");
            }
        }

        let dns_socket = sockets.get_mut::<udp::Socket>(dns_handle);
        if !dns_socket.is_open() {
            dns_socket.bind(DNS_SERVER_PORT).expect("bind udp dns");
        }
        if let Ok((payload, endpoint)) = dns_socket.recv() {
            if let Some((name, response)) = build_dns_response(payload, options.m9_profile) {
                let rcode = (response[3] & 0x0F) as u32;
                if !options.dns_reply_delay.is_zero() {
                    thread::sleep(options.dns_reply_delay);
                }
                if dns_socket.send_slice(&response, endpoint).is_ok() {
                    println!("[FIX ] dns query name={name} rcode={rcode}");
                }
            }
        }
        if let Some(echo) = tcp_echo_service.as_mut() {
            echo.poll(&mut sockets);
        }
        tls_service.poll(&mut sockets);
        if let Some(http) = m9_http_service.as_mut() {
            http.poll(&mut sockets);
        }

        for event in device.drain_events() {
            println!("{event}");
        }
        thread::sleep(StdDuration::from_millis(1));
    }
}

struct QemuSocketDevice {
    stream: TcpStream,
    /// Bytes received from QEMU that do not yet form a complete
    /// length-prefixed frame. The socket is non-blocking, so a read may stop
    /// mid-prefix or mid-frame; buffering keeps the stream in sync.
    pending: Vec<u8>,
    rx_queue: VecDeque<Vec<u8>>,
    events: Vec<String>,
}

impl QemuSocketDevice {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            pending: Vec::with_capacity(4 * (4 + MAX_FRAME_BYTES)),
            rx_queue: VecDeque::new(),
            events: Vec::new(),
        }
    }

    fn drain_events(&mut self) -> impl Iterator<Item = String> + '_ {
        self.events.drain(..)
    }

    fn read_frames_from_socket(&mut self) {
        let mut chunk = [0u8; 4096];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => self.pending.extend_from_slice(&chunk[..n]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => break,
            }
        }
        self.parse_pending_frames();
    }

    /// Splits complete `[u32 BE len][frame]` records out of `pending`.
    /// Oversized or zero-length records are skipped in full so the stream
    /// never desynchronises.
    fn parse_pending_frames(&mut self) {
        let mut offset = 0usize;
        while self.pending.len() - offset >= 4 {
            let len_bytes: [u8; 4] = self.pending[offset..offset + 4]
                .try_into()
                .expect("4-byte slice");
            let frame_len = u32::from_be_bytes(len_bytes) as usize;
            if self.pending.len() - offset - 4 < frame_len {
                break;
            }
            let start = offset + 4;
            let end = start + frame_len;
            if frame_len != 0 && frame_len <= MAX_FRAME_BYTES {
                let frame = self.pending[start..end].to_vec();
                if frame.len() >= 14 && u16::from_be_bytes([frame[12], frame[13]]) == 0x0806 {
                    self.events.push("[FIX ] arp request".to_owned());
                }
                self.rx_queue.push_back(frame);
            } else {
                self.events
                    .push(format!("[FIX ] dropped frame len={frame_len}"));
            }
            offset = end;
        }
        self.pending.drain(..offset);
    }

    fn write_frame_to_socket(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let len = u32::try_from(frame.len()).expect("frame length fits in u32");
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(frame)?;
        self.stream.flush()
    }
}

impl Device for QemuSocketDevice {
    type RxToken<'a> = QemuRxToken;
    type TxToken<'a> = QemuTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = MAX_FRAME_BYTES;
        caps.medium = Medium::Ethernet;
        caps
    }

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.read_frames_from_socket();
        let frame = self.rx_queue.pop_front()?;
        Some((QemuRxToken { frame }, QemuTxToken { device: self }))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(QemuTxToken { device: self })
    }
}

struct QemuRxToken {
    frame: Vec<u8>,
}

impl phy::RxToken for QemuRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.frame)
    }
}

struct QemuTxToken<'a> {
    device: &'a mut QemuSocketDevice,
}

const M9_HTTP_ADDR: [u8; 4] = [10, 77, 0, 50];

fn build_dns_response(query: &[u8], m9_profile: bool) -> Option<(String, Vec<u8>)> {
    if query.len() < 12 {
        return None;
    }
    let id = [query[0], query[1]];
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount != 1 {
        return None;
    }
    let (name, qend) = parse_dns_qname(query, 12)?;
    if qend + 4 > query.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[qend], query[qend + 1]]);
    if qtype == 28 && m9_profile {
        let question = query.get(12..qend + 4)?.to_vec();
        let mut response = Vec::with_capacity(question.len() + 16);
        response.extend_from_slice(&id);
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&question);
        return Some((name, response));
    }
    if qtype != 1 {
        return None;
    }
    let question = query.get(12..qend + 4)?.to_vec();
    let mut response = Vec::with_capacity(question.len() + 32);
    response.extend_from_slice(&id);
    let flags_ok = 0x8480u16;
    let answer: [u8; 4] = if m9_profile {
        M9_HTTP_ADDR
    } else {
        FIXTURE_A_RECORD.octets()
    };
    if name.eq_ignore_ascii_case(FIXTURE_HOSTNAME) {
        response.extend_from_slice(&flags_ok.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&question);
        response.push(0xC0);
        response.push(0x0C);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&FIXTURE_A_TTL_SECS.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&answer);
    } else {
        let flags_nx = flags_ok | 3u16;
        response.extend_from_slice(&flags_nx.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&question);
    }
    Some((name, response))
}

fn parse_dns_qname(msg: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut name = String::new();
    let mut first = true;
    while offset < msg.len() {
        let len = msg[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            return None;
        }
        offset += 1;
        if offset + len > msg.len() {
            return None;
        }
        if !first {
            name.push('.');
        }
        first = false;
        let label = msg.get(offset..offset + len)?;
        name.push_str(core::str::from_utf8(label).ok()?);
        offset += len;
    }
    Some((name, offset))
}

impl phy::TxToken for QemuTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if buffer.len() >= 14 {
            let eth_type = u16::from_be_bytes([buffer[12], buffer[13]]);
            if eth_type == 0x0806 {
                self.device.events.push("[FIX ] arp reply".to_owned());
            } else if eth_type == 0x0800 && buffer.len() >= 34 && buffer[23] == 1 {
                self.device.events.push("[FIX ] icmp echo".to_owned());
            }
        }
        let _ = self.device.write_frame_to_socket(&buffer);
        result
    }
}
