//! Hermetic M7 QEMU raw-Ethernet peer (host-side smoltcp stack).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration as StdDuration;

use clean_slate_network::fixture::{PEER_IPV4, PEER_MAC, UDP_ECHO_PORT};
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::udp;
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

const MAX_FRAME_BYTES: usize = 1514;

pub struct M7FixturePeer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl M7FixturePeer {
    pub fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let handle = thread::spawn(move || run_peer(listener, stop_flag));
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

fn run_peer(listener: TcpListener, stop: Arc<AtomicBool>) {
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
    });

    let mut sockets = SocketSet::new(vec![]);
    let udp_echo = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]),
    );
    let udp_handle = sockets.add(udp_echo);

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

        for event in device.drain_events() {
            println!("{event}");
        }
        thread::sleep(StdDuration::from_millis(1));
    }
}

struct QemuSocketDevice {
    stream: TcpStream,
    rx_queue: VecDeque<Vec<u8>>,
    events: Vec<String>,
}

impl QemuSocketDevice {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            rx_queue: VecDeque::new(),
            events: Vec::new(),
        }
    }

    fn drain_events(&mut self) -> impl Iterator<Item = String> + '_ {
        self.events.drain(..)
    }

    fn read_frames_from_socket(&mut self) {
        loop {
            let mut len_buf = [0u8; 4];
            match self.stream.read_exact(&mut len_buf) {
                Ok(()) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break;
                }
                Err(_) => break,
            }
            let frame_len = u32::from_be_bytes(len_buf) as usize;
            if frame_len == 0 || frame_len > MAX_FRAME_BYTES {
                continue;
            }
            let mut frame = vec![0u8; frame_len];
            if self.stream.read_exact(&mut frame).is_err() {
                break;
            }
            if frame.len() >= 14 && u16::from_be_bytes([frame[12], frame[13]]) == 0x0806 {
                self.events.push("[FIX ] arp request".to_owned());
            }
            self.rx_queue.push_back(frame);
        }
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
