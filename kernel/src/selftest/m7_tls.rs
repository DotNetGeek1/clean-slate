use core::arch::x86_64::_rdrand64_step;
use core::hint::spin_loop;
use core::mem::MaybeUninit;

use clean_slate_network::addr::SocketAddrV4;
use clean_slate_network::device::NetworkLink;
use clean_slate_network::error::NetworkError;
use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, GUEST_IPV4, PEER_IPV4, PEER_MAC, TCP_ECHO_PORT,
    TLS_PORT, TLS_SERVER_NAME,
};
use clean_slate_network::protocol::TrustedCaller;
use clean_slate_network::session::SessionGeneration;
use clean_slate_network::session::SessionId;
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::{TcpState, TcpTransport};
use clean_slate_network::tls::{
    TlsConfig, TlsError, TlsSession, TLS_RECORD_BUFFER_BYTES, VALIDATION_TIME_UNIX,
};
use rand_core::{CryptoRng, RngCore};

use crate::device::virtio::net::VirtioNetDevice;
use crate::{serial_write_fmt, serial_write_line};

const OWNER: TrustedCaller = TrustedCaller::new(1, 0, 1);
const ARP_TTL: u64 = 50_000;
const POLL_LIMIT: usize = 50_000_000;

static mut TCP_TRANSPORT: MaybeUninit<TcpTransport<VirtioNetDevice>> = MaybeUninit::uninit();
static mut TCP_TRANSPORT_READY: bool = false;

static mut TLS_READ_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];
static mut TLS_WRITE_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];

pub struct RdrandRng;

impl CryptoRng for RdrandRng {}

impl RngCore for RdrandRng {
    fn next_u32(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut word = 0u64;
        while unsafe { _rdrand64_step(&mut word) } == 0 {
            spin_loop();
        }
        word
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut offset = 0usize;
        while offset < dest.len() {
            let mut word = 0u64;
            while unsafe { _rdrand64_step(&mut word) } == 0 {
                spin_loop();
            }
            let take = (dest.len() - offset).min(8);
            dest[offset..offset + take].copy_from_slice(&word.to_le_bytes()[..take]);
            offset += take;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

pub(crate) fn run_m7_tls_self_test() -> Result<(), &'static str> {
    let tcp = tcp_transport()?;
    let mut tick = 0u64;
    tick = run_tcp_echo_phase(tcp, tick)?;
    run_tls_phase(tcp, false, tick)
}

pub(crate) fn run_m7_tls_fail_closed_self_test() -> Result<(), &'static str> {
    let tcp = tcp_transport()?;
    run_tls_phase(tcp, true, 0)
}

fn tcp_transport() -> Result<&'static mut TcpTransport<VirtioNetDevice>, &'static str> {
    unsafe {
        if !TCP_TRANSPORT_READY {
            let device = VirtioNetDevice::discover()?;
            let mac = device.link().mac;
            let stack = L3Stack::new(device, mac, GUEST_IPV4, ARP_TTL);
            let slot = TCP_TRANSPORT.as_mut_ptr();
            TcpTransport::init_in_place(slot, stack, SessionGeneration::new(1));
            (*TCP_TRANSPORT.as_mut_ptr())
                .stack_mut()
                .arp_cache_mut()
                .insert(PEER_IPV4, PEER_MAC, 0);
            TCP_TRANSPORT_READY = true;
        }
        Ok(&mut *TCP_TRANSPORT.as_mut_ptr())
    }
}

#[inline(never)]
fn run_tcp_echo_phase(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    tick: u64,
) -> Result<u64, &'static str> {
    let remote_echo = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
    let mut tick = tick;
    let echo_id = tcp
        .connect(tick, OWNER, remote_echo)
        .map_err(|_| "tcp echo connect failed")?;
    tick = drive_tcp_until(tcp, echo_id, tick, TcpState::Established)?;
    serial_write_fmt(format_args!(
        "[TCP ] connected peer={}.{}.{}.{}:{}\n",
        PEER_IPV4.octets()[0],
        PEER_IPV4.octets()[1],
        PEER_IPV4.octets()[2],
        PEER_IPV4.octets()[3],
        TCP_ECHO_PORT
    ));
    tick = tick.saturating_add(1);
    tcp.send(tick, echo_id, OWNER, APP_REQUEST_BYTES)
        .map_err(|_| "tcp echo send failed")?;
    tick = tick.saturating_add(1);
    let mut buf = [0u8; 64];
    let (n, tick) = receive_all(tcp, echo_id, tick, &mut buf)?;
    if &buf[..n] != APP_RESPONSE_BYTES {
        return Err("tcp echo response mismatch");
    }
    serial_write_fmt(format_args!("[TCP ] echo ok len={n}\n"));
    let _ = tcp.close(tick, echo_id, OWNER);
    poll_for_ticks(tcp, tick.saturating_add(1), 10_000)?;
    Ok(tick)
}

#[inline(never)]
fn run_tls_phase(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    expect_identity_failure: bool,
    mut tick: u64,
) -> Result<(), &'static str> {
    let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
    let config = TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX);
    let remote_tls = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
    let read_buf = unsafe { &mut *core::ptr::addr_of_mut!(TLS_READ_BUF) };
    let write_buf = unsafe { &mut *core::ptr::addr_of_mut!(TLS_WRITE_BUF) };
    tick = tick.saturating_add(1);
    let tls_result = TlsSession::connect(
        tick, tcp, OWNER, remote_tls, config, RdrandRng, read_buf, write_buf,
    );
    if expect_identity_failure {
        return match tls_result {
            Err(TlsError::PeerIdentity) => {
                serial_write_fmt(format_args!(
                    "[TLS ] peer identity rejected name={}\n",
                    TLS_SERVER_NAME
                ));
                serial_write_line("[M7.6] FAIL-CLOSED OK");
                Ok(())
            }
            Ok(_) => Err("expected peer identity failure"),
            Err(_) => Err("unexpected tls error for fail-closed boot"),
        };
    }
    let mut tls = tls_result.map_err(|_| "tls connect failed")?;
    serial_write_fmt(format_args!(
        "[TLS ] authenticated peer={}\n",
        tls.peer_name()
    ));
    tick = tick.saturating_add(100);
    tls.write(tick, APP_REQUEST_BYTES)
        .map_err(|_| "tls write failed")?;
    let mut app_buf = [0u8; 64];
    tick = tick.saturating_add(100);
    let n = tls
        .read(tick, &mut app_buf)
        .map_err(|_| "tls read failed")?;
    if &app_buf[..n] != APP_RESPONSE_BYTES {
        return Err("tls app response mismatch");
    }
    serial_write_fmt(format_args!("[TLS ] app bytes ok len={n}\n"));
    tick = tick.saturating_add(100);
    tls.close(tick).map_err(|_| "tls close failed")?;
    serial_write_line("[TLS ] closed");
    serial_write_line("[M7.6] PASS");
    Ok(())
}

fn drive_tcp_until(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    id: SessionId,
    mut tick: u64,
    target: TcpState,
) -> Result<u64, &'static str> {
    for _ in 0..POLL_LIMIT {
        tcp.poll(tick).map_err(|_| "tcp poll failed")?;
        match tcp.state(id, OWNER) {
            Ok(s) if s == target => return Ok(tick),
            Ok(TcpState::Reset) | Ok(TcpState::Closed) => return Err("tcp drive reset"),
            Err(_) => return Err("tcp drive stale session"),
            Ok(_) => {}
        }
        tick = tick.saturating_add(1);
        spin_loop();
    }
    Err("tcp drive timeout")
}

fn poll_for_ticks(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    mut tick: u64,
    count: usize,
) -> Result<u64, &'static str> {
    for _ in 0..count {
        tcp.poll(tick).map_err(|_| "tcp poll failed")?;
        tick = tick.saturating_add(1);
        spin_loop();
    }
    Ok(tick)
}

fn receive_all(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    id: SessionId,
    mut tick: u64,
    out: &mut [u8],
) -> Result<(usize, u64), &'static str> {
    let mut total = 0usize;
    for _ in 0..POLL_LIMIT {
        tcp.poll(tick).map_err(|_| "tcp poll failed")?;
        let n = match tcp.receive(id, OWNER, &mut out[total..]) {
            Ok(n) => n,
            Err(NetworkError::Closed) | Err(NetworkError::Reset) if total == 0 => {
                tick = tick.saturating_add(1);
                spin_loop();
                continue;
            }
            Err(NetworkError::NotFound) => return Err("tcp recv stale"),
            Err(_) => return Err("tcp recv"),
        };
        total += n;
        if total >= APP_RESPONSE_BYTES.len() {
            return Ok((total, tick));
        }
        tick = tick.saturating_add(1);
        spin_loop();
    }
    Err("tcp receive timeout")
}
