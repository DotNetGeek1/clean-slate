//! Deterministic passive TCP responder for host tests (one connection at a time).

use crate::addr::{IpProtocol, Ipv4Addr, SocketAddrV4};
use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::fixture::{APP_REQUEST_BYTES, APP_RESPONSE_BYTES, PEER_IPV4, TCP_ECHO_PORT};
use crate::stack::{Inbound, L3Stack};
use crate::tcp::conn::write_tcp_to_buf;
use crate::tcp::segment::{parse as parse_tcp, TcpFlags, TcpSegment, OUR_TCP_MSS};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
enum PeerState {
    Listen,
    SynReceived,
    Established,
    CloseWait,
}

/// Minimal host-side TCP echo peer on [`TCP_ECHO_PORT`].
pub struct TestPeer<L: NetworkLink> {
    stack: L3Stack<L>,
    state: PeerState,
    local: SocketAddrV4,
    remote: Option<SocketAddrV4>,
    iss: u32,
    snd_nxt: u32,
    rcv_nxt: u32,
    recv_acc: [u8; 4096],
    recv_len: usize,
    drop_inbound_remaining: u32,
    drop_outbound_remaining: u32,
    reply_rst_next: bool,
    bad_ack_next: bool,
    out_of_order_next: bool,
    stop_acking: bool,
    syn_ack_piggyback: Option<&'static [u8]>,
    banner_on_establish: Option<&'static [u8]>,
}

impl<L: NetworkLink> TestPeer<L> {
    pub fn new(stack: L3Stack<L>) -> Self {
        Self {
            stack,
            state: PeerState::Listen,
            local: SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT),
            remote: None,
            iss: 1_000,
            snd_nxt: 1_000,
            rcv_nxt: 0,
            recv_acc: [0; 4096],
            recv_len: 0,
            drop_inbound_remaining: 0,
            drop_outbound_remaining: 0,
            reply_rst_next: false,
            bad_ack_next: false,
            out_of_order_next: false,
            stop_acking: false,
            syn_ack_piggyback: None,
            banner_on_establish: None,
        }
    }

    pub fn set_syn_ack_piggyback(&mut self, payload: &'static [u8]) {
        self.syn_ack_piggyback = Some(payload);
    }

    pub fn set_banner_on_establish(&mut self, payload: &'static [u8]) {
        self.banner_on_establish = Some(payload);
    }

    pub fn stack_mut(&mut self) -> &mut L3Stack<L> {
        &mut self.stack
    }

    pub fn drop_next_n_segments(&mut self, n: u32) {
        self.drop_inbound_remaining = n;
    }

    /// Drops the next `n` TCP segments the peer would transmit (forces guest retransmit).
    pub fn drop_next_n_outbound(&mut self, n: u32) {
        self.drop_outbound_remaining = n;
    }

    pub fn reply_rst_on_next(&mut self) {
        self.reply_rst_next = true;
    }

    pub fn send_bad_ack(&mut self) {
        self.bad_ack_next = true;
    }

    pub fn send_out_of_order_data(&mut self) {
        self.out_of_order_next = true;
    }

    pub fn stop_acking(&mut self) {
        self.stop_acking = true;
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
                if self.drop_inbound_remaining > 0 {
                    self.drop_inbound_remaining -= 1;
                    continue;
                }
                if self.reply_rst_next {
                    self.reply_rst_next = false;
                    let remote = SocketAddrV4::new(src, seg.src_port);
                    self.send_rst(now, remote, self.snd_nxt)?;
                    continue;
                }
                self.handle_segment(now, src, &seg, payload)?;
            }
        }
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
                    if let Some(banner) = self.banner_on_establish {
                        let data = TcpSegment {
                            src_port: self.local.port,
                            dst_port: seg.src_port,
                            seq: self.snd_nxt,
                            ack: self.rcv_nxt,
                            data_offset: 5,
                            flags: TcpFlags::ACK.union(TcpFlags::PSH),
                            window: 4096,
                            checksum: 0,
                            urgent: 0,
                            mss_option: None,
                        };
                        self.transmit(now, remote, &data, banner)?;
                        self.snd_nxt = self.snd_nxt.wrapping_add(banner.len() as u32);
                    }
                } else if seg.flags.contains(TcpFlags::SYN) {
                    self.send_syn_ack(now, remote, seg.src_port)?;
                }
            }
            PeerState::Established => {
                if self.bad_ack_next {
                    self.bad_ack_next = false;
                    let bad = TcpSegment {
                        src_port: self.local.port,
                        dst_port: seg.src_port,
                        seq: self.snd_nxt,
                        ack: 0,
                        data_offset: 5,
                        flags: TcpFlags::ACK,
                        window: 4096,
                        checksum: 0,
                        urgent: 0,
                        mss_option: None,
                    };
                    self.transmit(now, remote, &bad, &[])?;
                    return Ok(());
                }
                if self.out_of_order_next {
                    self.out_of_order_next = false;
                    let ooo = TcpSegment {
                        src_port: self.local.port,
                        dst_port: seg.src_port,
                        seq: self.rcv_nxt.wrapping_add(1000),
                        ack: seg.seq,
                        data_offset: 5,
                        flags: TcpFlags::ACK.union(TcpFlags::PSH),
                        window: 4096,
                        checksum: 0,
                        urgent: 0,
                        mss_option: None,
                    };
                    self.transmit(now, remote, &ooo, b"ooo")?;
                    return Ok(());
                }
                if !payload.is_empty() && seg.seq == self.rcv_nxt {
                    let take = payload.len().min(self.recv_acc.len() - self.recv_len);
                    self.recv_acc[self.recv_len..self.recv_len + take]
                        .copy_from_slice(payload.get(..take).unwrap_or(&[]));
                    self.recv_len += take;
                    self.rcv_nxt = self.rcv_nxt.wrapping_add(take as u32);
                    if !self.stop_acking {
                        self.send_ack(now, remote)?;
                        if &self.recv_acc[..self.recv_len] == APP_REQUEST_BYTES {
                            self.transmit(
                                now,
                                remote,
                                &TcpSegment {
                                    src_port: self.local.port,
                                    dst_port: seg.src_port,
                                    seq: self.snd_nxt,
                                    ack: self.rcv_nxt,
                                    data_offset: 5,
                                    flags: TcpFlags::ACK.union(TcpFlags::PSH),
                                    window: 4096,
                                    checksum: 0,
                                    urgent: 0,
                                    mss_option: None,
                                },
                                APP_RESPONSE_BYTES,
                            )?;
                            self.snd_nxt =
                                self.snd_nxt.wrapping_add(APP_RESPONSE_BYTES.len() as u32);
                        }
                    }
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
                }
            }
            PeerState::CloseWait => {
                if seg.flags.contains(TcpFlags::ACK) {
                    self.state = PeerState::Listen;
                    self.remote = None;
                    self.recv_len = 0;
                }
            }
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
        let piggy = self.syn_ack_piggyback.unwrap_or(&[]);
        self.transmit(now, remote, &syn_ack, piggy)
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

    fn send_rst(&mut self, now: u64, remote: SocketAddrV4, seq: u32) -> Result<(), NetworkError> {
        let seg = TcpSegment {
            src_port: self.local.port,
            dst_port: remote.port,
            seq,
            ack: 0,
            data_offset: 5,
            flags: TcpFlags::RST.union(TcpFlags::ACK),
            window: 0,
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
        if self.drop_outbound_remaining > 0 {
            self.drop_outbound_remaining -= 1;
            return Ok(());
        }
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
