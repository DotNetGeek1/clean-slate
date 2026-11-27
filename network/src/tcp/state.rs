//! TCP connection states (RFC 793 §3.2, without LISTEN: listeners live in their own table).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
    CloseWait,
    LastAck,
    Reset,
}

impl TcpState {
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed | Self::Reset)
    }

    /// The handshake has completed (sequence numbers are synchronized both ways).
    pub const fn is_synchronized(self) -> bool {
        !matches!(
            self,
            Self::Closed | Self::SynSent | Self::SynReceived | Self::Reset
        )
    }
}
