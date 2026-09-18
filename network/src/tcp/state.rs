//! Client TCP states (active open only).

/// TCP connection state for the client-only subset implemented in M7.4c.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    SynSent,
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
}
