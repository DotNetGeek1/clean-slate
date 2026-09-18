//! TCP transport counters.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpStats {
    pub dropped_bad_checksum: u64,
    pub dropped_out_of_order: u64,
    pub dropped_bad_ack: u64,
    pub dropped_no_conn: u64,
    pub resets_received: u64,
    pub resets_sent: u64,
    pub retransmits: u64,
    pub timeouts: u64,
    pub segments_sent: u64,
    pub segments_received: u64,
}
