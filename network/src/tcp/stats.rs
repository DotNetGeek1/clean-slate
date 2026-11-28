//! TCP transport counters.

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TcpStats {
    pub dropped_bad_checksum: u64,
    /// Unacceptable segments (outside the receive window, duplicates, blind RST/SYN) and
    /// out-of-order segments that did not fit the reassembly ranges.
    pub dropped_out_of_order: u64,
    pub dropped_bad_ack: u64,
    pub dropped_no_conn: u64,
    pub resets_received: u64,
    pub resets_sent: u64,
    /// Retransmission timeouts (each resends at least one segment).
    pub retransmits: u64,
    /// Retransmissions after three duplicate ACKs.
    pub fast_retransmits: u64,
    /// Zero-window probes started by the persist timer.
    pub window_probes: u64,
    /// Segments held for reassembly ahead of a gap.
    pub out_of_order_queued: u64,
    /// SYNs to a listener that started a passive open.
    pub passive_opens: u64,
    /// SYNs to a listener whose backlog (or the connection table) was full; each is answered
    /// with RST (and counted in `resets_sent` too).
    pub dropped_syn_backlog: u64,
    pub timeouts: u64,
    pub segments_sent: u64,
    pub segments_received: u64,
}
