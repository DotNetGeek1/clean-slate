//! Per-request and net-service wait keys for M7 bridge blocking (#167).

use crate::sched::wait::{wake_all, wake_all_registered, WaitKey};

/// In-flight M7 bridge request completion (shared with Linux socket broker #105).
pub(crate) fn net_bridge_request_wait_key(request_id: u64) -> WaitKey {
    WaitKey((0x54u64 << 56) | request_id)
}

const NET_SERVICE_WORK_KEY: WaitKey = WaitKey(0x55_u64 << 56);

pub(crate) fn net_service_work_wait_key() -> WaitKey {
    NET_SERVICE_WORK_KEY
}

/// `NET_SUBOP_WAIT_WORK` blocks with `NativeOutcome`, which takes the pending-wake shortcut;
/// the key is fixed, so it holds at most one pending-wake slot.
pub(crate) fn wake_net_service_work() {
    wake_all(NET_SERVICE_WORK_KEY);
}

/// A raw transmit found the NIC's TX ring full and waits for a completion.
const NET_TX_SPACE_KEY: WaitKey = WaitKey(0x56_u64 << 56);

pub(crate) fn net_tx_space_wait_key() -> WaitKey {
    NET_TX_SPACE_KEY
}

/// The virtio-net TX interrupt sink; host tests never discover a NIC to install it on.
#[cfg_attr(test, allow(dead_code))]
pub(crate) fn wake_net_tx_space() {
    wake_all_registered(NET_TX_SPACE_KEY);
}

/// Request ids are never reused, so a pending wake recorded for a completion that lands before
/// the client polls would hold its slot forever (#287). Both waiters (`NET_SUBOP_POLL` and the
/// Linux socket broker) check the request and register in one masked syscall.
pub(crate) fn notify_net_request_complete(request_id: u64) -> usize {
    wake_all_registered(net_bridge_request_wait_key(request_id))
}
