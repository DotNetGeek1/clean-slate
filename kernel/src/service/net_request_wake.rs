//! Per-request and net-service wait keys for M7 bridge blocking (#167).

use crate::sched::wait::{wake_all, WaitKey};

/// In-flight M7 bridge request completion (shared with Linux socket broker #105).
pub(crate) fn net_bridge_request_wait_key(request_id: u64) -> WaitKey {
    WaitKey((0x54u64 << 56) | request_id)
}

const NET_SERVICE_WORK_KEY: WaitKey = WaitKey(0x55_u64 << 56);

pub(crate) fn net_service_work_wait_key() -> WaitKey {
    NET_SERVICE_WORK_KEY
}

pub(crate) fn wake_net_service_work() {
    wake_all(NET_SERVICE_WORK_KEY);
}

pub(crate) fn notify_net_request_complete(request_id: u64) -> usize {
    wake_all(net_bridge_request_wait_key(request_id))
}
