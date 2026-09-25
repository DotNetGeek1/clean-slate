//! Per-request and net-service wait keys for M7 bridge blocking (#167).

use crate::sched::wait::{wake_all, WaitKey};
use crate::sync::global_cell::GlobalCell;

/// In-flight M7 bridge request completion (shared with Linux socket broker #105).
pub(crate) fn net_bridge_request_wait_key(request_id: u64) -> WaitKey {
    WaitKey((0x54u64 << 56) | request_id)
}

const NET_SERVICE_WORK_KEY: WaitKey = WaitKey(0x55_u64 << 56);
const NET_SERVICE_RX_KEY: WaitKey = WaitKey((0x55_u64 << 56) | 1);

pub(crate) fn net_service_work_wait_key() -> WaitKey {
    NET_SERVICE_WORK_KEY
}

pub(crate) fn net_service_rx_wait_key() -> WaitKey {
    NET_SERVICE_RX_KEY
}

pub(crate) fn wake_net_service_work() {
    wake_all(NET_SERVICE_WORK_KEY);
}

pub(crate) fn wake_net_service_rx() {
    wake_all(NET_SERVICE_RX_KEY);
}

static REQUEST_WAKE_SLOT: GlobalCell<[Option<(u64, WaitKey)>; 16]> = GlobalCell::new([None; 16]);

pub(crate) fn notify_net_request_complete(request_id: u64) -> usize {
    let mut woken = 0usize;
    let wakes = unsafe { &mut *REQUEST_WAKE_SLOT.get() };
    for entry in wakes.iter_mut() {
        if entry.map(|(id, _)| id) == Some(request_id) {
            if let Some((_, key)) = *entry {
                woken = wake_all(key);
            }
            *entry = None;
        }
    }
    woken
}

pub(crate) fn register_net_request_wake(request_id: u64, key: WaitKey) {
    let wakes = unsafe { &mut *REQUEST_WAKE_SLOT.get() };
    for entry in wakes.iter_mut() {
        if entry.map(|(id, _)| id) == Some(request_id) {
            *entry = Some((request_id, key));
            return;
        }
    }
    for entry in wakes.iter_mut() {
        if entry.is_none() {
            *entry = Some((request_id, key));
            return;
        }
    }
}

pub(crate) fn clear_net_request_wake(request_id: u64) {
    let wakes = unsafe { &mut *REQUEST_WAKE_SLOT.get() };
    for entry in wakes.iter_mut() {
        if entry.map(|(id, _)| id) == Some(request_id) {
            *entry = None;
        }
    }
}
