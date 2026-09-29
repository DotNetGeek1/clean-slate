//! Bounded raw-input queue with in-order loss records (wire §6.2, C5/C6).

use clean_slate_graphics::ids::InputDeviceId;
use clean_slate_graphics::limits::RAW_INPUT_COALESCE_HIGH_WATER;
use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord};

/// What one [`RawInputQueue::push`] did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PushOutcome {
    /// The queue went from empty to non-empty (the consumer wake edge).
    pub(crate) queued_into_empty: bool,
    pub(crate) dropped: bool,
    pub(crate) coalesced: bool,
}

pub(crate) struct RawInputQueue<const N: usize> {
    ring: [Option<RawInputRecord>; N],
    head: usize,
    len: usize,
    next_seq: u64,
    pending_dropped: u32,
    first_drop_device: Option<InputDeviceId>,
    last_time_ns: u64,
}

impl<const N: usize> RawInputQueue<N> {
    pub(crate) const fn new() -> Self {
        Self {
            ring: [const { None }; N],
            head: 0,
            len: 0,
            next_seq: 1,
            pending_dropped: 0,
            first_drop_device: None,
            last_time_ns: 0,
        }
    }

    pub(crate) fn push(
        &mut self,
        device: InputDeviceId,
        kind: RawInputKind,
        now_ns: u64,
    ) -> PushOutcome {
        let mut outcome = PushOutcome::default();
        let was_empty = self.len == 0 && self.pending_dropped == 0;
        let now = self.last_time_ns.max(now_ns);
        self.last_time_ns = now;
        let mut appended = false;

        if self.materialize_pending_overflow(now) {
            appended = true;
        }

        if let RawInputKind::RelMotion { dx, dy } = kind {
            if self.pending_dropped == 0 && self.len >= RAW_INPUT_COALESCE_HIGH_WATER {
                let tail_idx = (self.head + self.len - 1) % N;
                if let Some(tail) = &mut self.ring[tail_idx] {
                    if tail.device == device {
                        if let RawInputKind::RelMotion {
                            dx: ref mut tdx,
                            dy: ref mut tdy,
                        } = tail.kind
                        {
                            *tdx = tdx.saturating_add(dx);
                            *tdy = tdy.saturating_add(dy);
                            tail.time_ns = now;
                            outcome.coalesced = true;
                            outcome.queued_into_empty = was_empty && appended;
                            return outcome;
                        }
                    }
                }
            }
        }

        if self.len < N {
            self.push_record(device, kind, now);
            appended = true;
        } else {
            self.pending_dropped = self.pending_dropped.saturating_add(1);
            if self.first_drop_device.is_none() {
                self.first_drop_device = Some(device);
            }
            outcome.dropped = true;
        }

        outcome.queued_into_empty = was_empty && appended;
        outcome
    }

    pub(crate) fn pop(&mut self, now_ns: u64) -> Option<RawInputRecord> {
        if self.len > 0 {
            let record = self.ring[self.head].take()?;
            self.head = (self.head + 1) % N;
            self.len -= 1;
            return Some(record);
        }

        if self.pending_dropped > 0 {
            let now = self.last_time_ns.max(now_ns);
            self.last_time_ns = now;
            let device = self.first_drop_device?;
            let dropped = self.pending_dropped;
            self.pending_dropped = 0;
            self.first_drop_device = None;
            let seq = self.take_next_seq();
            return Some(RawInputRecord {
                seq,
                time_ns: now,
                device,
                kind: RawInputKind::Overflow { dropped },
            });
        }

        None
    }

    pub(crate) fn record_loss(&mut self, device: InputDeviceId) -> bool {
        let edge = self.len == 0 && self.pending_dropped == 0;
        self.pending_dropped = self.pending_dropped.saturating_add(1);
        if self.first_drop_device.is_none() {
            self.first_drop_device = Some(device);
        }
        edge
    }

    pub(crate) fn clear_into_loss(&mut self) {
        if self.len == 0 {
            return;
        }
        if self.first_drop_device.is_none() {
            if let Some(record) = &self.ring[self.head] {
                self.first_drop_device = Some(record.device);
            }
        }
        let add = u32::try_from(self.len).unwrap_or(u32::MAX);
        self.pending_dropped = self.pending_dropped.saturating_add(add);
        for slot in &mut self.ring {
            *slot = None;
        }
        self.head = 0;
        self.len = 0;
    }

    #[cfg(any(test, feature = "m10-input-self-test"))]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    #[cfg(any(test, feature = "m10-input-self-test"))]
    pub(crate) fn pending_dropped(&self) -> u32 {
        self.pending_dropped
    }

    #[cfg(test)]
    pub(crate) fn is_empty_including_pending(&self) -> bool {
        self.len == 0 && self.pending_dropped == 0
    }

    fn take_next_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }

    fn push_record(&mut self, device: InputDeviceId, kind: RawInputKind, now: u64) {
        let idx = (self.head + self.len) % N;
        let seq = self.take_next_seq();
        self.ring[idx] = Some(RawInputRecord {
            seq,
            time_ns: now,
            device,
            kind,
        });
        self.len += 1;
    }

    fn materialize_pending_overflow(&mut self, now: u64) -> bool {
        if self.pending_dropped == 0 || self.len >= N {
            return false;
        }
        let Some(device) = self.first_drop_device else {
            return false;
        };
        let dropped = self.pending_dropped;
        self.pending_dropped = 0;
        self.first_drop_device = None;
        self.push_record(device, RawInputKind::Overflow { dropped }, now);
        true
    }
}

#[cfg(test)]
mod tests;
