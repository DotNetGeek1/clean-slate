//! M6.7 bounded audit-event ring (`AuditSink` implementation, host-testable).

use crate::audit::{AuditEvent, AuditSink};

/// Fixed-capacity ring of [`AuditEvent`] records with monotonic kernel-assigned sequences.
pub struct BoundedAuditLog<const N: usize> {
    events: [AuditEvent; N],
    start: usize,
    len: usize,
    next_sequence: u64,
    dropped: u64,
}

impl<const N: usize> BoundedAuditLog<N> {
    pub const fn new() -> Self {
        Self {
            events: [const { dummy_event() }; N],
            start: 0,
            len: 0,
            next_sequence: 1,
            dropped: 0,
        }
    }

    pub const fn capacity(&self) -> usize {
        N
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn oldest_sequence(&self) -> Option<u64> {
        if self.len == 0 {
            None
        } else {
            Some(self.events[self.start].sequence)
        }
    }

    pub fn newest_sequence(&self) -> Option<u64> {
        if self.len == 0 {
            None
        } else {
            let index = (self.start + self.len - 1) % N;
            Some(self.events[index].sequence)
        }
    }

    /// Copies events with `sequence >= since` into `out` (oldest first).
    ///
    /// Returns `(count, next_since)` where `next_since` is one past the last returned
    /// sequence, or `self.next_sequence()` when nothing matched.
    pub fn read_from(&self, since: u64, out: &mut [AuditEvent]) -> (usize, u64) {
        if self.len == 0 || out.is_empty() {
            return (0, self.next_sequence);
        }
        let mut written = 0usize;
        let mut last_sequence = 0u64;
        for offset in 0..self.len {
            let index = (self.start + offset) % N;
            let event = self.events[index];
            if event.sequence < since {
                continue;
            }
            if written >= out.len() {
                break;
            }
            out[written] = event;
            last_sequence = event.sequence;
            written += 1;
        }
        let next_since = if written == 0 {
            self.next_sequence
        } else {
            last_sequence + 1
        };
        (written, next_since)
    }

    pub fn get(&self, sequence: u64) -> Option<AuditEvent> {
        for offset in 0..self.len {
            let index = (self.start + offset) % N;
            let event = self.events[index];
            if event.sequence == sequence {
                return Some(event);
            }
        }
        None
    }

    fn push_event(&mut self, event: AuditEvent) {
        if self.len < N {
            let index = (self.start + self.len) % N;
            self.events[index] = event;
            self.len += 1;
        } else {
            self.events[self.start] = event;
            self.start = (self.start + 1) % N;
            self.dropped += 1;
        }
    }
}

impl<const N: usize> AuditSink for BoundedAuditLog<N> {
    fn record(&mut self, mut event: AuditEvent) {
        event.sequence = self.next_sequence;
        self.next_sequence += 1;
        self.push_event(event);
    }
}

impl<const N: usize> Default for BoundedAuditLog<N> {
    fn default() -> Self {
        Self::new()
    }
}

const fn dummy_event() -> AuditEvent {
    AuditEvent {
        sequence: 0,
        actor: crate::holder::HolderId(0),
        class: crate::resource::ResourceClass::PersistentObject,
        _pad_class: [0; 7],
        resource_id: 0,
        requested: crate::rights::Rights::empty(),
        _pad_rights: 0,
        handle: 0,
        outcome: crate::audit::AuditOutcome::allowed(),
        depth: 0,
        _pad_tail: [0; 7],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{authorize_audited, format_audit_line, AuditOutcome};
    use crate::{
        CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityState, HolderId, Provenance,
        ResourceRef, Rights, AUDIT_EVENT_SIZE_BYTES,
    };

    fn live_record(
        holder: HolderId,
        resource: ResourceRef,
        rights: Rights,
        generation: u32,
    ) -> CapabilityRecord {
        CapabilityRecord {
            state: CapabilityState::Live,
            holder,
            resource,
            rights,
            provenance: Provenance::root(holder),
            generation,
        }
    }

    #[test]
    fn sequences_monotonic_from_log() {
        let mut log = BoundedAuditLog::<4>::new();
        assert_eq!(log.next_sequence(), 1);
        for seq in [99u64, 1, 42] {
            let event = crate::audit::event_for(
                seq,
                HolderId(1),
                ResourceRef::object(1),
                Rights::READ,
                CapabilityHandle::new(0, 1),
                0,
                Ok(()),
            );
            log.record(event);
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.oldest_sequence(), Some(1));
        assert_eq!(log.newest_sequence(), Some(3));
        assert_eq!(log.get(2).unwrap().sequence, 2);
    }

    #[test]
    fn overflow_drops_oldest() {
        let mut log = BoundedAuditLog::<4>::new();
        for _ in 0..6 {
            let event = crate::audit::event_for(
                0,
                HolderId(1),
                ResourceRef::object(1),
                Rights::READ,
                CapabilityHandle::INVALID,
                0,
                Ok(()),
            );
            log.record(event);
        }
        assert_eq!(log.len(), 4);
        assert_eq!(log.dropped(), 2);
        assert_eq!(log.oldest_sequence(), Some(3));
        assert_eq!(log.newest_sequence(), Some(6));
        let mut buf = [dummy_event(); 8];
        let (count, next) = log.read_from(1, &mut buf);
        assert_eq!(count, 4);
        assert_eq!(next, 7);
        assert_eq!(buf[0].sequence, 3);
        assert_eq!(buf[3].sequence, 6);
        let (count, next) = log.read_from(5, &mut buf[..2]);
        assert_eq!(count, 2);
        assert_eq!(next, 7);
        assert_eq!(buf[0].sequence, 5);
        assert_eq!(buf[1].sequence, 6);
        let (count, next) = log.read_from(99, &mut buf);
        assert_eq!(count, 0);
        assert_eq!(next, 7);
    }

    #[test]
    fn authorize_audited_records_errors() {
        let holder = HolderId(3);
        let resource = ResourceRef::object(2);
        let handle = CapabilityHandle::new(1, 2);
        let record = live_record(holder, resource, Rights::READ, 2);
        let mut log = BoundedAuditLog::<8>::new();

        assert!(
            authorize_audited(&mut log, 0, &record, handle, holder, resource, Rights::READ).is_ok()
        );
        assert_eq!(log.get(1).unwrap().outcome.tag, AuditOutcome::TAG_ALLOWED);

        let wrong_holder = HolderId(9);
        assert_eq!(
            authorize_audited(
                &mut log,
                0,
                &record,
                handle,
                wrong_holder,
                resource,
                Rights::READ
            ),
            Err(CapabilityError::UnauthorizedHolder)
        );
        assert_eq!(
            CapabilityError::from_u8(log.get(2).unwrap().outcome.error_code),
            Some(CapabilityError::UnauthorizedHolder)
        );

        assert_eq!(
            authorize_audited(
                &mut log,
                0,
                &record,
                handle,
                holder,
                resource,
                Rights::WRITE
            ),
            Err(CapabilityError::MissingRight)
        );
        assert_eq!(
            CapabilityError::from_u8(log.get(3).unwrap().outcome.error_code),
            Some(CapabilityError::MissingRight)
        );

        let mut stale = record;
        stale.state = CapabilityState::Revoked;
        assert_eq!(
            authorize_audited(&mut log, 0, &stale, handle, holder, resource, Rights::READ),
            Err(CapabilityError::Revoked)
        );
        assert_eq!(
            CapabilityError::from_u8(log.get(4).unwrap().outcome.error_code),
            Some(CapabilityError::Revoked)
        );

        stale.state = CapabilityState::Live;
        stale.generation = 1;
        assert_eq!(
            authorize_audited(&mut log, 0, &stale, handle, holder, resource, Rights::READ),
            Err(CapabilityError::StaleHandle)
        );
        assert_eq!(
            CapabilityError::from_u8(log.get(5).unwrap().outcome.error_code),
            Some(CapabilityError::StaleHandle)
        );
    }

    #[test]
    fn format_audit_line_exact() {
        let allowed = crate::audit::event_for(
            7,
            HolderId(5),
            ResourceRef::process(9, 1),
            Rights::OBSERVE,
            CapabilityHandle::new(2, 3),
            0,
            Ok(()),
        );
        let mut line = alloc::string::String::new();
        format_audit_line(&allowed, &mut line).unwrap();
        assert_eq!(
            line,
            "[AUD ] seq=7 actor=5 class=process-control resource=9 op=observe outcome=allowed depth=0"
        );

        let denied = crate::audit::event_for(
            8,
            HolderId(5),
            ResourceRef::process(9, 1),
            Rights::TERMINATE,
            CapabilityHandle::new(2, 3),
            0,
            Err(CapabilityError::MissingRight),
        );
        line.clear();
        format_audit_line(&denied, &mut line).unwrap();
        assert_eq!(
            line,
            "[AUD ] seq=8 actor=5 class=process-control resource=9 op=terminate outcome=missing-right depth=0"
        );
        assert_eq!(AUDIT_EVENT_SIZE_BYTES, 64);
        assert_eq!(core::mem::size_of::<AuditEvent>(), 64);
    }
}
