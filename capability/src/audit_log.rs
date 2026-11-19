//! M6.7 bounded audit-event ring (`AuditSink` implementation, host-testable).

use crate::audit::{AuditEvent, AuditSink};

/// Fixed-capacity ring of [`AuditEvent`] records with contiguous kernel-assigned sequences.
///
/// When full, a new record overwrites the oldest. Nothing is lost silently: every record,
/// stored or not, consumes a sequence; [`Self::dropped`] counts the ones no longer held; and
/// [`Self::read_from`] returns an [`crate::AuditKind::Lost`] record for every gap a reader's
/// cursor runs into.
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
            events: [AuditEvent::EMPTY; N],
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

    /// Copies records with `sequence >= since` into `out`, oldest first, with an
    /// [`AuditEvent::lost`] record in place of every run of sequences that is no longer held
    /// (overwritten, or reserved by [`Self::record_lost`]). `since == 0` reads from 1.
    ///
    /// Returns `(count, next_since)` where `next_since` is one past the last sequence the
    /// returned records cover, or `self.next_sequence()` when `since` is past the end.
    pub fn read_from(&self, since: u64, out: &mut [AuditEvent]) -> (usize, u64) {
        let mut cursor = since.max(1);
        if cursor >= self.next_sequence {
            return (0, self.next_sequence);
        }
        let mut written = 0usize;
        for offset in 0..self.len {
            let event = self.events[(self.start + offset) % N];
            if event.sequence < cursor {
                continue;
            }
            if event.sequence > cursor {
                if written == out.len() {
                    return (written, cursor);
                }
                out[written] = AuditEvent::lost(cursor, event.sequence - cursor);
                written += 1;
                cursor = event.sequence;
            }
            if written == out.len() {
                return (written, cursor);
            }
            out[written] = event;
            written += 1;
            cursor = event.sequence + 1;
        }
        if cursor < self.next_sequence && written < out.len() {
            out[written] = AuditEvent::lost(cursor, self.next_sequence - cursor);
            written += 1;
            cursor = self.next_sequence;
        }
        (written, cursor)
    }

    /// Accounts for `missing` records that could not be written at all: their sequences are
    /// consumed and counted in [`Self::dropped`], so readers see the gap as a lost record.
    pub fn record_lost(&mut self, missing: u64) {
        self.next_sequence += missing;
        self.dropped += missing;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{authorize_audited, format_audit_line, AuditKind, AuditOutcome};
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

    fn use_event(actor: u64) -> AuditEvent {
        crate::audit::event_for(
            0,
            HolderId(actor),
            ResourceRef::object(1),
            Rights::READ,
            CapabilityHandle::INVALID,
            0,
            Ok(()),
        )
    }

    #[test]
    fn overflow_drops_oldest_and_reports_the_loss() {
        let mut log = BoundedAuditLog::<4>::new();
        for _ in 0..6 {
            log.record(use_event(1));
        }
        assert_eq!(log.len(), 4);
        assert_eq!(log.dropped(), 2);
        assert_eq!(log.oldest_sequence(), Some(3));
        assert_eq!(log.newest_sequence(), Some(6));
        let mut buf = [AuditEvent::EMPTY; 8];
        let (count, next) = log.read_from(1, &mut buf);
        assert_eq!(count, 5);
        assert_eq!(next, 7);
        assert_eq!(buf[0].kind, AuditKind::Lost);
        assert_eq!((buf[0].sequence, buf[0].resource_id), (1, 2));
        assert_eq!(buf[1].sequence, 3);
        assert_eq!(buf[4].sequence, 6);
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
    fn a_reader_that_keeps_up_never_sees_a_lost_record() {
        let mut log = BoundedAuditLog::<4>::new();
        let mut buf = [AuditEvent::EMPTY; 4];
        let mut cursor = 1;
        for round in 0..10u64 {
            for _ in 0..3 {
                log.record(use_event(round));
            }
            let (count, next) = log.read_from(cursor, &mut buf);
            assert_eq!(count, 3);
            assert!(buf[..count]
                .iter()
                .all(|event| event.kind != AuditKind::Lost));
            assert_eq!(buf[0].sequence, cursor);
            cursor = next;
        }
        assert_eq!(cursor, 31);
        assert_eq!(log.dropped(), 26);
    }

    #[test]
    fn the_lost_count_is_exact_after_many_overwrites() {
        let mut log = BoundedAuditLog::<64>::new();
        for actor in 0..1000 {
            log.record(use_event(actor));
        }
        assert_eq!(log.dropped(), 936);
        let mut buf = [AuditEvent::EMPTY; 8];
        let (count, next) = log.read_from(0, &mut buf);
        assert_eq!(count, 8);
        assert_eq!(buf[0], AuditEvent::lost(1, 936));
        assert_eq!(buf[1].sequence, 937);
        assert_eq!(buf[1].actor, HolderId(936));
        assert_eq!(next, 944);
        assert_eq!(buf[0].sequence + buf[0].resource_id, buf[1].sequence);
    }

    #[test]
    fn unwritable_records_leave_a_gap_readers_are_told_about() {
        let mut log = BoundedAuditLog::<8>::new();
        log.record(use_event(1));
        log.record_lost(3);
        log.record(use_event(2));
        log.record_lost(2);
        assert_eq!(log.dropped(), 5);
        assert_eq!(log.next_sequence(), 8);
        let mut buf = [AuditEvent::EMPTY; 8];
        let (count, next) = log.read_from(1, &mut buf);
        assert_eq!(count, 4);
        assert_eq!(buf[0].sequence, 1);
        assert_eq!(buf[1], AuditEvent::lost(2, 3));
        assert_eq!(buf[2].sequence, 5);
        assert_eq!(buf[3], AuditEvent::lost(6, 2));
        assert_eq!(next, 8);

        let (count, next) = log.read_from(1, &mut buf[..2]);
        assert_eq!(
            (count, next),
            (2, 5),
            "a full buffer stops after the lost record"
        );
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
            "[AUD ] seq=7 kind=authorize actor=5 class=process-control resource=9 op=observe outcome=allowed depth=0 t=0"
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
            "[AUD ] seq=8 kind=authorize actor=5 class=process-control resource=9 op=terminate outcome=missing-right depth=0 t=0"
        );

        let revoke = AuditEvent::new(
            AuditKind::Revoke,
            HolderId::KERNEL,
            ResourceRef::process(9, 1),
            Rights::empty(),
        )
        .with_subject(HolderId(5))
        .with_count(3);
        line.clear();
        format_audit_line(&revoke, &mut line).unwrap();
        assert_eq!(
            line,
            "[AUD ] seq=0 kind=revoke actor=0 class=process-control resource=9 op=none outcome=allowed depth=0 subject=5 count=3 t=0"
        );

        let refused = AuditEvent::new(
            AuditKind::Authorize,
            HolderId(5),
            ResourceRef::process(9, 1),
            Rights::TERMINATE,
        )
        .refused(crate::audit::PolicyRefusal::SelfTerminate);
        line.clear();
        format_audit_line(&refused, &mut line).unwrap();
        assert!(line.contains(" outcome=self-terminate "), "{line}");

        line.clear();
        format_audit_line(&AuditEvent::lost(4, 60), &mut line).unwrap();
        assert_eq!(line, "[AUD ] seq=4 kind=lost missing=60");
        assert_eq!(AUDIT_EVENT_SIZE_BYTES, 64);
        assert_eq!(core::mem::size_of::<AuditEvent>(), 64);
    }
}
