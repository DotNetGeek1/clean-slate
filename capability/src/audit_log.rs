//! M6.7 bounded audit-event ring (`AuditSink` implementation, host-testable).

use crate::audit::{AuditEvent, AuditKind, AuditSink};
use crate::HolderId;

/// Most records one holder ([`AuditEvent::charged_holder`]) may have in the ring at once
/// (#219). The kernel's own records, granted to or revoking the kernel, share one budget.
pub const AUDIT_HOLDER_BUDGET: usize = 16;

/// Where [`BoundedAuditLog::record_event`] put an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recorded {
    /// Stored as a new record with this sequence.
    Stored(u64),
    /// A repeat, merged into the earlier record with this sequence (its `count` went up).
    Merged(u64),
}

/// Fixed-capacity log of [`AuditEvent`] records with contiguous kernel-assigned sequences,
/// held in sequence order.
///
/// A new record always goes in. To make room, a holder that already has
/// [`AUDIT_HOLDER_BUDGET`] records loses its own oldest; otherwise, when the log is full,
/// the oldest record overall goes. So a holder flooding the log only ever displaces its
/// own records once it is at its budget, and cannot push out another holder's.
///
/// An allowed use identical to the same holder's newest record, which no reader has been
/// handed yet ([`Self::mark_read`]), is merged into it: the record's `count` becomes the
/// number of uses it stands for (2, 3, ...; saturating, after which a new record starts).
/// Merging consumes no sequence and no space.
///
/// Nothing is lost silently: every stored record consumes a sequence; [`Self::dropped`]
/// counts the ones no longer held; and [`Self::read_from`] returns an [`AuditKind::Lost`]
/// record for every gap a reader's cursor runs into, wherever it is.
pub struct BoundedAuditLog<const N: usize> {
    events: [AuditEvent; N],
    len: usize,
    next_sequence: u64,
    dropped: u64,
    holder_budget: usize,
    /// Highest sequence handed to a reader; records at or below it are never merged into.
    read_through: u64,
}

impl<const N: usize> BoundedAuditLog<N> {
    pub const fn new() -> Self {
        Self::with_holder_budget(AUDIT_HOLDER_BUDGET)
    }

    pub const fn with_holder_budget(holder_budget: usize) -> Self {
        Self {
            events: [AuditEvent::EMPTY; N],
            len: 0,
            next_sequence: 1,
            dropped: 0,
            holder_budget,
            read_through: 0,
        }
    }

    pub const fn holder_budget(&self) -> usize {
        self.holder_budget
    }

    /// Records in the log charged to `holder`.
    pub fn held_by(&self, holder: HolderId) -> usize {
        self.held()
            .iter()
            .filter(|event| event.charged_holder() == holder)
            .count()
    }

    /// Records sequences up to `sequence` as handed to a reader.
    pub fn mark_read(&mut self, sequence: u64) {
        self.read_through = self.read_through.max(sequence);
    }

    /// Highest sequence handed to a reader; 0 before the first read.
    pub fn read_through(&self) -> u64 {
        self.read_through
    }

    /// Adds `event` (its sequence is assigned here) and says where it went.
    pub fn record_event(&mut self, mut event: AuditEvent) -> Recorded {
        let holder = event.charged_holder();
        let newest_of_holder = self
            .held()
            .iter()
            .rposition(|held| held.charged_holder() == holder);
        if let Some(index) = newest_of_holder {
            if self.is_repeat(&self.events[index], &event) {
                let merged = &mut self.events[index];
                merged.count = merged.count.max(1) + 1;
                return Recorded::Merged(merged.sequence);
            }
        }
        event.sequence = self.next_sequence;
        self.next_sequence += 1;
        if self.held_by(holder) >= self.holder_budget {
            let oldest_of_holder = self
                .held()
                .iter()
                .position(|held| held.charged_holder() == holder)
                .expect("a holder at its budget has a record");
            self.evict(oldest_of_holder);
        } else if self.len == N {
            self.evict(0);
        }
        self.events[self.len] = event;
        self.len += 1;
        Recorded::Stored(event.sequence)
    }

    /// `event` is an allowed use identical to `earlier` (but for sequence, time and count),
    /// `earlier` has not been read, and its count has room.
    fn is_repeat(&self, earlier: &AuditEvent, event: &AuditEvent) -> bool {
        let comparable = |e: &AuditEvent| AuditEvent {
            sequence: 0,
            timestamp_ns: 0,
            count: 0,
            ..*e
        };
        event.kind == AuditKind::Authorize
            && event.is_allowed()
            && earlier.sequence > self.read_through
            && earlier.count < u32::MAX
            && comparable(earlier) == comparable(event)
    }

    fn evict(&mut self, index: usize) {
        self.events.copy_within(index + 1..self.len, index);
        self.len -= 1;
        self.dropped += 1;
    }

    fn held(&self) -> &[AuditEvent] {
        &self.events[..self.len]
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
        self.held().first().map(|event| event.sequence)
    }

    pub fn newest_sequence(&self) -> Option<u64> {
        self.held().last().map(|event| event.sequence)
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
        for &event in self.held() {
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
        self.held()
            .iter()
            .find(|event| event.sequence == sequence)
            .copied()
    }
}

impl<const N: usize> AuditSink for BoundedAuditLog<N> {
    fn record(&mut self, event: AuditEvent) {
        self.record_event(event);
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
        for (slot, seq) in [99u64, 1, 42].into_iter().enumerate() {
            let event = crate::audit::event_for(
                seq,
                HolderId(1),
                ResourceRef::object(1),
                Rights::READ,
                CapabilityHandle::new(slot as u16, 1),
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

    /// A denied use: never merged, so every one takes a sequence.
    fn use_event(actor: u64) -> AuditEvent {
        crate::audit::event_for(
            0,
            HolderId(actor),
            ResourceRef::object(1),
            Rights::READ,
            CapabilityHandle::INVALID,
            0,
            Err(CapabilityError::InvalidHandle),
        )
    }

    fn allowed_use(actor: u64, slot: u16) -> AuditEvent {
        crate::audit::event_for(
            0,
            HolderId(actor),
            ResourceRef::object(1),
            Rights::READ,
            CapabilityHandle::new(slot, 1),
            0,
            Ok(()),
        )
    }

    fn sequences<const N: usize>(log: &BoundedAuditLog<N>) -> alloc::vec::Vec<u64> {
        let mut buf = [AuditEvent::EMPTY; 16];
        let (count, _) = log.read_from(1, &mut buf);
        buf[..count]
            .iter()
            .map(|event| match event.kind {
                AuditKind::Lost => u64::MAX - event.resource_id,
                _ => event.sequence,
            })
            .collect()
    }

    #[test]
    fn a_holder_at_its_budget_displaces_only_its_own_records() {
        let mut log = BoundedAuditLog::<8>::with_holder_budget(3);
        log.record(use_event(1));
        for _ in 0..10 {
            log.record(use_event(2));
        }
        assert_eq!(log.held_by(HolderId(1)), 1);
        assert_eq!(log.held_by(HolderId(2)), 3);
        assert_eq!(log.dropped(), 7);
        assert_eq!(log.next_sequence(), 12);
        // Holder 1's record survives; holder 2's first seven are a lost run behind it.
        assert_eq!(sequences(&log), [1, u64::MAX - 7, 9, 10, 11]);
    }

    #[test]
    fn a_full_log_below_the_budget_ages_out_the_oldest_record() {
        let mut log = BoundedAuditLog::<4>::with_holder_budget(3);
        for actor in 1..=6 {
            log.record(use_event(actor));
        }
        assert_eq!(log.dropped(), 2);
        assert_eq!(sequences(&log), [u64::MAX - 2, 3, 4, 5, 6]);
    }

    #[test]
    fn the_kernel_acting_on_a_holder_is_charged_to_that_holder() {
        let grant = AuditEvent::new(
            AuditKind::Grant,
            HolderId::KERNEL,
            ResourceRef::object(1),
            Rights::READ,
        )
        .with_subject(HolderId(5));
        assert_eq!(grant.charged_holder(), HolderId(5));
        assert_eq!(use_event(7).charged_holder(), HolderId(7));
        let kernel_only = AuditEvent::new(
            AuditKind::Revoke,
            HolderId::KERNEL,
            ResourceRef::object(1),
            Rights::empty(),
        );
        assert_eq!(kernel_only.charged_holder(), HolderId::KERNEL);
    }

    #[test]
    fn repeated_allowed_uses_merge_into_one_record() {
        let mut log = BoundedAuditLog::<8>::new();
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Stored(1));
        assert_eq!(log.get(1).unwrap().count, 0, "a single use has count 0");
        for _ in 0..4 {
            assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Merged(1));
        }
        // Another holder in between does not end the run.
        assert_eq!(log.record_event(allowed_use(2, 0)), Recorded::Stored(2));
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Merged(1));
        assert_eq!(log.get(1).unwrap().count, 6);
        assert_eq!(log.next_sequence(), 3);
        assert_eq!(log.dropped(), 0);
    }

    #[test]
    fn a_denial_or_a_different_use_ends_the_run() {
        let mut log = BoundedAuditLog::<8>::new();
        log.record(allowed_use(1, 0));
        log.record(allowed_use(1, 0));
        assert_eq!(log.record_event(use_event(1)), Recorded::Stored(2));
        assert_eq!(
            log.record_event(use_event(1)),
            Recorded::Stored(3),
            "denials never merge"
        );
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Stored(4));
        assert_eq!(
            log.record_event(allowed_use(1, 1)),
            Recorded::Stored(5),
            "other handle"
        );
        assert_eq!(log.get(1).unwrap().count, 2);
        assert_eq!(log.get(4).unwrap().count, 0);
    }

    #[test]
    fn a_record_handed_to_a_reader_is_not_merged_into() {
        let mut log = BoundedAuditLog::<8>::new();
        log.record(allowed_use(1, 0));
        log.record(allowed_use(1, 0));
        log.mark_read(1);
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Stored(2));
        assert_eq!(
            log.get(1).unwrap().count,
            2,
            "what the reader saw stays as it was"
        );
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Merged(2));
    }

    #[test]
    fn read_through_only_moves_forward() {
        let mut log = BoundedAuditLog::<8>::new();
        assert_eq!(log.read_through(), 0);
        log.mark_read(5);
        log.mark_read(3);
        assert_eq!(log.read_through(), 5);
    }

    #[test]
    fn a_saturated_count_starts_a_new_record() {
        let mut log = BoundedAuditLog::<8>::new();
        let nearly_full = allowed_use(1, 0).with_count(u32::MAX as usize - 1);
        assert_eq!(log.record_event(nearly_full), Recorded::Stored(1));
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Merged(1));
        assert_eq!(log.get(1).unwrap().count, u32::MAX);
        assert_eq!(log.record_event(allowed_use(1, 0)), Recorded::Stored(2));
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
