//! #219 stage B: the audit service's drain of the kernel capability audit log.
//!
//! The service reads with `CAP_AUDIT_READ` (12) from the first sequence it has not been handed.
//! The kernel records each read as an allowed use before answering it, so a read always returns
//! at least that record, and the log is caught up once a read returns fewer records than asked
//! for. Gaps come back as `lost` records. The drain also checks that the sequences it is handed
//! are contiguous, so a gap the kernel did not report is a `FAIL` line rather than silence.
//!
//! Lines, each at most one console message, and ending in `~` where one had to be cut:
//! - `[ADT ] lost first=S missing=N` for each lost run;
//! - `[ADT ] #S WHO OUTCOME [KIND] CLASS` for each denied or refused record, where `WHO` is the
//!   actor `A`, `A>H` when it acted on another holder `H`, or `kernel>H`; `KIND` is named only
//!   when it is not an authorization; and the outcome, kind and class are fixed short names
//!   (`noright`, `mismatch`, `deleg`, `process`, ...), so a record fits one message while its
//!   numbers stay within [`RECORD_LINE_MAX_NUMBER`];
//! - `[ADT ] drained through=S records=R lost=L`, which the service prints after its first
//!   drain and after any drain that printed one of the above.

use core::fmt::{self, Write};
use core::mem::offset_of;

use clean_slate_capability::{
    AuditEvent, AuditKind, AuditOutcome, CapabilityError, HolderId, PolicyRefusal, ResourceClass,
    AUDIT_EVENT_SIZE_BYTES,
};

/// The kernel returns at most this many records per read.
pub const AUDIT_READ_BATCH: usize = 8;
/// Reads one drain makes at most; a log still not caught up is finished by the next drain.
pub const AUDIT_DRAIN_MAX_READS: usize = 16;
/// The console refuses longer messages; a longer line is cut to this length, its last byte `~`.
pub const AUDIT_LINE_MAX_BYTES: usize = 64;

pub type AuditReadBuffer = [[u8; AUDIT_EVENT_SIZE_BYTES]; AUDIT_READ_BATCH];

pub trait AuditLogSource {
    /// Reads the records from `since` into `out`. Returns how many, or the kernel's status.
    fn read(&mut self, since: u64, out: &mut AuditReadBuffer) -> Result<usize, u64>;
}

/// The fields of one [`AuditEvent`] the reader uses. Decoded byte by byte, so an enum byte the
/// reader does not know stays a number instead of becoming an invalid value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub actor: u64,
    pub subject: u64,
    pub resource_id: u64,
    pub class: u8,
    pub kind: u8,
    pub outcome: AuditOutcome,
}

impl AuditRecord {
    pub fn decode(bytes: &[u8; AUDIT_EVENT_SIZE_BYTES]) -> Self {
        let word = |offset: usize| {
            let mut le = [0u8; 8];
            le.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(le)
        };
        let outcome = offset_of!(AuditEvent, outcome);
        Self {
            sequence: word(offset_of!(AuditEvent, sequence)),
            actor: word(offset_of!(AuditEvent, actor)),
            subject: word(offset_of!(AuditEvent, subject)),
            resource_id: word(offset_of!(AuditEvent, resource_id)),
            class: bytes[offset_of!(AuditEvent, class)],
            kind: bytes[offset_of!(AuditEvent, kind)],
            outcome: AuditOutcome {
                tag: bytes[outcome + offset_of!(AuditOutcome, tag)],
                error_code: bytes[outcome + offset_of!(AuditOutcome, error_code)],
            },
        }
    }

    fn is_lost(&self) -> bool {
        self.kind == AuditKind::Lost as u8
    }
}

/// What one drain was handed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DrainSummary {
    /// The highest sequence handed over so far, by this drain or an earlier one.
    pub through: u64,
    /// Stored records handed over (lost runs are not records).
    pub records: u64,
    pub denied: u64,
    pub refused: u64,
    /// Sequences the kernel reported lost.
    pub lost: u64,
    /// Sequence jumps the kernel did not report as lost.
    pub unreported_gaps: u64,
}

impl DrainSummary {
    /// Whether the drain printed a line for a record, a lost run or a gap.
    pub fn printed_anything(&self) -> bool {
        self.denied + self.refused + self.lost + self.unreported_gaps > 0
    }
}

pub struct AuditDrain {
    next_since: u64,
}

impl Default for AuditDrain {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditDrain {
    /// Starts at sequence 1, so whatever the log lost before the first read is reported too.
    pub const fn new() -> Self {
        Self { next_since: 1 }
    }

    /// Reads until the log is caught up or [`AUDIT_DRAIN_MAX_READS`] reads have been made,
    /// emitting a line for every denied or refused record, lost run and unreported gap.
    pub fn drain(
        &mut self,
        source: &mut impl AuditLogSource,
        emit: &mut impl FnMut(&str),
    ) -> Result<DrainSummary, u64> {
        let mut summary = DrainSummary::default();
        let mut buffer = [[0u8; AUDIT_EVENT_SIZE_BYTES]; AUDIT_READ_BATCH];
        for _ in 0..AUDIT_DRAIN_MAX_READS {
            let count = source
                .read(self.next_since, &mut buffer)?
                .min(AUDIT_READ_BATCH);
            for raw in &buffer[..count] {
                self.take(AuditRecord::decode(raw), &mut summary, emit);
            }
            if count < AUDIT_READ_BATCH {
                break;
            }
        }
        summary.through = self.next_since - 1;
        Ok(summary)
    }

    fn take(
        &mut self,
        record: AuditRecord,
        summary: &mut DrainSummary,
        emit: &mut impl FnMut(&str),
    ) {
        if record.sequence != self.next_since {
            summary.unreported_gaps += 1;
            emit_line(
                emit,
                format_args!(
                    "[ADT ] FAIL unreported gap expected={} got={}",
                    self.next_since, record.sequence
                ),
            );
        }
        let after = if record.is_lost() {
            summary.lost = summary.lost.saturating_add(record.resource_id);
            emit_line(
                emit,
                format_args!(
                    "[ADT ] lost first={} missing={}",
                    record.sequence, record.resource_id
                ),
            );
            record.sequence.saturating_add(record.resource_id)
        } else {
            summary.records = summary.records.saturating_add(1);
            match record.outcome.tag {
                AuditOutcome::TAG_ALLOWED => {}
                AuditOutcome::TAG_DENIED => {
                    summary.denied += 1;
                    emit_line(emit, format_args!("{}", RecordLine(&record)));
                }
                _ => {
                    summary.refused += 1;
                    emit_line(emit, format_args!("{}", RecordLine(&record)));
                }
            }
            record.sequence.saturating_add(1)
        };
        // Never back: a sequence below the cursor is already reported as a gap.
        self.next_since = self.next_since.max(after);
    }
}

/// The summary line the service prints after a drain. Its records are at most
/// [`AUDIT_READ_BATCH`] × [`AUDIT_DRAIN_MAX_READS`], so the line is cut only once `through` and
/// `lost` together pass 23 digits.
pub fn format_drain_summary(summary: &DrainSummary, emit: &mut impl FnMut(&str)) {
    emit_line(
        emit,
        format_args!(
            "[ADT ] drained through={} records={} lost={}",
            summary.through, summary.records, summary.lost
        ),
    );
}

/// A record line fits one console message while its sequence, actor and subject are each
/// below 10^10, which covers the whole `u32` range.
pub const RECORD_LINE_MAX_NUMBER: u64 = 9_999_999_999;

struct RecordLine<'a>(&'a AuditRecord);

impl fmt::Display for RecordLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let record = self.0;
        write!(f, "[ADT ] #{} ", record.sequence)?;
        let kernel = HolderId::KERNEL.0;
        match (record.actor, record.subject) {
            (actor, subject) if actor == kernel && subject == kernel => f.write_str("kernel")?,
            (actor, subject) if actor == kernel => write!(f, "kernel>{subject}")?,
            (actor, subject) if subject == actor => write!(f, "{actor}")?,
            (actor, subject) => write!(f, "{actor}>{subject}")?,
        }
        write!(f, " {}", Outcome(record.outcome))?;
        if record.kind != AuditKind::Authorize as u8 {
            write!(f, " {}", Kind(record.kind))?;
        }
        write!(f, " {}", Class(record.class))
    }
}

struct Outcome(AuditOutcome);

impl fmt::Display for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.0.error_code;
        match self.0.tag {
            AuditOutcome::TAG_ALLOWED => f.write_str("allowed"),
            AuditOutcome::TAG_DENIED => match CapabilityError::from_u8(code) {
                Some(error) => f.write_str(denial_name(error)),
                None => write!(f, "deny{code}"),
            },
            AuditOutcome::TAG_REFUSED => match PolicyRefusal::from_u8(code) {
                Some(refusal) => f.write_str(refusal_name(refusal)),
                None => write!(f, "rfsd{code}"),
            },
            tag => write!(f, "tag{tag}"),
        }
    }
}

struct Kind(u8);

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match AuditKind::from_u8(self.0) {
            Some(kind) => f.write_str(kind_name(kind)),
            None => write!(f, "k{}", self.0),
        }
    }
}

struct Class(u8);

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match ResourceClass::from_u8(self.0) {
            Some(class) => f.write_str(class_name(class)),
            None => write!(f, "c{}", self.0),
        }
    }
}

const fn denial_name(error: CapabilityError) -> &'static str {
    match error {
        CapabilityError::InvalidHandle => "invalid",
        CapabilityError::StaleHandle => "stale",
        CapabilityError::Revoked => "revoked",
        CapabilityError::UnauthorizedHolder => "foreign",
        CapabilityError::WrongResource => "wrongres",
        CapabilityError::MissingRight => "noright",
        CapabilityError::InvalidRights => "badright",
        CapabilityError::RightsWidening => "widening",
        CapabilityError::DelegationDepthExceeded => "depth",
        CapabilityError::CapacityExhausted => "capacity",
        CapabilityError::GenerationExhausted => "gen-out",
        CapabilityError::NotDelegable => "nodeleg",
        CapabilityError::QuotaExceeded => "quota",
    }
}

const fn refusal_name(refusal: PolicyRefusal) -> &'static str {
    match refusal {
        PolicyRefusal::StaleTarget => "staletgt",
        PolicyRefusal::SelfTerminate => "selfterm",
        PolicyRefusal::TargetNotLive => "notlive",
        PolicyRefusal::InvalidRequest => "badreq",
        PolicyRefusal::AuthorityMismatch => "mismatch",
        PolicyRefusal::Unavailable => "unavail",
        PolicyRefusal::Busy => "busy",
    }
}

const fn kind_name(kind: AuditKind) -> &'static str {
    match kind {
        AuditKind::Authorize => "auth",
        AuditKind::Grant => "grant",
        AuditKind::Delegate => "deleg",
        AuditKind::Revoke => "revoke",
        AuditKind::Drop => "drop",
        AuditKind::Inherit => "fork",
        AuditKind::Lost => "lost",
    }
}

const fn class_name(class: ResourceClass) -> &'static str {
    match class {
        ResourceClass::PersistentObject => "object",
        ResourceClass::ProcessControl => "process",
        ResourceClass::IpcEndpoint => "ipc",
        ResourceClass::BlockDevice => "block",
        ResourceClass::LifecycleControl => "service",
        ResourceClass::Audit => "audit",
        ResourceClass::Network => "net",
        ResourceClass::SharedBuffer => "buffer",
        ResourceClass::Graphics => "gfx",
        ResourceClass::Display => "display",
        ResourceClass::Input => "input",
    }
}

/// Formats into one console message. What does not fit is cut, and the cut is marked by
/// replacing the last byte with `~`, so a cut number is never read as a whole one.
fn emit_line(emit: &mut impl FnMut(&str), args: fmt::Arguments<'_>) {
    let mut line = Line {
        bytes: [0; AUDIT_LINE_MAX_BYTES],
        len: 0,
        cut: false,
    };
    let _ = line.write_fmt(args);
    if line.cut {
        line.bytes[AUDIT_LINE_MAX_BYTES - 1] = b'~';
    }
    // Every field is ASCII, so a cut never splits a character.
    emit(core::str::from_utf8(&line.bytes[..line.len]).unwrap_or("[ADT ] ?"));
}

struct Line {
    bytes: [u8; AUDIT_LINE_MAX_BYTES],
    len: usize,
    cut: bool,
}

impl Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let take = s.len().min(self.bytes.len() - self.len);
        self.bytes[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        self.cut |= take < s.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::{
        CapabilityError, CapabilityHandle, PolicyRefusal, ResourceRef, Rights,
    };
    use std::collections::VecDeque;
    use std::string::{String, ToString};
    use std::vec::Vec;

    const AUDIT: ResourceRef = ResourceRef {
        class: ResourceClass::Audit,
        id: 0,
        instance_generation: 0,
    };

    fn bytes_of(event: &AuditEvent) -> [u8; AUDIT_EVENT_SIZE_BYTES] {
        let mut bytes = [0u8; AUDIT_EVENT_SIZE_BYTES];
        // SAFETY: `AuditEvent` is `repr(C)`, 64 bytes, with its padding spelled out as fields.
        unsafe {
            core::ptr::copy_nonoverlapping(
                (event as *const AuditEvent).cast::<u8>(),
                bytes.as_mut_ptr(),
                AUDIT_EVENT_SIZE_BYTES,
            );
        }
        bytes
    }

    fn use_by(sequence: u64, actor: u64, result: Result<(), CapabilityError>) -> AuditEvent {
        clean_slate_capability::event_for(
            sequence,
            HolderId(actor),
            AUDIT,
            Rights::AUDIT_READ,
            CapabilityHandle::INVALID,
            0,
            result,
        )
    }

    fn denied(sequence: u64, actor: u64) -> AuditEvent {
        use_by(sequence, actor, Err(CapabilityError::MissingRight))
    }

    fn allowed(sequence: u64, actor: u64) -> AuditEvent {
        use_by(sequence, actor, Ok(()))
    }

    /// Hands out scripted reads and records the `since` of each.
    struct Script {
        reads: VecDeque<Vec<AuditEvent>>,
        since: Vec<u64>,
    }

    impl Script {
        fn new(reads: Vec<Vec<AuditEvent>>) -> Self {
            Self {
                reads: reads.into(),
                since: Vec::new(),
            }
        }
    }

    impl AuditLogSource for Script {
        fn read(&mut self, since: u64, out: &mut AuditReadBuffer) -> Result<usize, u64> {
            self.since.push(since);
            let batch = self.reads.pop_front().expect("an unscripted read");
            assert!(batch.len() <= AUDIT_READ_BATCH);
            for (slot, event) in out.iter_mut().zip(&batch) {
                *slot = bytes_of(event);
            }
            Ok(batch.len())
        }
    }

    fn drain(drain: &mut AuditDrain, script: &mut Script) -> (DrainSummary, Vec<String>) {
        let mut lines = Vec::new();
        let summary = drain
            .drain(script, &mut |line: &str| lines.push(String::from(line)))
            .expect("drain");
        (summary, lines)
    }

    #[test]
    fn decoding_reads_every_field_the_kernel_writes() {
        let mut event = AuditEvent::new(AuditKind::Delegate, HolderId(9), AUDIT, Rights::empty())
            .with_subject(HolderId(12))
            .refused(PolicyRefusal::TargetNotLive);
        event.sequence = 0x0102_0304_0506_0708;
        event.resource_id = 77;
        assert_eq!(
            AuditRecord::decode(&bytes_of(&event)),
            AuditRecord {
                sequence: 0x0102_0304_0506_0708,
                actor: 9,
                subject: 12,
                resource_id: 77,
                class: ResourceClass::Audit as u8,
                kind: AuditKind::Delegate as u8,
                outcome: AuditOutcome::refused(PolicyRefusal::TargetNotLive),
            }
        );
    }

    #[test]
    fn a_short_read_ends_the_drain_and_allowed_records_print_nothing() {
        let mut reader = AuditDrain::new();
        let mut script = Script::new(vec![vec![allowed(1, 0), allowed(2, 4), allowed(3, 7)]]);
        let (summary, lines) = drain(&mut reader, &mut script);
        assert_eq!(script.since, [1]);
        assert!(lines.is_empty());
        assert!(!summary.printed_anything());
        assert_eq!(
            summary,
            DrainSummary {
                through: 3,
                records: 3,
                ..DrainSummary::default()
            }
        );
        assert_eq!(reader.next_since, 4);
    }

    #[test]
    fn a_full_read_is_followed_by_another_from_the_next_sequence() {
        let mut reader = AuditDrain::new();
        let first: Vec<_> = (1..=8).map(|seq| allowed(seq, 3)).collect();
        let mut script = Script::new(vec![first, vec![allowed(9, 7)]]);
        let (summary, _) = drain(&mut reader, &mut script);
        assert_eq!(script.since, [1, 9]);
        assert_eq!((summary.through, summary.records), (9, 9));
    }

    #[test]
    fn a_drain_stops_after_its_read_budget() {
        let mut reader = AuditDrain::new();
        let reads: Vec<Vec<_>> = (0..AUDIT_DRAIN_MAX_READS as u64)
            .map(|read| (1..=8).map(|seq| allowed(read * 8 + seq, 3)).collect())
            .collect();
        let mut script = Script::new(reads);
        let (summary, _) = drain(&mut reader, &mut script);
        assert_eq!(script.since.len(), AUDIT_DRAIN_MAX_READS);
        assert_eq!(summary.through, 8 * AUDIT_DRAIN_MAX_READS as u64);
    }

    #[test]
    fn denials_refusals_and_lost_runs_are_printed_exactly() {
        let mut reader = AuditDrain::new();
        let refused = AuditEvent::new(
            AuditKind::Grant,
            HolderId::KERNEL,
            ResourceRef::process(5, 0),
            Rights::empty(),
        )
        .with_subject(HolderId(5))
        .refused(PolicyRefusal::AuthorityMismatch);
        let mut refused = refused;
        refused.sequence = 3;
        let mut script = Script::new(vec![vec![
            AuditEvent::lost(1, 2),
            refused,
            denied(4, 6),
            AuditEvent::lost(5, 84),
            denied(89, 6),
            allowed(90, 8),
        ]]);
        let (summary, lines) = drain(&mut reader, &mut script);
        assert_eq!(
            lines,
            [
                "[ADT ] lost first=1 missing=2",
                "[ADT ] #3 kernel>5 mismatch grant process",
                "[ADT ] #4 6 noright audit",
                "[ADT ] lost first=5 missing=84",
                "[ADT ] #89 6 noright audit",
            ]
        );
        assert_eq!(
            summary,
            DrainSummary {
                through: 90,
                records: 4,
                denied: 2,
                refused: 1,
                lost: 86,
                unreported_gaps: 0,
            }
        );
        let mut summary_lines = Vec::new();
        format_drain_summary(&summary, &mut |line: &str| {
            summary_lines.push(String::from(line))
        });
        assert_eq!(
            summary_lines,
            ["[ADT ] drained through=90 records=4 lost=86"]
        );
    }

    #[test]
    fn a_summary_fits_until_its_figures_pass_23_digits_and_a_cut_one_is_marked() {
        let summary_line = |through: u64, lost: u64| {
            let mut lines = Vec::new();
            let summary = DrainSummary {
                through,
                records: (AUDIT_READ_BATCH * AUDIT_DRAIN_MAX_READS) as u64,
                lost,
                ..DrainSummary::default()
            };
            format_drain_summary(&summary, &mut |line: &str| lines.push(String::from(line)));
            lines.remove(0)
        };
        let fits = summary_line(99_999_999_999, 99_999_999_999);
        assert_eq!(
            fits,
            "[ADT ] drained through=99999999999 records=128 lost=99999999999"
        );
        assert_eq!(summary_line(999_999_999_999, 99_999_999_999).len(), 64);
        let cut = summary_line(9_999_999_999_999, 99_999_999_999);
        assert_eq!(cut.len(), AUDIT_LINE_MAX_BYTES);
        assert!(cut.ends_with(" lost=999999999~"), "{cut}");
    }

    #[test]
    fn a_gap_the_kernel_did_not_report_is_a_failure_line() {
        let mut reader = AuditDrain::new();
        let mut script = Script::new(vec![vec![allowed(1, 2), allowed(5, 2)]]);
        let (summary, lines) = drain(&mut reader, &mut script);
        assert_eq!(lines, ["[ADT ] FAIL unreported gap expected=2 got=5"]);
        assert_eq!(summary.unreported_gaps, 1);
        assert!(summary.printed_anything());
        assert_eq!(reader.next_since, 6);
    }

    #[test]
    fn the_cursor_never_moves_back() {
        let mut reader = AuditDrain::new();
        let mut script = Script::new(vec![vec![allowed(1, 2), allowed(2, 2), allowed(1, 2)]]);
        let (_, lines) = drain(&mut reader, &mut script);
        assert_eq!(lines, ["[ADT ] FAIL unreported gap expected=3 got=1"]);
        assert_eq!(reader.next_since, 3);
    }

    fn record_line(record: &AuditRecord) -> String {
        let mut lines = Vec::new();
        emit_line(
            &mut |line: &str| lines.push(String::from(line)),
            format_args!("{}", RecordLine(record)),
        );
        lines.remove(0)
    }

    /// Longest outcome, kind and class names a record line may print, unknown values included:
    /// with three 10-digit numbers they make a 64-byte line.
    const OUTCOME_MAX_BYTES: usize = 8;
    const KIND_MAX_BYTES: usize = 6;
    const CLASS_MAX_BYTES: usize = 7;

    #[test]
    fn every_short_name_keeps_to_its_width_unknown_values_included() {
        for byte in 0..=u8::MAX {
            assert!(
                Kind(byte).to_string().len() <= KIND_MAX_BYTES,
                "kind {byte}"
            );
            assert!(
                Class(byte).to_string().len() <= CLASS_MAX_BYTES,
                "class {byte}"
            );
            for tag in 0..=u8::MAX {
                let outcome = Outcome(AuditOutcome {
                    tag,
                    error_code: byte,
                });
                assert!(
                    outcome.to_string().len() <= OUTCOME_MAX_BYTES,
                    "{tag}/{byte}"
                );
            }
        }
    }

    /// Every kind, class and outcome byte the kernel can write today plus an unknown one of each,
    /// with every way of naming who acted, at the largest numbers the bound allows.
    #[test]
    fn every_record_fits_one_message_uncut_at_the_largest_numbers() {
        let max = RECORD_LINE_MAX_NUMBER;
        let kernel = HolderId::KERNEL.0;
        let known_and_unknown = |known: fn(u8) -> bool| -> Vec<u8> {
            assert!(!known(u8::MAX));
            (0..=u8::MAX)
                .filter(|&byte| known(byte) || byte == u8::MAX)
                .collect()
        };
        let kinds = known_and_unknown(|byte| AuditKind::from_u8(byte).is_some());
        let classes = known_and_unknown(|byte| ResourceClass::from_u8(byte).is_some());
        let denials = known_and_unknown(|byte| CapabilityError::from_u8(byte).is_some());
        let refusals = known_and_unknown(|byte| PolicyRefusal::from_u8(byte).is_some());
        let mut outcomes = vec![AuditOutcome::allowed()];
        for (tag, codes) in [
            (AuditOutcome::TAG_DENIED, &denials),
            (AuditOutcome::TAG_REFUSED, &refusals),
            (u8::MAX, &vec![u8::MAX]),
        ] {
            outcomes.extend(
                codes
                    .iter()
                    .map(|&error_code| AuditOutcome { tag, error_code }),
            );
        }
        let parties = [(max, max), (max, max - 1), (kernel, max), (kernel, kernel)];
        let mut longest = String::new();
        for &kind in &kinds {
            for &class in &classes {
                for &outcome in &outcomes {
                    for (actor, subject) in parties {
                        let line = record_line(&AuditRecord {
                            sequence: max,
                            actor,
                            subject,
                            resource_id: max,
                            class,
                            kind,
                            outcome,
                        });
                        assert!(!line.ends_with('~'), "{line}");
                        if line.len() > longest.len() {
                            longest = line;
                        }
                    }
                }
            }
        }
        assert_eq!(longest.len(), AUDIT_LINE_MAX_BYTES, "{longest}");
    }

    #[test]
    fn a_record_past_the_bound_is_cut_and_marked() {
        let mut long = AuditEvent::new(
            AuditKind::Delegate,
            HolderId(u64::MAX),
            ResourceRef::object(1),
            Rights::empty(),
        )
        .with_subject(HolderId(u64::MAX - 1))
        .with_result(Err(CapabilityError::GenerationExhausted));
        long.sequence = u64::MAX;
        let line = record_line(&AuditRecord::decode(&bytes_of(&long)));
        assert_eq!(line.len(), AUDIT_LINE_MAX_BYTES);
        assert!(line.starts_with("[ADT ] #18446744073709551615 18446744073709551615>"));
        assert!(line.ends_with('~'));
    }

    #[test]
    fn an_unknown_kind_or_class_byte_is_printed_as_a_number() {
        let mut bytes = bytes_of(&denied(1, 4));
        bytes[offset_of!(AuditEvent, kind)] = 0xee;
        bytes[offset_of!(AuditEvent, class)] = 0xdd;
        let line = std::format!("{}", RecordLine(&AuditRecord::decode(&bytes)));
        assert_eq!(line, "[ADT ] #1 4 noright k238 c221");
    }

    #[test]
    fn a_read_refusal_is_returned() {
        struct Refuses;
        impl AuditLogSource for Refuses {
            fn read(&mut self, _: u64, _: &mut AuditReadBuffer) -> Result<usize, u64> {
                Err(0xdead)
            }
        }
        let mut reader = AuditDrain::new();
        assert_eq!(reader.drain(&mut Refuses, &mut |_: &str| {}), Err(0xdead));
    }
}
