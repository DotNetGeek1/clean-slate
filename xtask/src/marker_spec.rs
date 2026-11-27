//! Acceptance serial markers: strict order plus unordered groups where logs race.
//!
//! A line the kernel tags [`CONSOLE_LINE_TAG`] is a console-service stream's output (#310):
//! text a client process wrote. No marker can be satisfied by text on such a line, so a client
//! cannot print a gate's marker for it. Only a marker that is itself a console line (it starts
//! with the tag) matches there.
//!
//! A line that starts with [`IPC_CONSOLE_LINE_PREFIX`] is a console-sink message, also a
//! client's words: the kernel starts every line of one that way, so a client cannot start a line
//! of its own (#223). Services' own markers (`[INIT]`, `[SUP ]`, `[ADT ]`, ...) arrive only on
//! such lines and still match there, but a milestone verdict marker (one whose tag is
//! `[M<digit>…]`, such as `[M4  ] PASS`) is the kernel's or xtask's and never does.

pub use clean_slate_native_abi::console::CONSOLE_LINE_TAG;
pub use clean_slate_native_abi::console::IPC_CONSOLE_LINE_PREFIX;

/// The first `marker` in `output` at or after `from` that is not inside a client's line it
/// cannot come from (see the module docs), as an offset into `output`.
pub fn find_marker(output: &str, from: usize, marker: &str) -> Option<usize> {
    if marker.starts_with(CONSOLE_LINE_TAG) || marker.starts_with(IPC_CONSOLE_LINE_PREFIX) {
        return output[from..].find(marker).map(|at| from + at);
    }
    let verdict = is_milestone_marker(marker);
    output[from..]
        .match_indices(marker)
        .map(|(at, _)| from + at)
        .find(|&at| {
            let line_start = output[..at].rfind('\n').map_or(0, |newline| newline + 1);
            let line = &output[line_start..];
            !(line.starts_with(CONSOLE_LINE_TAG)
                || verdict && line.starts_with(IPC_CONSOLE_LINE_PREFIX))
        })
}

/// A marker whose tag is a milestone's, `[M` and a digit: `[M4  ] PASS`, `[M4.3] kernel
/// evidence`, `[M10.port] FAIL`.
fn is_milestone_marker(marker: &str) -> bool {
    let bytes = marker.trim_start_matches('\n').as_bytes();
    bytes.len() > 2 && bytes[0] == b'[' && bytes[1] == b'M' && bytes[2].is_ascii_digit()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerStep<'a> {
    /// Next occurrence of `text` at or after the search cursor.
    Ordered(&'a str),
    /// All strings appear at or after the cursor (any order); cursor moves past the last match.
    UnorderedGroup(&'a [&'a str]),
    /// All strings appear somewhere in the full output (any order); cursor is max(cursor, last end).
    UnorderedGroupAnywhere(&'a [&'a str]),
    /// Next complete line at or after the cursor that contains `prefix`. Every `(key, value)`
    /// must appear on that line with `value` as the whole token after `key`. Any other value is
    /// a mismatch that fails the lane, so a marker cannot be satisfied by an arbitrary outcome.
    Line {
        prefix: &'a str,
        fields: &'a [(&'a str, &'a str)],
    },
}

#[derive(Debug, Clone, Copy)]
pub enum MarkerSet<'a> {
    Ordered(&'a [&'a str]),
    Steps(&'a [MarkerStep<'a>]),
}

pub struct MarkerTracker<'a> {
    ordered: Option<&'a [&'a str]>,
    steps: Option<&'a [MarkerStep<'a>]>,
    next_step: usize,
    mismatch: Option<String>,
    /// Byte offset in the serial stream after the last matched marker (for split validation).
    pub search_start: usize,
}

impl<'a> MarkerTracker<'a> {
    pub fn from_set(set: MarkerSet<'a>) -> Self {
        match set {
            MarkerSet::Ordered(markers) => Self::from_ordered(markers),
            MarkerSet::Steps(steps) => Self::from_steps(steps),
        }
    }

    pub fn from_ordered(markers: &'a [&'a str]) -> Self {
        Self {
            ordered: Some(markers),
            steps: None,
            next_step: 0,
            mismatch: None,
            search_start: 0,
        }
    }

    pub fn from_steps(steps: &'a [MarkerStep<'a>]) -> Self {
        Self {
            ordered: None,
            steps: Some(steps),
            next_step: 0,
            mismatch: None,
            search_start: 0,
        }
    }

    #[allow(dead_code)]
    pub fn next_step_index(&self) -> usize {
        self.next_step
    }

    /// Set once a [`MarkerStep::Line`] found its line with a wrong value; the set can then
    /// never complete.
    pub fn mismatch(&self) -> Option<&str> {
        self.mismatch.as_deref()
    }

    pub fn step_count(&self) -> usize {
        if let Some(markers) = self.ordered {
            markers.len()
        } else if let Some(steps) = self.steps {
            steps.len()
        } else {
            0
        }
    }

    pub fn pending_label(&self) -> String {
        if let Some(markers) = self.ordered {
            return markers
                .get(self.next_step)
                .map(|s| (*s).to_owned())
                .unwrap_or_else(|| "complete".to_owned());
        }
        let Some(steps) = self.steps else {
            return "complete".to_owned();
        };
        match steps.get(self.next_step) {
            Some(MarkerStep::Ordered(text)) => (*text).to_owned(),
            Some(MarkerStep::UnorderedGroup(texts) | MarkerStep::UnorderedGroupAnywhere(texts)) => {
                format!("unordered group [{}]", texts.join(", "))
            }
            Some(MarkerStep::Line { prefix, fields }) => line_label(prefix, fields),
            None => "complete".to_owned(),
        }
    }

    pub fn consume(&mut self, output: &str) -> bool {
        let total = self.step_count();
        while self.next_step < total && self.mismatch.is_none() {
            if let Some(markers) = self.ordered {
                let Some(marker) = markers.get(self.next_step) else {
                    break;
                };
                let Some(at) = find_marker(output, self.search_start, marker) else {
                    break;
                };
                self.search_start = at + marker.len();
                self.next_step += 1;
                continue;
            }

            let Some(steps) = self.steps else {
                break;
            };
            match steps[self.next_step] {
                MarkerStep::Ordered(marker) => {
                    let Some(at) = find_marker(output, self.search_start, marker) else {
                        break;
                    };
                    self.search_start = at + marker.len();
                    self.next_step += 1;
                }
                MarkerStep::UnorderedGroup(texts) => {
                    if !Self::consume_group(texts, false, output, &mut self.search_start) {
                        break;
                    }
                    self.next_step += 1;
                }
                MarkerStep::UnorderedGroupAnywhere(texts) => {
                    if !Self::consume_group(texts, true, output, &mut self.search_start) {
                        break;
                    }
                    self.next_step += 1;
                }
                MarkerStep::Line { prefix, fields } => {
                    let Some(line_start) = find_marker(output, self.search_start, prefix) else {
                        break;
                    };
                    let Some(line_len) = output[line_start..].find('\n') else {
                        break;
                    };
                    let line = output[line_start..line_start + line_len].trim_end();
                    if let Err(reason) = check_line_fields(line, fields) {
                        self.mismatch = Some(format!(
                            "{}: {reason} in `{line}`",
                            line_label(prefix, fields)
                        ));
                        break;
                    }
                    self.search_start = line_start + line_len + 1;
                    self.next_step += 1;
                }
            }
        }
        self.next_step == total
    }

    fn consume_group(
        texts: &[&str],
        anywhere: bool,
        output: &str,
        search_start: &mut usize,
    ) -> bool {
        let mut max_end = *search_start;
        for text in texts {
            let from = if anywhere { 0 } else { *search_start };
            let Some(at) = find_marker(output, from, text) else {
                return false;
            };
            max_end = max_end.max(at + text.len());
        }
        *search_start = max_end;
        true
    }
}

impl<'a> MarkerSet<'a> {
    /// Every text the set requires: ordered markers, group members and line prefixes.
    pub fn required_texts(self) -> Vec<&'a str> {
        match self {
            MarkerSet::Ordered(markers) => markers.to_vec(),
            MarkerSet::Steps(steps) => steps
                .iter()
                .flat_map(|step| match step {
                    MarkerStep::Ordered(text) => core::slice::from_ref(text),
                    MarkerStep::UnorderedGroup(texts)
                    | MarkerStep::UnorderedGroupAnywhere(texts) => texts,
                    MarkerStep::Line { prefix, .. } => core::slice::from_ref(prefix),
                })
                .copied()
                .collect(),
        }
    }
}

/// Where the guest failure report on `line` starts, if `line` is one. A failure is either the
/// `[FAIL]` tag anywhere on the line, or a bracketed tag followed by the word `FAIL`
/// (`[DNS ] FAIL reason=…`, `[M10.port] FAIL …`, `[M9.J] FAIL brk`). `FAIL` must end at
/// whitespace or at the end of the line, so `[M7.6] FAIL-CLOSED OK` is not a failure. This is
/// the one rule every lane uses to recognise a guest failure.
pub fn guest_failure_start(line: &str) -> Option<usize> {
    const FAIL_TAG: &str = "[FAIL]";
    const FAIL_WORD: &str = "] FAIL";
    let tagged = line.find(FAIL_TAG);
    let worded = line.match_indices(FAIL_WORD).find_map(|(close, _)| {
        let after = &line[close + FAIL_WORD.len()..];
        if !after.chars().next().is_none_or(char::is_whitespace) {
            return None;
        }
        let open = line[..close].rfind('[')?;
        (!line[open + 1..close].contains(']')).then_some(open)
    });
    match (tagged, worded) {
        (Some(tagged), Some(worded)) => Some(tagged.min(worded)),
        (tagged, worded) => tagged.or(worded),
    }
}

/// The failure report on `line`, from its tag to the end of the line.
pub fn guest_failure(line: &str) -> Option<&str> {
    guest_failure_start(line).map(|start| line[start..].trim_end())
}

/// First guest failure line in `output`. An unterminated last line is checked only with
/// `include_tail`: a partial `[TAG] FAIL` could still turn out to be `[TAG] FAIL-CLOSED`.
pub fn first_guest_failure(output: &str, include_tail: bool) -> Option<&str> {
    complete_lines(output, include_tail)
        .lines()
        .find_map(guest_failure)
}

/// [`first_guest_failure`] over a raw serial transcript.
pub fn first_guest_failure_in_bytes(transcript: &[u8], include_tail: bool) -> Option<String> {
    let text = String::from_utf8_lossy(transcript);
    first_guest_failure(&text, include_tail).map(str::to_owned)
}

/// [`first_guest_failure_in_bytes`] over a transcript that only grows, rescanning only what
/// arrived since the last call (from the start of the line that was still incomplete then).
///
/// The serial reader hands over whatever one socket read returned, often a byte or two, so a
/// lane that rescanned the whole transcript per read did quadratic work: by the later steps of
/// `test-m10-desktop` under host load it spent most of its time rescanning and read the guest's
/// lines seconds after they were printed (#349).
#[derive(Debug, Default)]
pub struct GuestFailureScan {
    /// Where the first line not yet known to be complete starts.
    line_start: usize,
}

impl GuestFailureScan {
    /// The first complete failure line in `transcript[..]` not reported before. `transcript`
    /// must be the same buffer, only grown, on every call.
    pub fn next_in(&mut self, transcript: &[u8]) -> Option<String> {
        let from = self.line_start.min(transcript.len());
        let fresh = &transcript[from..];
        if let Some(end) = fresh.iter().rposition(|&byte| byte == b'\n') {
            self.line_start = from + end + 1;
        }
        first_guest_failure_in_bytes(fresh, false)
    }
}

fn complete_lines(output: &str, include_tail: bool) -> &str {
    match output.rfind('\n') {
        _ if include_tail => output,
        Some(end) => &output[..=end],
        None => "",
    }
}

/// First guest failure line in `output` that the lane did not ask for (see
/// [`guest_failure_start`]). A failure line is expected only when it contains one of the set's
/// own required texts that is itself a failure line, so each lane's allow-list is exactly the
/// failure markers it requires. An unterminated last line is checked only with `include_tail`,
/// so a required failure marker is not judged before it has fully arrived.
pub fn unexpected_guest_failure(
    output: &str,
    set: MarkerSet<'_>,
    include_tail: bool,
) -> Option<String> {
    let expected: Vec<&str> = set
        .required_texts()
        .into_iter()
        .filter(|text| guest_failure_start(text).is_some())
        .collect();
    complete_lines(output, include_tail)
        .lines()
        .find_map(|line| {
            let failure = guest_failure(line)?;
            if expected.iter().any(|text| line.contains(text)) {
                return None;
            }
            Some(failure.to_owned())
        })
}

fn line_label(prefix: &str, fields: &[(&str, &str)]) -> String {
    let expected: Vec<String> = fields
        .iter()
        .map(|(key, value)| format!("{key}{value}"))
        .collect();
    format!("{prefix} with [{}]", expected.join(" "))
}

/// Token after the first `key` on `line`, ending at whitespace or end of line.
fn field_token<'l>(line: &'l str, key: &str) -> Option<&'l str> {
    let start = line.find(key)? + key.len();
    let rest = &line[start..];
    let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn check_line_fields(line: &str, fields: &[(&str, &str)]) -> Result<(), String> {
    for (key, expected) in fields {
        match field_token(line, key) {
            Some(actual) if actual == *expected => {}
            Some(actual) => return Err(format!("expected {key}{expected}, found {key}{actual}")),
            None => return Err(format!("expected {key}{expected}, found no {key}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_failure_scan_finds_a_line_split_across_reads_once_it_is_complete() {
        let mut scan = GuestFailureScan::default();
        let mut transcript = b"[BOOT] ok\n[STOR".to_vec();
        assert_eq!(scan.next_in(&transcript), None);
        transcript.extend_from_slice(b"] FAI");
        assert_eq!(scan.next_in(&transcript), None);
        transcript.extend_from_slice(b"L disk\n[IDLE ] quiet\n");
        assert_eq!(
            scan.next_in(&transcript).as_deref(),
            Some("[STOR] FAIL disk")
        );
        // Lines already scanned are not reported again.
        transcript.extend_from_slice(b"[IDLE ] quiet\n");
        assert_eq!(scan.next_in(&transcript), None);
    }

    #[test]
    fn the_failure_scan_matches_a_whole_transcript_scan() {
        let transcript = b"[A] ok\n[B] FAIL-CLOSED x\n[C] ok\n[D] FAIL now\n[E] FAIL tail";
        let mut scan = GuestFailureScan::default();
        let mut found = None;
        for end in 0..=transcript.len() {
            if let Some(failure) = scan.next_in(&transcript[..end]) {
                found.get_or_insert(failure);
            }
        }
        assert_eq!(found, first_guest_failure_in_bytes(transcript, false));
        assert_eq!(found.as_deref(), Some("[D] FAIL now"));
    }

    #[test]
    fn unexpected_guest_failure_reports_any_fail_line_the_lane_did_not_require() {
        let set = MarkerSet::Ordered(&["[BOOT] ok", "[M1  ] PASS"]);
        assert_eq!(
            unexpected_guest_failure("[BOOT] ok\n[M1  ] PASS\n", set, true),
            None
        );
        assert_eq!(
            unexpected_guest_failure("[BOOT] ok\nx[FAIL] injected\r\n[M1  ] PASS\n", set, false),
            Some("[FAIL] injected".to_owned())
        );
    }

    #[test]
    fn every_guest_failure_tag_is_a_failure() {
        for (line, failure) in [
            ("[FAIL] boom", "[FAIL] boom"),
            ("[IPC ] console pid=3: [FAIL] boom\r", "[FAIL] boom"),
            ("[DNS ] FAIL reason=timeout", "[DNS ] FAIL reason=timeout"),
            (
                "[TLS ] FAIL entropy: no RDSEED or RDRAND",
                "[TLS ] FAIL entropy: no RDSEED or RDRAND",
            ),
            ("[VMOD] FAIL Timeout", "[VMOD] FAIL Timeout"),
            (
                "[M10.port] FAIL fixture pid=4 failed_step=9",
                "[M10.port] FAIL fixture pid=4 failed_step=9",
            ),
            ("[M9.J] FAIL brk", "[M9.J] FAIL brk"),
            (
                "[SCHED] FAIL pending wake dropped key=0x5400000000000012: table full\r",
                "[SCHED] FAIL pending wake dropped key=0x5400000000000012: table full",
            ),
            ("x[DNS ] FAIL", "[DNS ] FAIL"),
        ] {
            assert_eq!(guest_failure(line), Some(failure), "{line:?}");
        }
        for line in [
            "[M7.6] FAIL-CLOSED OK",
            "[DNS ] FAILED",
            "[M1  ] PASS",
            "[SVC ] launch service=2 note=FAIL",
            "] FAIL without an opening tag",
        ] {
            assert_eq!(guest_failure(line), None, "{line:?}");
        }
    }

    #[test]
    fn a_partial_worded_failure_waits_for_its_line_to_end() {
        assert_eq!(first_guest_failure("[M7.6] FAIL", false), None);
        assert_eq!(first_guest_failure("[M7.6] FAIL-CLOSED OK\n", false), None);
        assert_eq!(
            first_guest_failure("[DNS ] FAIL", true),
            Some("[DNS ] FAIL")
        );
        assert_eq!(
            first_guest_failure_in_bytes(b"[BOOT] ok\n[VMOD] FAIL Timeout\r\n", false).as_deref(),
            Some("[VMOD] FAIL Timeout")
        );
    }

    #[test]
    fn unexpected_guest_failure_reports_tagged_failures_the_lane_did_not_require() {
        let set = MarkerSet::Ordered(&["[DNS ] virtio ready mac=", "[M7.5] PASS"]);
        assert_eq!(
            unexpected_guest_failure(
                "[DNS ] virtio ready mac=x\n[DNS ] FAIL reason=timeout\n",
                set,
                false
            ),
            Some("[DNS ] FAIL reason=timeout".to_owned())
        );
        let tls = MarkerSet::Ordered(&["[TLS ] peer identity rejected", "[M7.6] FAIL-CLOSED OK"]);
        assert_eq!(
            unexpected_guest_failure(
                "[TLS ] peer identity rejected\n[M7.6] FAIL-CLOSED OK\n",
                tls,
                true
            ),
            None
        );
    }

    #[test]
    fn unexpected_guest_failure_allows_only_required_failure_markers() {
        const STEPS: &[MarkerStep<'static>] = &[
            MarkerStep::Ordered("[M9.G] probe"),
            MarkerStep::UnorderedGroup(&["[FAIL] kernel stack overflow slot=1 ", "[M9.G] PASS"]),
        ];
        let set = MarkerSet::Steps(STEPS);
        assert_eq!(set.required_texts().len(), 3);
        let expected = "[M9.G] probe\n[FAIL] kernel stack overflow slot=1 kind=task\n[M9.G] PASS\n";
        assert_eq!(unexpected_guest_failure(expected, set, true), None);
        assert_eq!(
            unexpected_guest_failure(
                &format!("{expected}[FAIL] kernel stack overflow slot=2\n"),
                set,
                true
            ),
            Some("[FAIL] kernel stack overflow slot=2".to_owned())
        );
    }

    #[test]
    fn unexpected_guest_failure_waits_for_the_line_unless_told_to_include_the_tail() {
        let set = MarkerSet::Ordered(&["[FAIL] kernel stack overflow slot=1 "]);
        assert_eq!(
            unexpected_guest_failure("[FAIL] kernel stack ov", set, false),
            None
        );
        assert_eq!(
            unexpected_guest_failure("[FAIL] kernel stack ov", set, true),
            Some("[FAIL] kernel stack ov".to_owned())
        );
        let line_set = MarkerSet::Steps(&[MarkerStep::Line {
            prefix: "[CRSH] inject",
            fields: &[],
        }]);
        assert_eq!(
            unexpected_guest_failure("[FAIL] boom", line_set, false),
            None
        );
        assert_eq!(
            unexpected_guest_failure("[FAIL] boom", line_set, true),
            Some("[FAIL] boom".to_owned())
        );
    }

    #[test]
    fn a_console_stream_line_cannot_satisfy_a_marker() {
        let forged = "[CON ] pid=7: [M4  ] PASS\n[CON ] pid=7: x [INIT] boot settled running=5\n";
        let markers = ["[M4  ] PASS"];
        assert!(!MarkerTracker::from_ordered(&markers).consume(forged));
        let steps = [MarkerStep::UnorderedGroupAnywhere(&["[INIT] boot settled"])];
        assert!(!MarkerTracker::from_steps(&steps).consume(forged));
        let steps = [MarkerStep::Line {
            prefix: "[INIT] boot settled",
            fields: &[("running=", "5")],
        }];
        assert!(!MarkerTracker::from_steps(&steps).consume(forged));
        // The real line after a forged one still counts, as does a line wrapped by the kernel.
        let real = format!("{forged}[M4  ] PASS\n");
        assert!(MarkerTracker::from_ordered(&markers).consume(&real));
        let wrapped = "[IPC ] console pid=1: [INIT] boot settled running=5\n";
        assert!(MarkerTracker::from_steps(&steps).consume(wrapped));
        // A marker that is itself a console line matches one.
        let greeting = ["[CON ] pid=7: playground: console stream open"];
        assert!(MarkerTracker::from_ordered(&greeting).consume(
            forged
                .replace("[M4  ] PASS", "playground: console stream open")
                .as_str()
        ));
    }

    #[test]
    fn a_console_sink_line_cannot_satisfy_a_milestone_verdict() {
        // A client wrote `"\n[M4  ] PASS"`; the kernel starts both lines with its prefix.
        let forged = "[IPC ] console pid=5: \n[IPC ] console pid=5: [M4  ] PASS\n";
        let markers = ["[M4  ] PASS"];
        assert!(!MarkerTracker::from_ordered(&markers).consume(forged));
        let steps = [MarkerStep::Line {
            prefix: "[M4.3] kernel evidence supervisor",
            fields: &[("console-messages=", "6")],
        }];
        assert!(!MarkerTracker::from_steps(&steps).consume(
            "[IPC ] console pid=1: [M4.3] kernel evidence supervisor pid=1 console-messages=6\n"
        ));
        // The kernel's own line, after the forged one, still counts.
        assert!(MarkerTracker::from_ordered(&markers).consume(&format!("{forged}[M4  ] PASS\n")));
        // A service's own marker still matches on its attributed line, and a marker that
        // spells out the attribution matches the line it names.
        let wrapped = "[IPC ] console pid=1: [SUP ] started pid=1\n";
        assert!(MarkerTracker::from_ordered(&["[SUP ] started pid=1"]).consume(wrapped));
        assert!(
            MarkerTracker::from_ordered(&["[IPC ] console pid=1: [SUP ] started pid=1"])
                .consume(wrapped)
        );
        assert!(is_milestone_marker("[M10.port] PASS"));
        assert!(is_milestone_marker("\n[M4  ] PASS"));
        assert!(!is_milestone_marker(
            "[MEM ] physical allocator initialized"
        ));
        assert!(!is_milestone_marker("[MM  ] scratch page map/unmap OK"));
    }

    #[test]
    fn ordered_markers_must_follow_sequence() {
        let mut tracker = MarkerTracker::from_ordered(&["alpha", "beta", "gamma"]);
        assert!(!tracker.consume("alpha\n"));
        assert!(tracker.consume("alpha\nbeta\ngamma\n"));
    }

    #[test]
    fn unordered_group_accepts_either_order_after_cursor() {
        let steps = [
            MarkerStep::Ordered("start"),
            MarkerStep::UnorderedGroup(&["[TASK] task 1 progress=", "[TASK] task 2 progress="]),
            MarkerStep::Ordered("[M2  ] PASS"),
        ];
        let mut tracker = MarkerTracker::from_steps(&steps);
        let a = "start\n[TASK] task 2 progress=1\n[TASK] task 1 progress=1\n[M2  ] PASS\n";
        let b = "start\n[TASK] task 1 progress=1\n[TASK] task 2 progress=1\n[M2  ] PASS\n";
        assert!(tracker.consume(a));
        tracker = MarkerTracker::from_steps(&steps);
        assert!(tracker.consume(b));
    }

    #[test]
    fn unordered_group_fails_when_member_missing() {
        let steps = [
            MarkerStep::Ordered("start"),
            MarkerStep::UnorderedGroup(&["one", "two"]),
            MarkerStep::Ordered("end"),
        ];
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(!tracker.consume("start\none\nend\n"));
        assert_eq!(tracker.next_step_index(), 1);
    }

    #[test]
    fn unordered_group_anywhere_finds_early_lines_before_later_ordered_prefix() {
        let steps = [
            MarkerStep::Ordered("[LNX ] exit pid="),
            MarkerStep::UnorderedGroupAnywhere(&[
                "[TASK] task 1 progress=",
                "[TASK] task 2 progress=",
            ]),
            MarkerStep::Ordered("[M2  ] PASS"),
        ];
        let output = "[TASK] task 1 progress=1\n[TASK] task 2 progress=1\n[LNX ] exit pid=1 status=0\n[M2  ] PASS\n";
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(tracker.consume(output));
    }

    const OUTCOME_STEPS: [MarkerStep<'static>; 2] = [
        MarkerStep::Line {
            prefix: "[CRSH] recovery outcome=",
            fields: &[("outcome=", "previous-commit")],
        },
        MarkerStep::Ordered("[TEST] crash recovery PASS"),
    ];

    #[test]
    fn line_step_accepts_the_required_value() {
        let mut tracker = MarkerTracker::from_steps(&OUTCOME_STEPS);
        assert!(tracker
            .consume("[CRSH] recovery outcome=previous-commit\r\n[TEST] crash recovery PASS\n"));
        assert_eq!(tracker.mismatch(), None);
    }

    #[test]
    fn line_step_rejects_any_other_value_as_a_mismatch() {
        let mut tracker = MarkerTracker::from_steps(&OUTCOME_STEPS);
        assert!(
            !tracker.consume("[CRSH] recovery outcome=new-commit\n[TEST] crash recovery PASS\n")
        );
        let mismatch = tracker.mismatch().expect("wrong outcome is a mismatch");
        assert!(mismatch.contains("expected outcome=previous-commit, found outcome=new-commit"));
        assert!(!tracker.consume(
            "[CRSH] recovery outcome=new-commit\n[CRSH] recovery outcome=previous-commit\n[TEST] crash recovery PASS\n"
        ));
    }

    #[test]
    fn line_step_value_is_the_whole_token_not_a_prefix() {
        let steps = [MarkerStep::Line {
            prefix: "[STOR] recovered generation=",
            fields: &[("generation=", "2")],
        }];
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(!tracker.consume("[STOR] recovered generation=23\n"));
        assert!(tracker.mismatch().is_some());
    }

    #[test]
    fn line_step_waits_for_the_end_of_the_line() {
        let steps = [MarkerStep::Line {
            prefix: "[PROC] teardown pid=",
            fields: &[("resources=", "0")],
        }];
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(!tracker.consume("[PROC] teardown pid=3 resour"));
        assert_eq!(tracker.mismatch(), None);
        assert!(tracker.consume("[PROC] teardown pid=3 resources=0\n"));
    }

    #[test]
    fn line_step_checks_every_field_and_reports_a_missing_key() {
        let steps = [MarkerStep::Line {
            prefix: "[STOR] read object=alpha id=1 ",
            fields: &[("bytes=", "900"), ("match=", "yes")],
        }];
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(tracker.consume("[STOR] read object=alpha id=1 bytes=900 checksum=1 match=yes\n"));
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(!tracker.consume("[STOR] read object=alpha id=1 bytes=900 match=no\n"));
        assert!(tracker.mismatch().unwrap().contains("found match=no"));
        let mut tracker = MarkerTracker::from_steps(&steps);
        assert!(!tracker.consume("[STOR] read object=alpha id=1 bytes=900\n"));
        assert!(tracker.mismatch().unwrap().contains("found no match="));
    }
}
