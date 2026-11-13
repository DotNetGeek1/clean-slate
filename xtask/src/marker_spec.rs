//! Acceptance serial markers: strict order plus unordered groups where logs race.

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
                let Some(offset) = output[self.search_start..].find(marker) else {
                    break;
                };
                self.search_start += offset + marker.len();
                self.next_step += 1;
                continue;
            }

            let Some(steps) = self.steps else {
                break;
            };
            match steps[self.next_step] {
                MarkerStep::Ordered(marker) => {
                    let Some(offset) = output[self.search_start..].find(marker) else {
                        break;
                    };
                    self.search_start += offset + marker.len();
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
                    let Some(offset) = output[self.search_start..].find(prefix) else {
                        break;
                    };
                    let line_start = self.search_start + offset;
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
            let haystack = if anywhere {
                output
            } else {
                &output[*search_start..]
            };
            let Some(offset) = haystack.find(text) else {
                return false;
            };
            let end = if anywhere {
                offset + text.len()
            } else {
                *search_start + offset + text.len()
            };
            max_end = max_end.max(end);
        }
        *search_start = max_end;
        true
    }
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
