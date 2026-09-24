//! Acceptance serial markers: strict order plus unordered groups where logs race.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkerStep<'a> {
    /// Next occurrence of `text` at or after the search cursor.
    Ordered(&'a str),
    /// All strings appear at or after the cursor (any order); cursor moves past the last match.
    UnorderedGroup(&'a [&'a str]),
    /// All strings appear somewhere in the full output (any order); cursor is max(cursor, last end).
    UnorderedGroupAnywhere(&'a [&'a str]),
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
            search_start: 0,
        }
    }

    pub fn from_steps(steps: &'a [MarkerStep<'a>]) -> Self {
        Self {
            ordered: None,
            steps: Some(steps),
            next_step: 0,
            search_start: 0,
        }
    }

    #[allow(dead_code)]
    pub fn next_step_index(&self) -> usize {
        self.next_step
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
            None => "complete".to_owned(),
        }
    }

    pub fn consume(&mut self, output: &str) -> bool {
        let total = self.step_count();
        while self.next_step < total {
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
}
