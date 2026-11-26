//! Key repeat (#309): one held key repeats after a delay, at a rate.
//!
//! Pure and clock-free: the compositor passes the time in. Only the most recently pressed key
//! that repeats ([`keymap::repeats`]) is armed. Its release, a reset or a focus change
//! disarms it; pressing a modifier does not, so holding `a` and then Shift continues as `A`.
//!
//! A late wake never bursts: [`KeyRepeater::due`] yields at most one repeat per call and skips
//! the ticks it missed.

use clean_slate_graphics::input::{KeyState, KeyUsage};
use clean_slate_graphics::keymap;

/// Repeat timing. `interval_ns == 0` turns repeat off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RepeatConfig {
    /// From the press to the first repeat.
    pub delay_ns: u64,
    /// Between repeats.
    pub interval_ns: u64,
}

impl RepeatConfig {
    /// 500 ms delay, 30 repeats a second.
    pub const DEFAULT: Self = Self {
        delay_ns: 500_000_000,
        interval_ns: 33_333_333,
    };
    pub const OFF: Self = Self {
        delay_ns: 0,
        interval_ns: 0,
    };

    pub const fn enabled(&self) -> bool {
        self.interval_ns != 0
    }
}

impl Default for RepeatConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Armed {
    usage: KeyUsage,
    next_ns: u64,
}

/// The repeat timer for seat 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KeyRepeater {
    armed: Option<Armed>,
}

impl KeyRepeater {
    pub const fn new() -> Self {
        Self { armed: None }
    }

    /// Folds one key transition at `now_ns`. `may_repeat` is false when the focused client
    /// did not ask for text input, so nothing is armed for it.
    pub fn key(
        &mut self,
        usage: KeyUsage,
        state: KeyState,
        now_ns: u64,
        may_repeat: bool,
        config: RepeatConfig,
    ) {
        match state {
            // A duplicate press of the armed key keeps its timer.
            KeyState::Pressed if self.held() == Some(usage) => {}
            KeyState::Pressed if keymap::repeats(usage) => {
                self.armed = (may_repeat && config.enabled()).then_some(Armed {
                    usage,
                    next_ns: now_ns.saturating_add(config.delay_ns),
                });
            }
            KeyState::Pressed => {}
            KeyState::Released => {
                if self.armed.is_some_and(|a| a.usage == usage) {
                    self.armed = None;
                }
            }
        }
    }

    /// Disarms (focus change, input reset).
    pub fn stop(&mut self) {
        self.armed = None;
    }

    pub fn held(&self) -> Option<KeyUsage> {
        self.armed.map(|a| a.usage)
    }

    /// When the next repeat is due, for the loop's wait deadline.
    pub fn deadline(&self) -> Option<u64> {
        self.armed.map(|a| a.next_ns)
    }

    /// One repeat if due at `now_ns`: the key and the tick time it stands for.
    pub fn due(&mut self, now_ns: u64, config: RepeatConfig) -> Option<(KeyUsage, u64)> {
        let armed = self.armed.as_mut()?;
        if now_ns < armed.next_ns || !config.enabled() {
            return None;
        }
        let tick = armed.next_ns;
        let next = tick.saturating_add(config.interval_ns);
        armed.next_ns = if next > now_ns {
            next
        } else {
            now_ns.saturating_add(config.interval_ns)
        };
        Some((armed.usage, tick))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: KeyUsage = KeyUsage(0x04);
    const B: KeyUsage = KeyUsage(0x05);
    const SHIFT: KeyUsage = KeyUsage(0xE1);
    const MS: u64 = 1_000_000;
    const CFG: RepeatConfig = RepeatConfig {
        delay_ns: 500 * MS,
        interval_ns: 40 * MS,
    };

    /// Steps a fake clock in 1 ms ticks from `from` to `to` (inclusive), collecting repeats.
    fn run(r: &mut KeyRepeater, from: u64, to: u64) -> Vec<u64> {
        let mut out = Vec::new();
        let mut t = from;
        while t <= to {
            if let Some((_, tick)) = r.due(t, CFG) {
                out.push(tick);
            }
            t += MS;
        }
        out
    }

    #[test]
    fn first_repeat_after_delay_then_at_rate() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 1000 * MS, true, CFG);
        assert_eq!(r.deadline(), Some(1500 * MS));
        let ticks = run(&mut r, 1000 * MS, 1620 * MS);
        assert_eq!(ticks, vec![1500 * MS, 1540 * MS, 1580 * MS, 1620 * MS]);
    }

    #[test]
    fn release_stops_and_other_release_does_not() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 0, true, CFG);
        r.key(B, KeyState::Released, 10 * MS, true, CFG);
        assert_eq!(r.held(), Some(A));
        r.key(A, KeyState::Released, 20 * MS, true, CFG);
        assert_eq!(r.deadline(), None);
        assert!(run(&mut r, 0, 2000 * MS).is_empty());
    }

    #[test]
    fn newest_press_takes_over_and_modifiers_do_not() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 0, true, CFG);
        r.key(B, KeyState::Pressed, 100 * MS, true, CFG);
        assert_eq!(r.held(), Some(B));
        assert_eq!(r.deadline(), Some(600 * MS));
        r.key(SHIFT, KeyState::Pressed, 200 * MS, true, CFG);
        assert_eq!(r.held(), Some(B), "a modifier press keeps the repeat");
        r.key(A, KeyState::Released, 300 * MS, true, CFG);
        assert_eq!(
            r.held(),
            Some(B),
            "releasing the older key keeps the newer one"
        );
    }

    #[test]
    fn a_duplicate_press_keeps_the_timer() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 0, true, CFG);
        r.key(A, KeyState::Pressed, 300 * MS, true, CFG);
        assert_eq!(r.deadline(), Some(500 * MS));
    }

    #[test]
    fn stop_disarms_for_focus_change() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 0, true, CFG);
        r.stop();
        assert!(run(&mut r, 0, 2000 * MS).is_empty());
    }

    #[test]
    fn not_armed_without_text_input_or_when_off() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 0, false, CFG);
        assert_eq!(r.deadline(), None);
        r.key(A, KeyState::Pressed, 0, true, RepeatConfig::OFF);
        assert_eq!(r.deadline(), None);
        r.key(SHIFT, KeyState::Pressed, 0, true, CFG);
        assert_eq!(r.deadline(), None, "modifiers never repeat");
    }

    #[test]
    fn late_wake_yields_one_repeat_and_skips_missed_ticks() {
        let mut r = KeyRepeater::new();
        r.key(A, KeyState::Pressed, 0, true, CFG);
        assert_eq!(r.due(2000 * MS, CFG), Some((A, 500 * MS)));
        assert_eq!(r.due(2000 * MS, CFG), None);
        assert_eq!(r.deadline(), Some(2040 * MS));
    }
}
