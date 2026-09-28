//! Destination: `graphics/src/window/tests.rs`, included from `graphics/src/window.rs` with
//! `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: per-connection serial minting (C3) and configure/ack matching (SPEC §5).

use crate::geometry::{Scale120, Size};
use crate::ids::{ObjectId, Serial, WindowId};
use crate::limits::{MAX_OUTSTANDING_CONFIGURES, MAX_SURFACE_EXTENT};
use crate::protocol::{Event, ProtocolError, Tagged};
use crate::window::{ConfigureState, DecorationMode, SerialMinter, WindowConfig, WindowStates};

fn size(width: u32, height: u32) -> Size {
    Size { width, height }
}

fn config(width: u32, height: u32) -> WindowConfig {
    WindowConfig::new(size(width, height), WindowStates::EMPTY, size(0, 0))
}

fn activated() -> WindowStates {
    WindowStates::from_bits(WindowStates::ACTIVATED).unwrap()
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

// --- SerialMinter -------------------------------------------------------------------------

#[test]
fn minter_starts_at_one_and_increments_by_one() {
    let mut minter = SerialMinter::new();
    assert_eq!(minter.mint(), Serial(1));
    assert_eq!(minter.mint(), Serial(2));
    assert_eq!(minter.mint(), Serial(3));
    assert_eq!(SerialMinter::default().peek(), Serial(1));
}

#[test]
fn minter_skips_zero_on_wrap() {
    let mut minter = SerialMinter::starting_at(u32::MAX - 1);
    assert_eq!(minter.mint(), Serial(u32::MAX - 1));
    assert_eq!(minter.mint(), Serial(u32::MAX));
    assert_eq!(minter.mint(), Serial(1));
    assert_eq!(minter.mint(), Serial(2));
}

#[test]
fn minter_starting_at_zero_is_normalised_to_one() {
    let mut minter = SerialMinter::starting_at(0);
    assert_eq!(minter.peek(), Serial(1));
    assert_eq!(minter.mint(), Serial(1));
}

#[test]
fn minter_peek_reports_next_serial_without_consuming() {
    let mut minter = SerialMinter::starting_at(u32::MAX);
    assert_eq!(minter.peek(), Serial(u32::MAX));
    assert_eq!(minter.peek(), Serial(u32::MAX));
    assert_eq!(minter.mint(), Serial(u32::MAX));
    assert_eq!(minter.peek(), Serial(1));
}

#[test]
fn minter_never_yields_zero_and_stays_unique_across_wrap() {
    let mut minter = SerialMinter::starting_at(u32::MAX - 1000);
    let mut seen = Vec::with_capacity(2000);
    for _ in 0..2000 {
        let s = minter.mint();
        assert_ne!(s, Serial(0));
        seen.push(s.0);
    }
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(seen.len(), 2000);
}

#[test]
fn windows_sharing_one_minter_get_distinct_serials_that_do_not_cross_ack() {
    let mut minter = SerialMinter::new();
    let mut a = ConfigureState::new();
    let mut b = ConfigureState::new();
    let sa = a.send(&mut minter, config(100, 100)).unwrap();
    let sb = b.send(&mut minter, config(200, 200)).unwrap();
    assert_ne!(sa, sb);
    let b_before = b;
    assert_eq!(b.ack(sa), Err(ProtocolError::SerialMismatch));
    assert_eq!(b, b_before);
    assert_eq!(a.ack(sa), Ok(config(100, 100)));
    assert_eq!(b.ack(sb), Ok(config(200, 200)));
}

// --- ConfigureState -----------------------------------------------------------------------

#[test]
fn fresh_window_is_not_configured() {
    let state = ConfigureState::new();
    assert!(!state.is_configured());
    assert_eq!(state.acked(), None);
    assert_eq!(state.outstanding_len(), 0);
    assert_eq!(state.last_sent(), None);
    assert_eq!(ConfigureState::default(), state);
}

#[test]
fn ack_of_sent_serial_configures_and_returns_its_config() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let cfg = WindowConfig::new(size(640, 480), activated(), size(1280, 800));
    let serial = state.send(&mut minter, cfg).unwrap();
    assert_eq!(serial, Serial(1));
    assert_eq!(state.outstanding_len(), 1);
    assert!(!state.is_configured());
    assert_eq!(state.ack(serial), Ok(cfg));
    assert!(state.is_configured());
    assert_eq!(state.acked(), Some((serial, cfg)));
    assert_eq!(state.outstanding_len(), 0);
}

#[test]
fn ack_of_unknown_serial_is_mismatch_and_leaves_state_unchanged() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let serial = state.send(&mut minter, config(10, 10)).unwrap();
    let before = state;
    assert_eq!(
        state.ack(Serial(serial.0 + 1)),
        Err(ProtocolError::SerialMismatch)
    );
    assert_eq!(state.ack(Serial(0)), Err(ProtocolError::SerialMismatch));
    assert_eq!(state, before);
}

#[test]
fn ack_before_any_configure_is_mismatch() {
    let mut state = ConfigureState::new();
    assert_eq!(state.ack(Serial(1)), Err(ProtocolError::SerialMismatch));
    assert!(!state.is_configured());
}

#[test]
fn each_serial_can_be_acked_at_most_once() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let serial = state.send(&mut minter, config(10, 10)).unwrap();
    assert!(state.ack(serial).is_ok());
    let before = state;
    assert_eq!(state.ack(serial), Err(ProtocolError::SerialMismatch));
    assert_eq!(state, before);
}

#[test]
fn ack_of_newer_serial_supersedes_every_older_outstanding_configure() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let s1 = state.send(&mut minter, config(1, 1)).unwrap();
    let s2 = state.send(&mut minter, config(2, 2)).unwrap();
    let s3 = state.send(&mut minter, config(3, 3)).unwrap();
    assert_eq!(state.ack(s2), Ok(config(2, 2)));
    assert_eq!(state.outstanding_len(), 1);
    assert_eq!(state.last_sent(), Some((s3, config(3, 3))));
    assert_eq!(state.ack(s1), Err(ProtocolError::SerialMismatch));
    assert_eq!(state.acked(), Some((s2, config(2, 2))));
    assert_eq!(state.ack(s3), Ok(config(3, 3)));
    assert_eq!(state.outstanding_len(), 0);
}

#[test]
fn ack_of_oldest_serial_keeps_newer_configures_outstanding() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let s1 = state.send(&mut minter, config(1, 1)).unwrap();
    let s2 = state.send(&mut minter, config(2, 2)).unwrap();
    assert_eq!(state.ack(s1), Ok(config(1, 1)));
    assert_eq!(state.outstanding_len(), 1);
    assert_eq!(state.check_ack(s2), Ok(()));
}

#[test]
fn check_ack_agrees_with_ack_and_never_mutates() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let s1 = state.send(&mut minter, config(1, 1)).unwrap();
    let before = state;
    assert_eq!(state.check_ack(s1), Ok(()));
    assert_eq!(
        state.check_ack(Serial(77)),
        Err(ProtocolError::SerialMismatch)
    );
    assert_eq!(state, before);
    assert!(state.ack(s1).is_ok());
    assert_eq!(state.check_ack(s1), Err(ProtocolError::SerialMismatch));
}

#[test]
fn outstanding_configures_are_bounded_and_a_refused_send_consumes_no_serial() {
    assert_eq!(MAX_OUTSTANDING_CONFIGURES, 4);
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let mut serials = Vec::new();
    for i in 0..MAX_OUTSTANDING_CONFIGURES {
        serials.push(state.send(&mut minter, config(i as u32, 1)).unwrap());
    }
    let next = minter.peek();
    let before = state;
    assert_eq!(
        state.send(&mut minter, config(99, 99)),
        Err(ProtocolError::LimitExceeded)
    );
    assert_eq!(minter.peek(), next);
    assert_eq!(state, before);
    assert!(state.ack(serials[0]).is_ok());
    assert_eq!(state.send(&mut minter, config(99, 99)), Ok(next));
}

#[test]
fn send_enforces_m10_vocabulary_without_consuming_a_serial() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let base = config(100, 100);
    let too_big = WindowConfig {
        size: size(MAX_SURFACE_EXTENT + 1, 1),
        ..base
    };
    let too_big_bounds = WindowConfig {
        bounds: size(1, MAX_SURFACE_EXTENT + 1),
        ..base
    };
    let scaled = WindowConfig {
        scale: Scale120(240),
        ..base
    };
    let client_deco = WindowConfig {
        decoration: DecorationMode::Client,
        ..base
    };
    let maximized = WindowConfig {
        states: WindowStates::from_bits(WindowStates::MAXIMIZED).unwrap(),
        ..base
    };
    let cases = [
        (too_big, ProtocolError::InvalidLayout),
        (too_big_bounds, ProtocolError::InvalidLayout),
        (scaled, ProtocolError::InvalidScale),
        (client_deco, ProtocolError::UnsupportedFeature),
        (maximized, ProtocolError::UnsupportedFeature),
    ];
    for (cfg, code) in cases {
        assert_eq!(cfg.validate_m10(), Err(code), "{cfg:?}");
        assert_eq!(state.send(&mut minter, cfg), Err(code), "{cfg:?}");
        assert_eq!(minter.peek(), Serial(1));
        assert_eq!(state.outstanding_len(), 0);
    }
    let edge = WindowConfig::new(
        size(MAX_SURFACE_EXTENT, MAX_SURFACE_EXTENT),
        activated(),
        size(MAX_SURFACE_EXTENT, MAX_SURFACE_EXTENT),
    );
    assert_eq!(edge.validate_m10(), Ok(()));
    assert_eq!(state.send(&mut minter, edge), Ok(Serial(1)));
}

#[test]
fn window_config_new_uses_m10_scale_and_server_decorations() {
    let cfg = config(1, 2);
    assert_eq!(cfg.scale, Scale120::ONE);
    assert_eq!(cfg.decoration, DecorationMode::Server);
    assert_eq!(cfg.size, size(1, 2));
    assert_eq!(cfg.bounds, size(0, 0));
    assert_eq!(cfg.states, WindowStates::EMPTY);
}

#[test]
fn last_sent_tracks_newest_outstanding_configure() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let _ = state.send(&mut minter, config(1, 1)).unwrap();
    let s2 = state.send(&mut minter, config(2, 2)).unwrap();
    assert_eq!(state.last_sent(), Some((s2, config(2, 2))));
    assert!(state.ack(s2).is_ok());
    assert_eq!(state.last_sent(), None);
}

#[test]
fn acked_config_is_retained_until_the_next_ack() {
    let mut minter = SerialMinter::new();
    let mut state = ConfigureState::new();
    let s1 = state.send(&mut minter, config(1, 1)).unwrap();
    assert!(state.ack(s1).is_ok());
    let s2 = state.send(&mut minter, config(2, 2)).unwrap();
    assert_eq!(state.acked(), Some((s1, config(1, 1))));
    assert!(state.is_configured());
    assert!(state.ack(s2).is_ok());
    assert_eq!(state.acked(), Some((s2, config(2, 2))));
}

#[test]
fn configure_event_round_trips_through_the_wire_codec() {
    let window = WindowId(ObjectId::new(3, 9).unwrap());
    let cfg = WindowConfig::new(size(640, 480), activated(), size(1280, 800));
    let event = cfg.event(window, Serial(42));
    assert_eq!(
        event,
        Event::Configure {
            window,
            serial: Serial(42),
            size: size(640, 480),
            scale: Scale120::ONE,
            decoration: DecorationMode::Server,
            states: activated(),
            bounds: size(1280, 800),
        }
    );
    let bytes = event.encode(0).unwrap();
    assert_eq!(
        Event::decode(&bytes),
        Ok(Tagged {
            tag: 0,
            message: event
        })
    );
}

/// Property: random sends and acks (valid and invalid) against an oldest-first model.
#[test]
fn property_ack_semantics_match_reference_model() {
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut minter = SerialMinter::starting_at(u32::MAX - 64);
    let mut state = ConfigureState::new();
    let mut model: Vec<(Serial, WindowConfig)> = Vec::new();
    let mut model_acked: Option<(Serial, WindowConfig)> = None;
    let mut ever_sent: Vec<Serial> = Vec::new();
    for step in 0..5000u32 {
        match rng.below(3) {
            0 => {
                let cfg = config(step % 4096, 1);
                let result = state.send(&mut minter, cfg);
                if model.len() == MAX_OUTSTANDING_CONFIGURES {
                    assert_eq!(result, Err(ProtocolError::LimitExceeded));
                } else {
                    let s = result.unwrap();
                    assert_ne!(s, Serial(0));
                    model.push((s, cfg));
                    ever_sent.push(s);
                }
            }
            1 if !model.is_empty() => {
                let i = rng.below(model.len() as u64) as usize;
                let (s, cfg) = model[i];
                assert_eq!(state.ack(s), Ok(cfg));
                model.drain(..=i);
                model_acked = Some((s, cfg));
            }
            _ => {
                let probe = if ever_sent.is_empty() || rng.below(2) == 0 {
                    Serial(rng.next() as u32)
                } else {
                    ever_sent[rng.below(ever_sent.len() as u64) as usize]
                };
                let expected = model.iter().position(|(s, _)| *s == probe);
                match expected {
                    Some(i) => {
                        let cfg = model[i].1;
                        assert_eq!(state.ack(probe), Ok(cfg));
                        model.drain(..=i);
                        model_acked = Some((probe, cfg));
                    }
                    None => {
                        let before = state;
                        assert_eq!(state.ack(probe), Err(ProtocolError::SerialMismatch));
                        assert_eq!(state, before);
                    }
                }
            }
        }
        assert_eq!(state.outstanding_len(), model.len());
        assert_eq!(state.acked(), model_acked);
        assert_eq!(state.last_sent(), model.last().copied());
    }
}
