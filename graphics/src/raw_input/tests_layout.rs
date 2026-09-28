//! §6.1 field/pad tiling for each raw-input kind payload.

use super::RAW_INPUT_RECORD_BYTES;

type Range = (u8, u8);

#[allow(clippy::needless_range_loop)]
fn assert_tiles(fields: &[Range], pads: &[Range]) {
    let mut covered = [false; RAW_INPUT_RECORD_BYTES];
    for &(s, e) in fields {
        assert!(s < e && e as usize <= RAW_INPUT_RECORD_BYTES);
        for i in s..e {
            assert!(!covered[i as usize], "overlap at {i}");
            covered[i as usize] = true;
        }
    }
    for &(s, e) in pads {
        for i in s..e {
            assert!(!covered[i as usize], "pad overlaps field at {i}");
            covered[i as usize] = true;
        }
    }
    for (i, slot) in covered.iter().enumerate() {
        assert!(*slot, "gap at offset {i}");
    }
}

const PAD_21_24: &[(u8, u8)] = &[(21, 24)];

#[test]
fn key_record_layout_tiles() {
    assert_tiles(
        &[(0, 8), (8, 16), (16, 20), (20, 21), (24, 26), (26, 27)],
        &[(21, 24), (27, 32)],
    );
}

#[test]
fn relmotion_record_layout_tiles() {
    assert_tiles(
        &[(0, 8), (8, 16), (16, 20), (20, 21), (24, 28), (28, 32)],
        PAD_21_24,
    );
}

#[test]
fn button_record_layout_tiles() {
    assert_tiles(
        &[(0, 8), (8, 16), (16, 20), (20, 21), (24, 26), (26, 27)],
        &[(21, 24), (27, 32)],
    );
}

#[test]
fn wheel_record_layout_tiles() {
    assert_tiles(
        &[(0, 8), (8, 16), (16, 20), (20, 21), (24, 28), (28, 32)],
        PAD_21_24,
    );
}

#[test]
fn overflow_record_layout_tiles() {
    assert_tiles(
        &[(0, 8), (8, 16), (16, 20), (20, 21), (24, 28)],
        &[(21, 24), (28, 32)],
    );
}
