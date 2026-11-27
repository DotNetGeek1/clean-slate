//! ABI struct field/pad tiling (§8.3, §9).

use super::display::{
    DISPLAY_MODE_ENTRY_BYTES, DISPLAY_MODE_INFO_BYTES, DISPLAY_MODE_LIST_BYTES,
    PRESENT_REQUEST_BYTES, PRESENT_STATUS_BYTES, SCANOUT_MAPPING_BYTES,
};
use super::input::INPUT_DEVICE_INFO_BYTES;
use crate::mode::MAX_OFFERED_MODES;

type Range = (usize, usize);

#[allow(clippy::needless_range_loop)]
fn assert_tiles(size: usize, fields: &[Range], pads: &[Range]) {
    let mut covered = vec![false; size];
    for &(s, e) in fields {
        assert!(s < e && e <= size);
        for i in s..e {
            assert!(!covered[i], "overlap at {i}");
            covered[i] = true;
        }
    }
    for &(s, e) in pads {
        for i in s..e {
            assert!(!covered[i], "pad overlaps field at {i}");
            covered[i] = true;
        }
    }
    for (i, slot) in covered.iter().enumerate() {
        assert!(*slot, "gap at offset {i}");
    }
}

#[test]
fn display_mode_info_layout_tiles() {
    assert_tiles(
        DISPLAY_MODE_INFO_BYTES,
        &[
            (0, 4),
            (4, 8),
            (8, 12),
            (12, 16),
            (16, 17),
            (18, 20),
            (20, 24),
            (24, 25),
            (25, 26),
        ],
        &[(17, 18), (26, 32)],
    );
}

#[test]
fn scanout_mapping_layout_tiles() {
    assert_tiles(
        SCANOUT_MAPPING_BYTES,
        &[(0, 4), (4, 5), (8, 16), (16, 24), (24, 28)],
        &[(5, 8), (28, 32)],
    );
}

#[test]
fn present_request_layout_tiles() {
    let mut fields = vec![(0, 4), (4, 5), (5, 6)];
    for i in 0..16 {
        fields.push((8 + 8 * i, 8 + 8 * (i + 1)));
    }
    assert_tiles(PRESENT_REQUEST_BYTES, &fields, &[(6, 8)]);
}

#[test]
fn present_status_layout_tiles() {
    assert_tiles(
        PRESENT_STATUS_BYTES,
        &[(0, 4), (4, 5), (5, 6), (6, 8), (8, 16), (16, 24), (24, 32)],
        &[(32, 40)],
    );
}

#[test]
fn input_device_info_layout_tiles() {
    assert_tiles(
        INPUT_DEVICE_INFO_BYTES,
        &[(0, 4), (4, 8), (8, 10), (10, 12)],
        &[(12, 16)],
    );
}

#[test]
fn display_mode_list_layout_tiles() {
    let mut fields = vec![(0, 4), (4, 5)];
    let mut pads = vec![(5, 8)];
    for i in 0..MAX_OFFERED_MODES {
        let base = 8 + DISPLAY_MODE_ENTRY_BYTES * i;
        fields.extend([(base, base + 2), (base + 2, base + 4), (base + 4, base + 5)]);
        pads.push((base + 5, base + DISPLAY_MODE_ENTRY_BYTES));
    }
    assert_tiles(DISPLAY_MODE_LIST_BYTES, &fields, &pads);
}
