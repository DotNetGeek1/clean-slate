//! Independent §2.3 / §3.3 field-range tiling vs production pad tables.

use super::frame_spec::{EVENT_SPECS, REQUEST_SPECS};
use super::BODY_OFFSET;
use super::FRAME_BYTES;

type Range = (u8, u8);

fn assert_tiles_12_64(fields: &[Range], pads: &[Range]) {
    let mut covered = [false; FRAME_BYTES];
    for &(s, e) in fields {
        assert!(s >= BODY_OFFSET as u8 && e as usize <= FRAME_BYTES);
        assert!(s < e);
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
    for (i, slot) in covered
        .iter()
        .enumerate()
        .take(FRAME_BYTES)
        .skip(BODY_OFFSET)
    {
        assert!(*slot, "gap at offset {i}");
    }
}

fn spec_pads(op: u16, specs: &[super::frame_spec::OpcodeSpec]) -> Vec<Range> {
    specs
        .iter()
        .find(|s| s.opcode == op)
        .map(|s| s.pads.to_vec())
        .expect("opcode in production table")
}

#[test]
fn request_body_layout_tiles_with_spec_fields() {
    let cases: &[(u16, &[Range])] = &[
        (super::OP_HELLO, &[(12, 24)]),
        (super::OP_REGISTER_BUFFER, &[(12, 25)]),
        (super::OP_UNREGISTER_BUFFER, &[]),
        (super::OP_CREATE_SURFACE, &[]),
        (super::OP_DESTROY_SURFACE, &[]),
        (super::OP_ASSIGN_ROLE, &[(12, 13), (16, 20)]),
        (super::OP_ATTACH, &[(12, 18)]),
        (super::OP_DAMAGE, &[(12, 13), (16, 56)]),
        (super::OP_SET_OPAQUE_REGION, &[(12, 14), (16, 64)]),
        (super::OP_SET_INPUT_REGION, &[(12, 14), (16, 64)]),
        (super::OP_COMMIT, &[(12, 14), (16, 20)]),
        (super::OP_CREATE_WINDOW, &[]),
        (super::OP_DESTROY_WINDOW, &[]),
        (super::OP_SET_TITLE, &[(12, 53)]),
        (super::OP_SET_SIZE_LIMITS, &[(12, 28)]),
        (super::OP_SHOW, &[]),
        (super::OP_HIDE, &[]),
        (super::OP_BEGIN_MOVE, &[(12, 16)]),
        (super::OP_BEGIN_RESIZE, &[(12, 17)]),
        (super::OP_ACK_CONFIGURE, &[(12, 16)]),
    ];
    for (op, fields) in cases {
        assert_tiles_12_64(fields, &spec_pads(*op, REQUEST_SPECS));
    }
}

#[test]
fn event_body_layout_tiles_with_spec_fields() {
    let cases: &[(u16, &[Range])] = &[
        (
            super::OP_WELCOME,
            &[
                (12, 14),
                (14, 16),
                (16, 24),
                (24, 28),
                (28, 32),
                (32, 36),
                (36, 40),
                (40, 41),
                (42, 44),
                (44, 48),
                (48, 52),
                (52, 56),
            ],
        ),
        (super::OP_ERROR, &[(12, 16)]),
        (super::OP_BUFFER_REGISTERED, &[]),
        (super::OP_BUFFER_RELEASED, &[]),
        (super::OP_BUFFER_UNREGISTERED, &[]),
        (super::OP_SURFACE_CREATED, &[]),
        (super::OP_FRAME_DONE, &[(12, 28)]),
        (super::OP_WINDOW_CREATED, &[]),
        (
            super::OP_CONFIGURE,
            &[
                (12, 16),
                (16, 20),
                (20, 24),
                (24, 26),
                (26, 27),
                (28, 32),
                (32, 36),
                (36, 40),
            ],
        ),
        (super::OP_CLOSE_REQUESTED, &[]),
        (super::OP_KEYBOARD_FOCUS, &[]),
        (
            super::OP_KEY,
            &[(12, 16), (16, 24), (24, 26), (26, 27), (28, 30)],
        ),
        (super::OP_MODIFIERS_CHANGED, &[(12, 14)]),
        (super::OP_POINTER_ENTER, &[(12, 24)]),
        (super::OP_POINTER_LEAVE, &[(12, 16)]),
        (super::OP_POINTER_MOTION, &[(12, 28)]),
        (super::OP_POINTER_BUTTON, &[(12, 27)]),
        (super::OP_POINTER_AXIS, &[(12, 28)]),
        (super::OP_INPUT_RESET, &[]),
    ];
    for (op, fields) in cases {
        assert_tiles_12_64(fields, &spec_pads(*op, EVENT_SPECS));
    }
}
