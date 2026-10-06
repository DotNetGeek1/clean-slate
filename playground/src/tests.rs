//! Host tests for layout, state transitions, damage minimality and rendering.

use std::vec;
use std::vec::Vec;

use clean_slate_graphics::input::{KeyState, KeyUsage, Modifiers, PointerButton, KEY_A};
use clean_slate_graphics::{BufferLayout, Point, Rect};
use clean_slate_raster::{pixel_at, Canvas};
use clean_slate_ui::surface::Damage;
use clean_slate_ui::{QualityTier, Style, CLEAN_SLATE_DARK};

use crate::app::{Control, Playground, MAX_CLICKS, TEXT_CAPACITY};
use crate::keys::{KEY_BACKSPACE, KEY_SPACE, KEY_TAB};
use crate::layout::{PanelLayout, PANEL_SIZE};
use crate::render;
use crate::session::buffer_layout;

const TIERS: [QualityTier; 2] = [QualityTier::Q0, QualityTier::Q1];

fn style(tier: QualityTier) -> Style<'static> {
    Style::new(&CLEAN_SLATE_DARK, tier)
}

fn app(tier: QualityTier) -> Playground {
    let mut app = Playground::laid_out(style(tier), PANEL_SIZE);
    app.set_window_active(true);
    app.set_keyboard_focus(true);
    app
}

fn mods(bits: u16) -> Modifiers {
    Modifiers::from_bits(bits).expect("known modifier bits")
}

fn none() -> Modifiers {
    mods(0)
}

fn center(r: Rect) -> Point {
    Point {
        x: r.x + (r.width / 2) as i32,
        y: r.y + (r.height / 2) as i32,
    }
}

fn overlaps(a: Rect, b: Rect) -> bool {
    matches!(a.intersect(b), Ok(Some(_)))
}

fn inside(inner: Rect, outer: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && inner.x + inner.width as i32 <= outer.x + outer.width as i32
        && inner.y + inner.height as i32 <= outer.y + outer.height as i32
}

fn click(app: &mut Playground, p: Point) {
    app.pointer_motion(p);
    app.pointer_button(PointerButton::Left, KeyState::Pressed);
    app.pointer_button(PointerButton::Left, KeyState::Released);
}

fn tap(app: &mut Playground, usage: KeyUsage, modifiers: Modifiers) {
    app.key(usage, KeyState::Pressed, modifiers);
    app.key(usage, KeyState::Released, modifiers);
}

fn pixels() -> (BufferLayout, Vec<u8>) {
    let layout = buffer_layout().expect("panel layout");
    (layout, vec![0u8; layout.byte_len()])
}

fn paint_full(app: &Playground) -> Vec<u8> {
    let (layout, mut bytes) = pixels();
    let mut canvas = Canvas::new(&mut bytes, layout).expect("canvas");
    render::paint(&mut canvas, app.style(), app.layout(), &app.view());
    bytes
}

fn paint_into(bytes: &mut [u8], app: &Playground, damage: &Damage) {
    let layout = buffer_layout().expect("panel layout");
    let mut canvas = Canvas::new(bytes, layout).expect("canvas");
    render::paint_damage(&mut canvas, app.style(), app.layout(), &app.view(), damage);
}

fn region(bytes: &[u8], r: Rect) -> Vec<u8> {
    let layout = buffer_layout().expect("panel layout");
    let mut out = Vec::new();
    for y in r.y..r.y + r.height as i32 {
        for x in r.x..r.x + r.width as i32 {
            out.extend_from_slice(&pixel_at(bytes, layout, x as u32, y as u32).expect("in bounds"));
        }
    }
    out
}

/// Applies `step` and returns its damage.
fn damage_of(app: &mut Playground, step: impl FnOnce(&mut Playground)) -> Damage {
    let before = app.view();
    step(app);
    app.damage_since(&before)
}

fn damaged(damage: &Damage) -> Vec<Rect> {
    damage.rects().to_vec()
}

// ---- layout -------------------------------------------------------------------------------------

#[test]
fn layout_regions_are_non_empty_and_inside_the_panel_at_q0_and_q1() {
    for tier in TIERS {
        let layout = PanelLayout::compute(style(tier), PANEL_SIZE);
        assert_eq!(layout.bounds.width, PANEL_SIZE.width);
        assert_eq!(layout.bounds.height, PANEL_SIZE.height);
        for (index, r) in layout.regions().into_iter().enumerate() {
            assert!(r.width > 0 && r.height > 0, "region {index} empty: {r:?}");
            assert!(inside(r, layout.bounds), "region {index} outside: {r:?}");
        }
        for r in [
            layout.increment,
            layout.reset,
            layout.counter,
            layout.toggle,
        ] {
            assert!(inside(r, layout.controls_card));
        }
        assert!(inside(layout.pad, layout.pointer_card));
        assert!(inside(layout.readout, layout.pointer_card));
        for r in [layout.keycap, layout.key_line, layout.text_line] {
            assert!(inside(r, layout.keyboard_card));
        }
    }
}

#[test]
fn independently_damaged_regions_never_overlap() {
    for tier in TIERS {
        let l = PanelLayout::compute(style(tier), PANEL_SIZE);
        let regions = [
            l.status,
            l.increment,
            l.reset,
            l.counter,
            l.toggle,
            l.pad,
            l.readout,
            l.keycap,
            l.key_line,
            l.text_line,
        ];
        for (i, a) in regions.iter().enumerate() {
            for b in &regions[i + 1..] {
                assert!(!overlaps(*a, *b), "{a:?} overlaps {b:?}");
            }
        }
        for a in [l.controls_card, l.pointer_card, l.keyboard_card] {
            for b in [l.title, l.status, l.subtitle] {
                assert!(!overlaps(a, b));
            }
        }
        assert!(!overlaps(l.controls_card, l.pointer_card));
        assert!(!overlaps(l.pointer_card, l.keyboard_card));
        assert!(!overlaps(l.controls_card, l.keyboard_card));
    }
}

#[test]
fn hit_testing_finds_each_control_at_its_centre_only() {
    let layout = PanelLayout::compute(style(QualityTier::Q0), PANEL_SIZE);
    for control in Control::ORDER {
        let r = layout.control_rect(control);
        assert_eq!(layout.control_at(center(r)), Some(control));
    }
    assert_eq!(layout.control_at(center(layout.pad)), None);
    assert_eq!(layout.control_at(center(layout.counter)), None);
    assert_eq!(layout.control_at(Point { x: 0, y: 0 }), None);
}

#[test]
fn marks_are_clipped_to_the_pad_interior() {
    let s = style(QualityTier::Q1);
    let layout = PanelLayout::compute(s, PANEL_SIZE);
    let interior = layout.pad_interior(s);
    let corner = Point {
        x: interior.x,
        y: interior.y,
    };
    let mark = layout.mark_rect(s, corner, 11);
    assert!(inside(mark, interior));
    assert_eq!((mark.width, mark.height), (6, 6));
}

// ---- state transitions ----------------------------------------------------------------------------

#[test]
fn clicking_increment_counts_and_reset_clears() {
    let mut app = app(QualityTier::Q0);
    let increment = center(app.layout().increment);
    click(&mut app, increment);
    click(&mut app, increment);
    assert_eq!(app.clicks(), 2);
    assert_eq!(app.focus(), Control::Increment);
    let reset = center(app.layout().reset);
    click(&mut app, reset);
    assert_eq!(app.clicks(), 0);
    assert_eq!(app.focus(), Control::Reset);
}

#[test]
fn release_outside_the_pressed_control_does_not_activate() {
    let mut app = app(QualityTier::Q0);
    app.pointer_motion(center(app.layout().increment));
    app.pointer_button(PointerButton::Left, KeyState::Pressed);
    assert!(app.view().increment.pressed);
    app.pointer_motion(center(app.layout().pad));
    assert!(
        !app.view().increment.pressed,
        "pressed shows only while hovered"
    );
    app.pointer_button(PointerButton::Left, KeyState::Released);
    assert_eq!(app.clicks(), 0);
}

#[test]
fn only_the_left_button_activates() {
    let mut app = app(QualityTier::Q0);
    app.pointer_motion(center(app.layout().increment));
    for button in [PointerButton::Right, PointerButton::Middle] {
        app.pointer_button(button, KeyState::Pressed);
        app.pointer_button(button, KeyState::Released);
    }
    assert_eq!(app.clicks(), 0);
}

#[test]
fn clicking_the_toggle_flips_the_marker_colour() {
    let mut app = app(QualityTier::Q1);
    let toggle = center(app.layout().toggle);
    click(&mut app, toggle);
    assert!(app.magenta());
    click(&mut app, toggle);
    assert!(!app.magenta());
}

#[test]
fn counter_saturates() {
    let mut app = app(QualityTier::Q0);
    for _ in 0..MAX_CLICKS + 3 {
        tap(&mut app, KEY_SPACE, none());
    }
    assert_eq!(app.clicks(), MAX_CLICKS);
}

#[test]
fn pad_tracks_the_cursor_and_last_click() {
    let mut app = app(QualityTier::Q0);
    let p = center(app.layout().pad);
    app.pointer_motion(p);
    let view = app.view();
    assert!(view.pad_hovered);
    assert_eq!(view.cursor, Some(p));
    assert_eq!(view.click_mark, None);
    click(&mut app, p);
    assert_eq!(app.view().click_mark, Some(p));
    app.pointer_leave();
    let view = app.view();
    assert!(!view.pad_hovered);
    assert_eq!(view.cursor, None);
    assert_eq!(view.click_mark, Some(p), "the click mark persists");
}

#[test]
fn typing_edits_the_text_line() {
    let mut app = app(QualityTier::Q0);
    tap(&mut app, KEY_A, none());
    tap(&mut app, KEY_A, mods(Modifiers::SHIFT));
    tap(&mut app, KeyUsage(0x1E), none());
    assert_eq!(app.text(), "aA1");
    tap(&mut app, KEY_BACKSPACE, none());
    assert_eq!(app.text(), "aA");
    tap(&mut app, KEY_A, mods(Modifiers::CTRL));
    assert_eq!(app.text(), "aA", "chorded keys are not text");
    tap(&mut app, KeyUsage(0x29), none());
    assert_eq!(app.text(), "");
    for _ in 0..TEXT_CAPACITY + 4 {
        tap(&mut app, KEY_A, mods(Modifiers::CAPS_LOCK));
    }
    assert_eq!(app.text().len(), TEXT_CAPACITY);
    assert!(app.text().bytes().all(|b| b == b'A'));
}

#[test]
fn tab_cycles_focus_and_space_activates_it() {
    let mut app = app(QualityTier::Q0);
    assert_eq!(app.focus(), Control::Increment);
    tap(&mut app, KEY_TAB, none());
    assert_eq!(app.focus(), Control::Reset);
    tap(&mut app, KEY_TAB, none());
    assert_eq!(app.focus(), Control::Toggle);
    tap(&mut app, KEY_SPACE, none());
    assert!(app.magenta());
    tap(&mut app, KEY_TAB, mods(Modifiers::SHIFT));
    assert_eq!(app.focus(), Control::Reset);
    tap(&mut app, KEY_TAB, mods(Modifiers::SHIFT));
    tap(&mut app, KEY_SPACE, none());
    assert_eq!(app.clicks(), 1);
}

#[test]
fn key_indicator_tracks_last_key_hold_and_presses() {
    let mut app = app(QualityTier::Q0);
    app.key(KEY_A, KeyState::Pressed, none());
    let view = app.view();
    assert_eq!(view.key, Some(KEY_A));
    assert!(view.key_held);
    assert_eq!(view.presses, 1);
    app.key(KEY_A, KeyState::Released, none());
    assert!(!app.view().key_held);
    assert_eq!(app.view().presses, 1, "releases are not presses");
}

#[test]
fn focus_loss_and_input_reset_drop_held_state() {
    let mut app = app(QualityTier::Q0);
    app.key(
        KEY_A,
        KeyState::Pressed,
        mods(Modifiers::SHIFT | Modifiers::CAPS_LOCK),
    );
    app.input_reset();
    let view = app.view();
    assert!(!view.key_held);
    assert_eq!(
        view.modifiers,
        mods(Modifiers::CAPS_LOCK),
        "lock state survives a reset"
    );

    app.key(KEY_A, KeyState::Pressed, none());
    app.set_keyboard_focus(false);
    let view = app.view();
    assert!(!view.key_held);
    assert!(
        !view.increment.focused,
        "no focus ring without keyboard focus"
    );
}

// ---- damage ---------------------------------------------------------------------------------------

#[test]
fn events_that_change_nothing_visible_produce_no_damage() {
    let mut app = app(QualityTier::Q1);
    let increment = app.layout().increment;
    app.pointer_motion(center(increment));
    let inside_button = Point {
        x: increment.x + 1,
        y: increment.y + 1,
    };
    assert!(damage_of(&mut app, |a| a.pointer_motion(inside_button)).is_empty());
    assert!(damage_of(&mut app, |a| a
        .pointer_button(PointerButton::Right, KeyState::Pressed))
    .is_empty());
    assert!(damage_of(&mut app, |a| a.set_window_active(true)).is_empty());
    assert!(damage_of(&mut app, |a| a.set_keyboard_focus(true)).is_empty());
    let title = center(app.layout().title);
    app.pointer_motion(title);
    assert!(damage_of(&mut app, |a| a.pointer_motion(Point {
        x: title.x + 3,
        y: title.y
    }))
    .is_empty());
    assert!(damage_of(&mut app, |a| click(a, title)).is_empty());
    assert!(damage_of(&mut app, |a| a.input_reset()).is_empty());
}

#[test]
fn a_button_click_damages_only_the_button_and_counter() {
    let mut app = app(QualityTier::Q0);
    let l = *app.layout();
    app.pointer_motion(center(l.increment));
    let press = damage_of(&mut app, |a| {
        a.pointer_button(PointerButton::Left, KeyState::Pressed)
    });
    assert_eq!(damaged(&press), vec![l.increment]);
    let release = damage_of(&mut app, |a| {
        a.pointer_button(PointerButton::Left, KeyState::Released)
    });
    assert_eq!(damaged(&release), vec![l.increment, l.counter]);
}

#[test]
fn hover_damages_only_the_entered_and_left_controls() {
    let mut app = app(QualityTier::Q0);
    let l = *app.layout();
    let enter = damage_of(&mut app, |a| a.pointer_motion(center(l.reset)));
    assert_eq!(damaged(&enter), vec![l.reset]);
    let cross = damage_of(&mut app, |a| a.pointer_motion(center(l.increment)));
    assert_eq!(damaged(&cross), vec![l.increment, l.reset]);
}

#[test]
fn a_toggle_click_damages_the_toggle_and_visible_marks() {
    let s = style(QualityTier::Q1);
    let mut app = app(QualityTier::Q1);
    let l = *app.layout();
    let mark = center(l.pad);
    click(&mut app, mark);
    app.pointer_motion(center(l.toggle));
    let flip = damage_of(&mut app, |a| click(a, center(l.toggle)));
    let rects = damaged(&flip);
    assert!(rects.contains(&l.toggle));
    assert!(rects.contains(&l.mark_rect(s, mark, crate::layout::CLICK_MARK_SIZE)));
    assert!(
        !rects.contains(&l.pad),
        "recolour does not repaint the whole pad"
    );
    assert!(!rects.contains(&l.counter));
}

#[test]
fn pointer_motion_inside_the_pad_damages_marker_rects_and_readout() {
    let s = style(QualityTier::Q0);
    let mut app = app(QualityTier::Q0);
    let l = *app.layout();
    let a = center(l.pad);
    let b = Point { x: a.x + 20, ..a };
    app.pointer_motion(a);
    let motion = damage_of(&mut app, |app| app.pointer_motion(b));
    let marker = crate::layout::MARKER_SIZE;
    assert_eq!(
        damaged(&motion),
        vec![
            l.mark_rect(s, a, marker),
            l.mark_rect(s, b, marker),
            l.readout
        ]
    );
    let panel = u64::from(l.bounds.width) * u64::from(l.bounds.height);
    assert!(
        motion.area() * 20 < panel,
        "motion repaints a small fraction of the panel"
    );
}

#[test]
fn typing_damages_the_key_indicator_and_text_line_only() {
    let mut app = app(QualityTier::Q0);
    let l = *app.layout();
    let press = damage_of(&mut app, |a| a.key(KEY_A, KeyState::Pressed, none()));
    assert_eq!(damaged(&press), vec![l.keycap, l.key_line, l.text_line]);
    let release = damage_of(&mut app, |a| a.key(KEY_A, KeyState::Released, none()));
    assert_eq!(damaged(&release), vec![l.keycap]);
}

#[test]
fn focus_changes_damage_status_rings_and_caret() {
    let mut app = app(QualityTier::Q0);
    let l = *app.layout();
    let blur = damage_of(&mut app, |a| a.set_keyboard_focus(false));
    assert_eq!(damaged(&blur), vec![l.status, l.increment, l.text_line]);
    let deactivate = damage_of(&mut app, |a| a.set_window_active(false));
    assert_eq!(damaged(&deactivate), vec![l.status]);
}

// ---- rendering ------------------------------------------------------------------------------------

type Step = fn(&mut Playground);

fn script() -> [(&'static str, Step); 14] {
    [
        ("hover +1", |a| {
            a.pointer_motion(center(a.layout().increment))
        }),
        ("press +1", |a| {
            a.pointer_button(PointerButton::Left, KeyState::Pressed)
        }),
        ("release +1", |a| {
            a.pointer_button(PointerButton::Left, KeyState::Released)
        }),
        ("click toggle", |a| click(a, center(a.layout().toggle))),
        ("enter pad", |a| a.pointer_motion(center(a.layout().pad))),
        ("click pad", |a| click(a, center(a.layout().pad))),
        ("move in pad", |a| {
            let p = center(a.layout().pad);
            a.pointer_motion(Point {
                x: p.x - 30,
                y: p.y + 9,
            })
        }),
        ("key a", |a| a.key(KEY_A, KeyState::Pressed, none())),
        ("release a", |a| a.key(KEY_A, KeyState::Released, none())),
        ("shift B", |a| {
            tap(a, KeyUsage(0x05), mods(Modifiers::SHIFT))
        }),
        ("tab", |a| tap(a, KEY_TAB, none())),
        ("blur", |a| a.set_keyboard_focus(false)),
        ("leave", |a| a.pointer_leave()),
        ("inactive", |a| a.set_window_active(false)),
    ]
}

#[test]
fn incremental_repaint_matches_a_full_repaint_at_q0_and_q1() {
    for tier in TIERS {
        let mut app = app(tier);
        let mut incremental = paint_full(&app);
        for (name, step) in script() {
            let damage = damage_of(&mut app, step);
            assert!(
                !damage.is_empty(),
                "{tier:?} {name}: expected a visible change"
            );
            paint_into(&mut incremental, &app, &damage);
            assert!(
                incremental == paint_full(&app),
                "{tier:?} {name}: damaged repaint differs from a full repaint"
            );
        }
    }
}

#[test]
fn clicks_and_keys_visibly_change_their_regions() {
    for tier in TIERS {
        let mut app = app(tier);
        let l = *app.layout();
        let before = paint_full(&app);
        click(&mut app, center(l.increment));
        let counted = paint_full(&app);
        assert_ne!(region(&before, l.counter), region(&counted, l.counter));

        click(&mut app, center(l.toggle));
        let toggled = paint_full(&app);
        assert_ne!(region(&counted, l.toggle), region(&toggled, l.toggle));

        tap(&mut app, KEY_A, none());
        let typed = paint_full(&app);
        assert_ne!(region(&toggled, l.key_line), region(&typed, l.key_line));
        assert_ne!(region(&toggled, l.text_line), region(&typed, l.text_line));
        assert_eq!(region(&toggled, l.title), region(&typed, l.title));
    }
}

#[test]
fn painting_is_deterministic() {
    for tier in TIERS {
        assert!(paint_full(&app(tier)) == paint_full(&app(tier)), "{tier:?}");
    }
}

#[test]
fn panel_background_uses_the_surface_token_and_is_opaque() {
    for tier in TIERS {
        let app = app(tier);
        let bytes = paint_full(&app);
        let layout = buffer_layout().expect("panel layout");
        let c = CLEAN_SLATE_DARK.palette.surface;
        let px = pixel_at(&bytes, layout, 2, 2).expect("in bounds");
        assert_eq!(&px[..3], &[c.b, c.g, c.r], "{tier:?} panel fill");
        let bottom = pixel_at(&bytes, layout, 2, PANEL_SIZE.height - 3).expect("in bounds");
        assert_eq!(&bottom[..3], &[c.b, c.g, c.r]);
    }
}

#[test]
fn accent_toggle_recolours_the_pointer_marker() {
    let mut app = app(QualityTier::Q0);
    let l = *app.layout();
    let p = center(l.pad);
    app.pointer_motion(p);
    let cyan = paint_full(&app);
    click(&mut app, center(l.toggle));
    app.pointer_motion(p);
    let magenta = paint_full(&app);
    let marker = l.mark_rect(app.style(), p, crate::layout::MARKER_SIZE);
    assert_ne!(region(&cyan, marker), region(&magenta, marker));
}
