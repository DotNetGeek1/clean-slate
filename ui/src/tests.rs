//! Crate-level tests: token validation, degradation, shell structure, damage and goldens.

use clean_slate_graphics::limits::{MAX_BUFFERS_PER_CLIENT, MAX_REGISTERED_BUFFERS};
use clean_slate_graphics::role::{validate_role, RoleGrant, GFX_CONNECT_BIT, GFX_SHELL_BIT};
use clean_slate_graphics::{BufferLayout, Layer, PixelFormat, Point, Rect};
use clean_slate_raster::{pixel_at, visible_crc32, Canvas};

use crate::chrome::{ChromeControl, ChromeState, ChromeStyle, CleanSlateChrome};
use crate::cursor::{cursor_rect, paint_cursor, ARROW};
use crate::icon::{paint_icon, Icon};
use crate::layout::RectExt;
use crate::quality::{Effects, QualityTier, Style};
use crate::reference;
use crate::shell::{wallpaper_color, RailInput, Shell, ShellConfig, ShellZones, RAIL_ITEMS};
use crate::surface::{repaint, Damage};
use crate::tokens::{Rgba, CLEAN_SLATE_DARK};
use crate::widgets::{Button, Card, CardKind, RailItem, SearchField, Text, Toggle, WidgetState};

const THEME: &crate::tokens::Theme = &CLEAN_SLATE_DARK;

fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn q0() -> Style<'static> {
    Style::new(THEME, QualityTier::Q0)
}

fn q1() -> Style<'static> {
    Style::new(THEME, QualityTier::Q1)
}

struct Buffer {
    bytes: Vec<u8>,
    layout: BufferLayout,
}

impl Buffer {
    fn new(width: u32, height: u32, format: PixelFormat, fill: [u8; 4]) -> Self {
        let layout = BufferLayout::packed(width, height, format).unwrap();
        let mut bytes = vec![0u8; layout.byte_len()];
        for px in bytes.chunks_exact_mut(4) {
            px.copy_from_slice(&fill);
        }
        Self { bytes, layout }
    }

    fn paint(&mut self, f: impl FnOnce(&mut Canvas<'_>)) -> &mut Self {
        let mut canvas = Canvas::new(&mut self.bytes, self.layout).unwrap();
        f(&mut canvas);
        self
    }

    fn px(&self, x: i32, y: i32) -> [u8; 4] {
        pixel_at(&self.bytes, self.layout, x as u32, y as u32).unwrap()
    }

    fn rgb(&self, p: Point) -> Rgba {
        let [b, g, r, _] = self.px(p.x, p.y);
        Rgba::rgb(r, g, b)
    }

    fn crc(&self) -> u32 {
        visible_crc32(&self.bytes, self.layout).unwrap()
    }

    /// Visible pixels row by row (stride padding excluded).
    fn visible(&self) -> Vec<[u8; 4]> {
        let stride = self.layout.stride_bytes() as usize;
        let row = self.layout.width() as usize * 4;
        self.bytes
            .chunks_exact(stride)
            .flat_map(|r| r[..row].chunks_exact(4).map(|p| [p[0], p[1], p[2], p[3]]))
            .collect()
    }
}

fn bg_bytes() -> [u8; 4] {
    let c = THEME.palette.background;
    [c.b, c.g, c.r, 0xFF]
}

// ---- token validation ---------------------------------------------------------------------

fn linear(c: u8) -> f64 {
    let s = f64::from(c) / 255.0;
    if s <= 0.04045 {
        s / 12.92
    } else {
        ((s + 0.055) / 1.055).powf(2.4)
    }
}

fn luminance(c: Rgba) -> f64 {
    0.2126 * linear(c.r) + 0.7152 * linear(c.g) + 0.0722 * linear(c.b)
}

/// WCAG 2.x contrast ratio.
fn contrast(a: Rgba, b: Rgba) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    let (hi, lo) = if la > lb { (la, lb) } else { (lb, la) };
    (hi + 0.05) / (lo + 0.05)
}

fn assert_contrast(name: &str, fg: Rgba, bg: Rgba, min: f64) {
    let ratio = contrast(fg, bg);
    assert!(
        ratio >= min,
        "{name}: contrast {ratio:.2} < {min} (fg {fg:?} on bg {bg:?})"
    );
}

#[test]
fn text_tokens_meet_wcag_aa_on_every_surface_they_appear_on() {
    let p = &THEME.palette;
    let all_surfaces = [
        ("background", p.background),
        ("surface", p.surface),
        ("surface_raised", p.surface_raised),
        ("surface_sunken", p.surface_sunken),
        ("card", p.card.opaque),
        ("rail", p.rail.opaque),
        ("rail_hover", p.rail_hover),
        ("control", p.control),
        ("control_hover", p.control_hover),
        ("control_pressed", p.control_pressed),
        ("wallpaper_top", p.wallpaper_top),
        ("wallpaper_horizon", p.wallpaper_horizon),
        ("wallpaper_bottom", p.wallpaper_bottom),
    ];
    for (name, bg) in all_surfaces {
        assert_contrast(name, p.text_primary, bg, 4.5);
        assert_contrast(name, p.text_secondary, bg, 4.5);
    }
    for (name, bg) in [
        ("background", p.background),
        ("surface", p.surface),
        ("surface_raised", p.surface_raised),
        ("surface_sunken", p.surface_sunken),
        ("card", p.card.opaque),
        ("rail", p.rail.opaque),
        ("rail_hover", p.rail_hover),
        ("wallpaper_top", p.wallpaper_top),
        ("wallpaper_horizon", p.wallpaper_horizon),
        ("wallpaper_bottom", p.wallpaper_bottom),
    ] {
        assert_contrast(name, p.text_muted, bg, 4.5);
    }
    for bg in [p.accent_cyan, p.primary_hover, p.primary_pressed] {
        assert_contrast("on accent", p.text_on_accent, bg, 4.5);
    }
    assert_contrast(
        "active title",
        p.chrome_active_title,
        p.chrome_active_bar,
        4.5,
    );
    assert_contrast(
        "inactive title",
        p.chrome_inactive_title,
        p.chrome_inactive_bar,
        4.5,
    );
    for bg in [p.chrome_control_hover, p.chrome_control_pressed] {
        assert_contrast("hovered control", p.chrome_active_title, bg, 4.5);
    }
    assert_contrast("accent caption", p.accent_cyan, p.card.opaque, 4.5);
}

#[test]
fn non_text_tokens_meet_wcag_3_to_1() {
    let p = &THEME.palette;
    for bg in [
        p.surface,
        p.control,
        p.background,
        p.surface_sunken,
        p.rail.opaque,
    ] {
        assert_contrast("focus ring", p.focus_ring, bg, 3.0);
    }
    assert_contrast("selected rail icon", p.accent_cyan, p.surface_raised, 3.0);
    assert_contrast("toggle on track", p.accent_cyan, p.surface, 3.0);
    assert_contrast("toggle on knob", p.text_on_accent, p.accent_cyan, 3.0);
    assert_contrast("toggle off knob", p.text_secondary, p.surface_sunken, 3.0);
    assert_contrast(
        "active control glyph",
        p.chrome_control_active,
        p.chrome_active_bar,
        3.0,
    );
    assert_contrast(
        "inactive control glyph",
        p.chrome_control_inactive,
        p.chrome_inactive_bar,
        3.0,
    );
    assert_contrast("focus underline", p.chrome_accent, p.chrome_active_bar, 3.0);
    assert_contrast("cursor", p.cursor_fill, p.cursor_outline, 7.0);
    assert_contrast("disabled text", p.text_disabled, p.surface, 2.0);
}

#[test]
fn focused_and_inactive_chrome_tokens_are_ordered() {
    let p = &THEME.palette;
    assert_ne!(p.chrome_active_bar, p.chrome_inactive_bar);
    assert!(
        contrast(p.chrome_active_border, p.background)
            > contrast(p.chrome_inactive_border, p.background)
    );
    assert!(
        contrast(p.chrome_active_title, p.chrome_active_bar)
            > contrast(p.chrome_inactive_title, p.chrome_inactive_bar)
    );
}

#[test]
fn opaque_fallbacks_and_text_tones_are_opaque() {
    let p = &THEME.palette;
    for fill in [p.card, p.rail] {
        assert!(fill.opaque.is_opaque());
        assert!(!fill.translucent.is_opaque());
    }
    use crate::tokens::TextTone::*;
    for tone in [Primary, Secondary, Muted, Disabled, OnAccent, Accent] {
        assert!(p.tone(tone).is_opaque(), "{tone:?}");
    }
}

#[test]
fn spacing_radius_and_metrics_sit_on_the_grid() {
    let s = THEME.spacing;
    for v in [s.xs, s.sm, s.md, s.lg, s.xl, s.xxl] {
        assert_eq!(v % s.unit, 0);
    }
    assert!(THEME.radius.sm < THEME.radius.md && THEME.radius.md < THEME.radius.lg);
    let m = THEME.shell;
    for v in [
        m.rail_width,
        m.rail_brand_height,
        m.rail_item_height,
        m.search_band_height,
        m.context_width,
        m.zone_padding,
    ] {
        assert_eq!(v % s.unit, 0, "{v}");
    }
    let c = THEME.chrome;
    assert!(c.control_size < c.title_bar_height);
    assert!(c.corner_radius > c.border_width);
}

// ---- quality tiers ------------------------------------------------------------------------

#[test]
fn tiers_clamp_to_q1_and_never_enable_blur_or_animation() {
    assert_eq!(QualityTier::Q3.clamp_m10(), QualityTier::Q1);
    assert_eq!(QualityTier::Q2.clamp_m10(), QualityTier::Q1);
    assert_eq!(THEME.budget.max_tier, QualityTier::M10_MAX);
    assert_eq!(Effects::for_tier(QualityTier::Q0), Effects::OPAQUE);
    for tier in [
        QualityTier::Q0,
        QualityTier::Q1,
        QualityTier::Q2,
        QualityTier::Q3,
    ] {
        let e = Effects::for_tier(tier);
        assert!(!e.blur && !e.animation, "{tier:?}");
    }
    assert_eq!(
        QualityTier::Q0.translucent_surface_format(),
        PixelFormat::Xrgb8888
    );
    assert_eq!(
        QualityTier::Q3.translucent_surface_format(),
        PixelFormat::Argb8888Premultiplied
    );
}

// ---- shell structure ----------------------------------------------------------------------

#[test]
fn zones_have_a_full_height_left_rail_and_no_bottom_zone() {
    for config in [ShellConfig::M10, ShellConfig::MINIMAL] {
        let z = ShellZones::compute(THEME, reference::SIZE, config);
        assert_eq!(z.rail, rect(0, 0, THEME.shell.rail_width, 800));
        assert_eq!(z.workspace.x, z.rail.right());
        assert_eq!(
            z.workspace.bottom(),
            z.output.bottom(),
            "no dock below the workspace"
        );
        let context_bottom = z.context.map_or(800, |c| c.bottom());
        assert_eq!(context_bottom, 800);
        let used: u64 = [Some(z.rail), z.search, Some(z.workspace), z.context]
            .iter()
            .flatten()
            .map(|r| r.area())
            .sum();
        assert_eq!(used, z.output.area(), "zones tile the output exactly");
        let area = z.window_area();
        assert!(area.x >= z.rail.right());
        assert_eq!(area.bottom(), 800);
    }
    let z = ShellZones::compute(THEME, reference::SIZE, ShellConfig::MINIMAL);
    assert!(z.search.is_none() && z.context.is_none());
    assert_eq!(z.workspace, rect(88, 0, 1280 - 88, 800));
}

#[test]
fn shell_surfaces_fit_the_buffer_budget_and_need_the_shell_grant() {
    let shell = Shell::new(THEME, QualityTier::Q1, reference::SIZE, ShellConfig::M10);
    let surfaces = shell.surfaces();
    let buffers: u32 = surfaces.iter().map(|s| s.buffers).sum();
    assert_eq!(buffers, THEME.budget.shell_buffers);
    assert!(buffers as usize <= MAX_BUFFERS_PER_CLIENT);
    assert!(
        MAX_REGISTERED_BUFFERS - buffers as usize >= MAX_BUFFERS_PER_CLIENT,
        "a full app budget remains alongside the shell"
    );
    let shell_grant = RoleGrant::from_rights_bits(GFX_CONNECT_BIT | GFX_SHELL_BIT);
    let app_grant = RoleGrant::from_rights_bits(GFX_CONNECT_BIT);
    let layers: Vec<_> = surfaces
        .iter()
        .map(|s| validate_role(s.role, shell_grant).unwrap())
        .collect();
    assert_eq!(layers, vec![Layer::Background, Layer::ShellFurniture]);
    for s in surfaces {
        assert!(validate_role(s.role, app_grant).is_err());
    }
    let q0 = Shell::new(THEME, QualityTier::Q0, reference::SIZE, ShellConfig::M10);
    assert!(q0
        .surfaces()
        .iter()
        .all(|s| s.format == PixelFormat::Xrgb8888));
}

fn paint_shell_surfaces(tier: QualityTier, prefill: [u8; 4]) -> (Buffer, Buffer) {
    let shell = Shell::new(THEME, tier, reference::SIZE, ShellConfig::M10);
    let [bg, rail] = shell.surfaces();
    let mut background = Buffer::new(bg.rect.width, bg.rect.height, bg.format, prefill);
    background.paint(|c| shell.paint_background(c));
    let mut rail_buf = Buffer::new(rail.rect.width, rail.rect.height, rail.format, prefill);
    rail_buf.paint(|c| shell.paint_rail(c));
    (background, rail_buf)
}

#[test]
fn shell_surfaces_cover_every_pixel_regardless_of_prior_contents() {
    for tier in [QualityTier::Q0, QualityTier::Q1] {
        let (bg_a, rail_a) = paint_shell_surfaces(tier, [0x00, 0x00, 0x00, 0x00]);
        let (bg_b, rail_b) = paint_shell_surfaces(tier, [0xA5, 0x5A, 0xFF, 0xFF]);
        assert!(
            bg_a.visible() == bg_b.visible(),
            "background depends on prior contents ({tier:?})"
        );
        assert!(
            rail_a.visible() == rail_b.visible(),
            "rail depends on prior contents ({tier:?})"
        );
    }
}

#[test]
fn q0_is_fully_opaque_and_q1_rail_carries_restrained_alpha() {
    let (bg, rail) = paint_shell_surfaces(QualityTier::Q0, [0; 4]);
    assert!(bg.visible().iter().all(|p| p[3] == 0xFF));
    assert!(rail.visible().iter().all(|p| p[3] == 0xFF));

    let (_, rail) = paint_shell_surfaces(QualityTier::Q1, [0; 4]);
    assert_eq!(rail.layout.format(), PixelFormat::Argb8888Premultiplied);
    let alpha = rail.px(4, 600)[3];
    assert_eq!(alpha, THEME.palette.rail.translucent.a);
    assert!(alpha >= 0xB0, "translucency stays restrained");
    for p in rail.visible() {
        assert!(
            p[0] <= p[3] && p[1] <= p[3] && p[2] <= p[3],
            "premultiplied invariant"
        );
    }
}

#[test]
fn reference_probes_hold_at_every_tier_and_with_effects_disabled() {
    for tier in [
        QualityTier::Q0,
        QualityTier::Q1,
        QualityTier::Q2,
        QualityTier::Q3,
    ] {
        let mut frame = Buffer::new(1280, 800, PixelFormat::Xrgb8888, [0; 4]);
        frame.paint(|c| reference::render(c, THEME, tier));
        for probe in reference::probes(THEME, tier) {
            assert_eq!(
                frame.rgb(probe.at),
                probe.expected,
                "{} at {:?} ({tier:?})",
                probe.name,
                probe.at
            );
        }
    }
}

#[test]
fn no_dock_bottom_band_is_pure_wallpaper_outside_windows() {
    let mut frame = Buffer::new(1280, 800, PixelFormat::Xrgb8888, [0; 4]);
    frame.paint(|c| reference::render(c, THEME, QualityTier::Q1));
    let zones = ShellZones::compute(THEME, reference::SIZE, ShellConfig::M10);
    let rail_right = zones.rail.right();
    for y in 720..800 {
        let expected = wallpaper_color(THEME, 800, y as u32);
        let context = zones.context.unwrap();
        for x in rail_right..context.x {
            assert_eq!(frame.rgb(Point { x, y }), expected, "({x},{y})");
        }
    }
}

// ---- rail interaction and damage ----------------------------------------------------------

#[test]
fn rail_input_damages_only_changed_items_within_budget() {
    let mut shell = Shell::new(THEME, QualityTier::Q0, reference::SIZE, ShellConfig::M10);
    let layout = *shell.rail_layout();
    let centre = |i: usize| {
        let r = layout.item(i).unwrap();
        Point {
            x: r.x + r.width as i32 / 2,
            y: r.y + r.height as i32 / 2,
        }
    };
    let check_budget = |d: &Damage| {
        assert!(d.rects().len() as u32 <= THEME.budget.max_damage_rects_per_update);
        assert!(d.area() <= u64::from(THEME.budget.max_damage_area_per_update));
    };

    let u = shell.handle_rail_input(RailInput::PointerMotion(centre(1)));
    assert_eq!(u.damage.rects(), &[layout.item(1).unwrap()]);
    check_budget(&u.damage);

    let same = shell.handle_rail_input(RailInput::PointerMotion(centre(1)));
    assert!(same.damage.is_empty(), "no visible change, no repaint");

    let u = shell.handle_rail_input(RailInput::PointerMotion(centre(2)));
    assert_eq!(
        u.damage.rects(),
        &[layout.item(1).unwrap(), layout.item(2).unwrap()]
    );
    check_budget(&u.damage);

    shell.handle_rail_input(RailInput::PointerButton { pressed: true });
    let u = shell.handle_rail_input(RailInput::PointerButton { pressed: false });
    assert_eq!(u.activated, Some(2));
    assert_eq!(shell.rail_state().selected, 2);
    check_budget(&u.damage);

    shell.handle_rail_input(RailInput::PointerButton { pressed: true });
    shell.handle_rail_input(RailInput::PointerMotion(centre(3)));
    let u = shell.handle_rail_input(RailInput::PointerButton { pressed: false });
    assert_eq!(u.activated, None, "release off the pressed item cancels");

    let u = shell.handle_rail_input(RailInput::PointerLeave);
    assert_eq!(shell.rail_state().hovered, None);
    check_budget(&u.damage);

    let u = shell.handle_rail_input(RailInput::PointerMotion(Point { x: 4, y: 600 }));
    assert!(u.damage.is_empty(), "gap between groups is not an item");
}

#[test]
fn rail_keyboard_focus_wraps_and_activates() {
    let mut shell = Shell::new(THEME, QualityTier::Q0, reference::SIZE, ShellConfig::M10);
    shell.handle_rail_input(RailInput::FocusPrevious);
    assert_eq!(shell.rail_state().focused, Some(RAIL_ITEMS - 1));
    shell.handle_rail_input(RailInput::FocusNext);
    assert_eq!(shell.rail_state().focused, Some(0));
    shell.handle_rail_input(RailInput::FocusNext);
    let u = shell.handle_rail_input(RailInput::Activate);
    assert_eq!(u.activated, Some(1));
    assert_eq!(shell.rail_state().selected, 1);
}

#[test]
fn damage_repaint_matches_a_full_repaint_and_touches_nothing_else() {
    for tier in [QualityTier::Q0, QualityTier::Q1] {
        let mut shell = Shell::new(THEME, tier, reference::SIZE, ShellConfig::M10);
        let [_, rail] = shell.surfaces();
        let mut incremental = Buffer::new(rail.rect.width, rail.rect.height, rail.format, [0; 4]);
        incremental.paint(|c| shell.paint_rail(c));
        let before = incremental.bytes.clone();

        let item = shell.rail_layout().item(3).unwrap();
        let update = shell.handle_rail_input(RailInput::PointerMotion(Point {
            x: item.x + 20,
            y: item.y + 20,
        }));
        assert!(!update.damage.is_empty());
        incremental.paint(|c| repaint(c, &update.damage, |c| shell.paint_rail(c)));

        let mut full = Buffer::new(rail.rect.width, rail.rect.height, rail.format, [0; 4]);
        full.paint(|c| shell.paint_rail(c));
        assert!(incremental.visible() == full.visible(), "{tier:?}");

        for y in 0..rail.rect.height as i32 {
            for x in 0..rail.rect.width as i32 {
                if !item.contains(Point { x, y }) {
                    let o = (y as u32 * incremental.layout.stride_bytes() + x as u32 * 4) as usize;
                    assert_eq!(before[o..o + 4], incremental.bytes[o..o + 4], "({x},{y})");
                }
            }
        }
    }
}

// ---- primitives ---------------------------------------------------------------------------

/// Paints into `bounds` inside a larger sentinel buffer and checks nothing outside changed.
fn assert_contained(name: &str, area: Rect, paint: impl FnOnce(&mut Canvas<'_>, Rect)) {
    const SENTINEL: [u8; 4] = [0x5A, 0xA5, 0x3C, 0xFF];
    let bounds = rect(16, 16, area.width, area.height);
    let mut buf = Buffer::new(
        area.width + 32,
        area.height + 32,
        PixelFormat::Xrgb8888,
        SENTINEL,
    );
    buf.paint(|c| paint(c, bounds));
    let mut touched = false;
    for y in 0..buf.layout.height() as i32 {
        for x in 0..buf.layout.width() as i32 {
            let inside = bounds.contains(Point { x, y });
            let changed = buf.px(x, y) != SENTINEL;
            assert!(
                inside || !changed,
                "{name} painted outside its bounds at ({x},{y})"
            );
            touched |= changed;
        }
    }
    assert!(touched, "{name} painted nothing");
}

#[test]
fn widgets_paint_only_inside_their_bounds() {
    let states = [
        WidgetState::REST,
        WidgetState::HOVERED,
        WidgetState::PRESSED,
        WidgetState::FOCUSED,
        WidgetState::DISABLED,
    ];
    for style in [q0(), q1()] {
        for state in states {
            assert_contained("button", rect(0, 0, 96, 32), |c, b| {
                Button::primary("A very long label").paint(c, style, b, state)
            });
            assert_contained("toggle", rect(0, 0, 100, 28), |c, b| {
                Toggle::labelled(true, "Overflowing label").paint(c, style, b, state)
            });
            assert_contained("card", rect(0, 0, 120, 80), |c, b| {
                Card::titled("A title that does not fit").paint(c, style, b, state);
            });
            assert_contained("rail item", rect(0, 0, 88, 60), |c, b| {
                RailItem {
                    icon: Icon::Settings,
                    label: "Settings and more",
                    selected: true,
                }
                .paint(c, style, b, state)
            });
            assert_contained("search", rect(0, 0, 160, 40), |c, b| {
                SearchField {
                    placeholder: "Search everything at once",
                }
                .paint(c, style, b, state)
            });
        }
        assert_contained("text", rect(0, 0, 50, 48), |c, b| {
            Text::display("Clean-Slate").paint(c, style, b)
        });
    }
}

#[test]
fn widget_states_are_visually_distinct() {
    let render = |paint: &dyn Fn(&mut Canvas<'_>)| {
        let mut buf = Buffer::new(160, 40, PixelFormat::Xrgb8888, bg_bytes());
        buf.paint(paint);
        buf.crc()
    };
    let states = [
        WidgetState::REST,
        WidgetState::HOVERED,
        WidgetState::PRESSED,
        WidgetState::FOCUSED,
        WidgetState::DISABLED,
    ];
    for button in [
        Button::primary("Run"),
        Button::new("Reset"),
        Button::quiet("Help"),
    ] {
        let crcs: Vec<u32> = states
            .iter()
            .map(|&s| render(&|c| button.paint(c, q0(), rect(0, 4, 120, 32), s)))
            .collect();
        for i in 0..crcs.len() {
            for j in i + 1..crcs.len() {
                assert_ne!(
                    crcs[i], crcs[j],
                    "{:?}: {:?} vs {:?}",
                    button.kind, states[i], states[j]
                );
            }
        }
    }
    let on = render(&|c| Toggle::new(true).paint(c, q0(), rect(0, 0, 60, 40), WidgetState::REST));
    let off = render(&|c| Toggle::new(false).paint(c, q0(), rect(0, 0, 60, 40), WidgetState::REST));
    assert_ne!(on, off);
}

#[test]
fn chrome_focus_is_distinct_and_controls_are_monochrome() {
    for style in [q0(), q1()] {
        let chrome = CleanSlateChrome::new(style);
        let content = rect(40, 60, 300, 160);
        let frame = chrome.frame_rect(content);
        let render = |state: ChromeState| {
            let mut buf = Buffer::new(400, 280, PixelFormat::Xrgb8888, bg_bytes());
            buf.paint(|c| chrome.paint_frame(c, frame, "Playground", state));
            buf
        };
        let focused = render(ChromeState {
            focused: true,
            ..ChromeState::default()
        });
        let inactive = render(ChromeState::default());
        assert_ne!(focused.crc(), inactive.crc());

        let hovered = render(ChromeState {
            focused: true,
            hovered: Some(ChromeControl::Close),
            ..ChromeState::default()
        });
        for buf in [&focused, &inactive, &hovered] {
            for control in ChromeControl::ALL {
                let r = chrome.control_rect(frame, control);
                for y in r.y..r.bottom() {
                    for x in r.x..r.right() {
                        let c = buf.rgb(Point { x, y });
                        let hi = c.r.max(c.g).max(c.b);
                        let lo = c.r.min(c.g).min(c.b);
                        assert!(hi - lo <= 0x20, "{control:?} pixel {c:?} is not monochrome");
                    }
                }
            }
        }

        let visual = chrome.visual_rect(frame);
        for buf in [&focused, &inactive] {
            for y in 0..280 {
                for x in 0..400 {
                    let p = Point { x, y };
                    if !visual.contains(p) || content.contains(p) {
                        assert_eq!(buf.px(x, y), bg_bytes(), "chrome touched ({x},{y})");
                    }
                }
            }
        }
    }
}

#[test]
fn long_titles_stop_before_the_controls() {
    let chrome = CleanSlateChrome::new(q0());
    let frame = rect(0, 0, 200, 120);
    let mut buf = Buffer::new(200, 120, PixelFormat::Xrgb8888, bg_bytes());
    buf.paint(|c| {
        chrome.paint_frame(
            c,
            frame,
            "An extremely long window title that overflows",
            ChromeState {
                focused: true,
                ..ChromeState::default()
            },
        )
    });
    let minimize = chrome.control_rect(frame, ChromeControl::Minimize);
    let bar = THEME.palette.chrome_active_bar;
    let gap_x = minimize.x - 4;
    for y in minimize.y..minimize.bottom() {
        assert_eq!(buf.rgb(Point { x: gap_x, y }), bar);
    }
}

#[test]
fn cursor_rect_bounds_every_cursor_pixel() {
    let hotspot = Point { x: 10, y: 6 };
    let mut buf = Buffer::new(40, 40, PixelFormat::Xrgb8888, bg_bytes());
    buf.paint(|c| paint_cursor(c, THEME, &ARROW, hotspot));
    let bounds = cursor_rect(&ARROW, hotspot);
    for y in 0..40 {
        for x in 0..40 {
            if !bounds.contains(Point { x, y }) {
                assert_eq!(buf.px(x, y), bg_bytes());
            }
        }
    }
    assert_eq!(buf.rgb(hotspot), THEME.palette.cursor_outline);
}

// ---- goldens ------------------------------------------------------------------------------

type Case = (
    &'static str,
    u32,
    u32,
    PixelFormat,
    Box<dyn Fn(&mut Canvas<'_>)>,
);

fn golden_cases() -> Vec<Case> {
    let x = PixelFormat::Xrgb8888;
    let a = PixelFormat::Argb8888Premultiplied;
    let b = |w: u32, h: u32| rect(0, 0, w, h);
    let mut cases: Vec<Case> = Vec::new();
    for (name, state) in [
        ("button.primary.rest", WidgetState::REST),
        ("button.primary.hover", WidgetState::HOVERED),
        ("button.primary.pressed", WidgetState::PRESSED),
        ("button.primary.focused", WidgetState::FOCUSED),
        ("button.primary.disabled", WidgetState::DISABLED),
    ] {
        cases.push((
            name,
            120,
            32,
            x,
            Box::new(move |c| Button::primary("Run").paint(c, q0(), b(120, 32), state)),
        ));
    }
    cases.push((
        "button.secondary.icon",
        120,
        32,
        x,
        Box::new(move |c| {
            Button::new("Files").with_icon(Icon::Files).paint(
                c,
                q0(),
                b(120, 32),
                WidgetState::REST,
            )
        }),
    ));
    cases.push((
        "button.quiet.hover",
        120,
        32,
        x,
        Box::new(move |c| Button::quiet("Help").paint(c, q0(), b(120, 32), WidgetState::HOVERED)),
    ));
    cases.push((
        "toggle.on",
        160,
        28,
        x,
        Box::new(move |c| {
            Toggle::labelled(true, "Wi-Fi").paint(c, q0(), b(160, 28), WidgetState::REST)
        }),
    ));
    cases.push((
        "toggle.off.focused",
        160,
        28,
        x,
        Box::new(move |c| {
            Toggle::labelled(false, "Wi-Fi").paint(c, q0(), b(160, 28), WidgetState::FOCUSED)
        }),
    ));
    cases.push((
        "card.titled.q0",
        200,
        120,
        x,
        Box::new(move |c| {
            Card::titled("Today").paint(c, q0(), b(200, 120), WidgetState::REST);
        }),
    ));
    cases.push((
        "card.titled.q1",
        200,
        120,
        x,
        Box::new(move |c| {
            Card::titled("Today").paint(c, q1(), b(200, 120), WidgetState::REST);
        }),
    ));
    cases.push((
        "card.inset.selected",
        200,
        80,
        x,
        Box::new(move |c| {
            Card {
                selected: true,
                ..Card::new().with_kind(CardKind::Inset)
            }
            .paint(c, q0(), b(200, 80), WidgetState::REST);
        }),
    ));
    cases.push((
        "text.scale",
        240,
        120,
        x,
        Box::new(move |c| {
            Text::display("Aa").paint(c, q0(), b(240, 56));
            Text::title("Title").paint(c, q0(), rect(0, 56, 240, 38));
            Text::heading("Heading").paint(c, q0(), rect(0, 94, 120, 22));
            Text::caption("Caption").paint(c, q0(), rect(120, 94, 120, 22));
        }),
    ));
    for (name, state, selected) in [
        ("rail.item.rest", WidgetState::REST, false),
        ("rail.item.hover", WidgetState::HOVERED, false),
        ("rail.item.selected", WidgetState::REST, true),
        ("rail.item.focused", WidgetState::FOCUSED, false),
    ] {
        cases.push((
            name,
            88,
            60,
            x,
            Box::new(move |c| {
                RailItem {
                    icon: Icon::Home,
                    label: "Home",
                    selected,
                }
                .paint(c, q0(), b(88, 60), state)
            }),
        ));
    }
    for (name, style, focused) in [
        ("chrome.focused.q0", q0(), true),
        ("chrome.inactive.q0", q0(), false),
        ("chrome.focused.q1", q1(), true),
    ] {
        cases.push((
            name,
            320,
            200,
            x,
            Box::new(move |c| {
                CleanSlateChrome::new(style).paint_frame(
                    c,
                    rect(10, 10, 300, 170),
                    "Playground",
                    ChromeState {
                        focused,
                        hovered: Some(ChromeControl::Maximize),
                        ..ChromeState::default()
                    },
                )
            }),
        ));
    }
    cases.push((
        "cursor.arrow",
        16,
        20,
        x,
        Box::new(move |c| paint_cursor(c, THEME, &ARROW, Point { x: 1, y: 1 })),
    ));
    cases.push((
        "icons",
        16 * 9,
        16,
        x,
        Box::new(move |c| {
            for (i, icon) in [
                Icon::Home,
                Icon::Apps,
                Icon::Spaces,
                Icon::Files,
                Icon::System,
                Icon::Settings,
                Icon::Search,
                Icon::Placeholder,
                Icon::Monogram('n'),
            ]
            .into_iter()
            .enumerate()
            {
                paint_icon(
                    c,
                    THEME,
                    icon,
                    Point {
                        x: i as i32 * 16,
                        y: 0,
                    },
                    1,
                    THEME.palette.text_primary,
                );
            }
        }),
    ));
    cases.push((
        "search.field",
        240,
        40,
        x,
        Box::new(move |c| {
            SearchField {
                placeholder: "Search",
            }
            .paint(c, q0(), b(240, 40), WidgetState::REST)
        }),
    ));
    for (name, tier, format) in [
        ("rail.surface.q0", QualityTier::Q0, x),
        ("rail.surface.q1", QualityTier::Q1, a),
    ] {
        cases.push((
            name,
            88,
            800,
            format,
            Box::new(move |c| {
                Shell::new(THEME, tier, reference::SIZE, ShellConfig::M10).paint_rail(c)
            }),
        ));
    }
    cases
}

/// CRC-32 of each primitive's visible pixels at a fixed size. Primitive-sized on purpose:
/// full-frame hashes are never pinned (see `reference::probes`).
const GOLDENS: &[(&str, u32)] = &[
    ("button.primary.rest", 0x4E1CDE51),
    ("button.primary.hover", 0xA16DC83A),
    ("button.primary.pressed", 0x51A316E0),
    ("button.primary.focused", 0x87913006),
    ("button.primary.disabled", 0xBEF6CE6A),
    ("button.secondary.icon", 0xAF4CEA7A),
    ("button.quiet.hover", 0x61D71096),
    ("toggle.on", 0x8E6D1A3A),
    ("toggle.off.focused", 0x6AEEB88C),
    ("card.titled.q0", 0xD4B92C6A),
    ("card.titled.q1", 0xFB39DA90),
    ("card.inset.selected", 0x30483E33),
    ("text.scale", 0xC9E7909F),
    ("rail.item.rest", 0x7D4ECE7A),
    ("rail.item.hover", 0xE84CB888),
    ("rail.item.selected", 0x4DD636C3),
    ("rail.item.focused", 0x2F4A8B31),
    ("chrome.focused.q0", 0x31856294),
    ("chrome.inactive.q0", 0x8EF80909),
    ("chrome.focused.q1", 0x87695C3E),
    ("cursor.arrow", 0xE40C4E42),
    ("icons", 0x1B10B562),
    ("search.field", 0xAD241DA3),
    ("rail.surface.q0", 0x47072FB6),
    ("rail.surface.q1", 0xEC4E75A3),
];

#[test]
fn primitive_goldens() {
    let mut mismatches = Vec::new();
    for (name, w, h, format, paint) in golden_cases() {
        let mut buf = Buffer::new(w, h, format, bg_bytes());
        buf.paint(|c| paint(c));
        let crc = buf.crc();
        let expected = GOLDENS.iter().find(|(n, _)| *n == name).map(|(_, v)| *v);
        if expected != Some(crc) {
            mismatches.push(format!("    (\"{name}\", 0x{crc:08X}),"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "golden mismatches (update GOLDENS after reviewing the rendering):\n{}",
        mismatches.join("\n")
    );
}

#[test]
fn golden_case_names_are_unique() {
    let mut names: Vec<_> = golden_cases().into_iter().map(|c| c.0).collect();
    names.sort_unstable();
    let len = names.len();
    names.dedup();
    assert_eq!(names.len(), len);
}
