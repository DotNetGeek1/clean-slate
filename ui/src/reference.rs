//! Reference desktop for review and structural checks.
//!
//! [`render`] paints, into one 1280×800 buffer, what the composed M10 desktop is meant to
//! look like: shell background, an inactive and a focused native window with sample #117-style
//! controls, the rail above them, and the cursor. It is a host-side preview, not a compositor:
//! the integrated desktop produces the same pixels from separate surfaces via #112/#115.
//!
//! [`probes`] lists point checks with token colours. Visual acceptance compares those points
//! rather than full-frame hashes, so unrelated rendering changes do not break screenshots.

use clean_slate_graphics::mode::REFERENCE_MODE;
use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_raster::Canvas;

use crate::chrome::{ChromeControl, ChromeState, ChromeStyle, CleanSlateChrome};
use crate::cursor::{paint_cursor, ARROW};
use crate::layout::{Flow, RectExt};
use crate::paint::fill;
use crate::quality::{QualityTier, Style};
use crate::shell::{wallpaper_color, Shell, ShellConfig};
use crate::tokens::{Rgba, Theme};
use crate::widgets::{Button, Card, CardKind, Text, Toggle, WidgetState, BUTTON_HEIGHT};

/// Client area of the focused sample window.
pub const FOCUSED_CONTENT: Rect = Rect {
    x: 560,
    y: 300,
    width: 520,
    height: 360,
};

/// Client area of the inactive sample window.
pub const INACTIVE_CONTENT: Rect = Rect {
    x: 200,
    y: 360,
    width: 400,
    height: 260,
};

/// Cursor hotspot in the reference frame (over the focused window's primary button).
pub const CURSOR_HOTSPOT: Point = Point { x: 602, y: 428 };

/// Output size of the reference frame.
pub const SIZE: Size = Size {
    width: REFERENCE_MODE.width_px,
    height: REFERENCE_MODE.height_px,
};

/// A point whose colour must equal a token-derived value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Probe {
    /// What the probe proves.
    pub name: &'static str,
    /// Output coordinate.
    pub at: Point,
    /// Expected opaque colour.
    pub expected: Rgba,
}

/// Paints the reference desktop for `theme` at `tier` into a 1280×800 canvas.
pub fn render(canvas: &mut Canvas<'_>, theme: &Theme, tier: QualityTier) {
    let shell = Shell::new(theme, tier, SIZE, ShellConfig::M10);
    let style = shell.style();
    let chrome = CleanSlateChrome::new(style);
    shell.paint_background(canvas);

    window(canvas, &chrome, INACTIVE_CONTENT, "Notes", unfocused());
    paint_notes(canvas, style, INACTIVE_CONTENT);

    let focused = ChromeState {
        focused: true,
        hovered: Some(ChromeControl::Close),
        ..ChromeState::default()
    };
    window(canvas, &chrome, FOCUSED_CONTENT, "Playground", focused);
    paint_playground(canvas, style, FOCUSED_CONTENT);

    shell.paint_rail(canvas);
    paint_cursor(canvas, theme, &ARROW, CURSOR_HOTSPOT);
}

fn unfocused() -> ChromeState {
    ChromeState::default()
}

fn window(
    canvas: &mut Canvas<'_>,
    chrome: &CleanSlateChrome<'_>,
    content: Rect,
    title: &str,
    state: ChromeState,
) {
    let frame = chrome.frame_rect(content);
    chrome.paint_frame(canvas, frame, title, state);
}

/// Sample native-app content: what #117 builds from the shared primitives.
fn paint_playground(canvas: &mut Canvas<'_>, style: Style<'_>, content: Rect) {
    let t = style.theme;
    fill(canvas, content, t.palette.surface);
    let mut col = Flow::column(content.shrink(t.spacing.xl), t.spacing.md);
    let title = Text::title("Playground");
    title.paint(canvas, style, col.next(title.measure(style).height));
    let body = Text::body("Native app built from shared UI primitives.");
    body.paint(canvas, style, col.next(body.measure(style).height));
    col.skip(t.spacing.xs);

    let mut buttons = Flow::row(col.next(BUTTON_HEIGHT), t.spacing.sm);
    let run = Button::primary("Run");
    run.paint(
        canvas,
        style,
        buttons.next(run.measure(style).width),
        WidgetState::HOVERED,
    );
    let reset = Button::new("Reset");
    reset.paint(
        canvas,
        style,
        buttons.next(reset.measure(style).width),
        WidgetState::FOCUSED,
    );
    let help = Button::quiet("Help");
    help.paint(
        canvas,
        style,
        buttons.next(help.measure(style).width),
        WidgetState::REST,
    );
    let off = Button::new("Disabled");
    off.paint(
        canvas,
        style,
        buttons.next(off.measure(style).width),
        WidgetState::DISABLED,
    );
    col.skip(t.spacing.xs);

    for (on, label) in [(true, "Translucency"), (false, "Animations")] {
        let toggle = Toggle::labelled(on, label);
        let size = toggle.measure(style);
        let slot = col.next(size.height);
        toggle.paint(
            canvas,
            style,
            Rect {
                width: size.width,
                ..slot
            },
            WidgetState::REST,
        );
    }
    col.skip(t.spacing.xs);

    let inset = Card::titled("Status").with_kind(CardKind::Inset);
    let well = col.next(76);
    let inner = inset.paint(canvas, style, well, WidgetState::REST);
    Text::caption("Clicks: 3   Last key: Enter").paint(canvas, style, inner);
}

fn paint_notes(canvas: &mut Canvas<'_>, style: Style<'_>, content: Rect) {
    let t = style.theme;
    fill(canvas, content, t.palette.surface);
    let mut col = Flow::column(content.shrink(t.spacing.xl), t.spacing.sm);
    for line in [
        Text::heading("Build a calmer desktop"),
        Text::body("Left rail, no dock."),
        Text::body("Monochrome window controls."),
        Text::body("Opaque first, translucent when cheap."),
        Text::caption("Inactive window: muted title and border."),
    ] {
        line.paint(canvas, style, col.next(line.measure(style).height));
    }
}

/// Structural probes for [`render`] at `tier`.
pub fn probes(theme: &Theme, tier: QualityTier) -> [Probe; 9] {
    let style = Style::new(theme, tier);
    let p = &theme.palette;
    let h = SIZE.height;
    let rail_y = 600;
    let rail = style
        .surface(p.rail)
        .flatten_over(wallpaper_color(theme, h, rail_y as u32));
    let bar_mid = |c: Rect| Point {
        x: c.x + c.width as i32 / 2,
        y: c.y - 16,
    };
    let underline = |c: Rect| Point {
        x: c.x + c.width as i32 / 2,
        y: c.y - 1,
    };
    let left_border = |c: Rect| Point {
        x: c.x - 1,
        y: c.y + 100,
    };
    [
        Probe {
            name: "rail background",
            at: Point { x: 4, y: rail_y },
            expected: rail,
        },
        Probe {
            name: "rail edge",
            at: Point { x: 87, y: rail_y },
            expected: p.border_subtle,
        },
        Probe {
            name: "workspace reaches the bottom edge (no dock)",
            at: Point { x: 700, y: 796 },
            expected: wallpaper_color(theme, h, 796),
        },
        Probe {
            name: "focused title bar",
            at: bar_mid(FOCUSED_CONTENT),
            expected: p.chrome_active_bar,
        },
        Probe {
            name: "inactive title bar",
            at: bar_mid(INACTIVE_CONTENT),
            expected: p.chrome_inactive_bar,
        },
        Probe {
            name: "focused accent underline",
            at: underline(FOCUSED_CONTENT),
            expected: p.chrome_accent,
        },
        Probe {
            name: "focused border",
            at: left_border(FOCUSED_CONTENT),
            expected: p.chrome_active_border,
        },
        Probe {
            name: "inactive border",
            at: left_border(INACTIVE_CONTENT),
            expected: p.chrome_inactive_border,
        },
        Probe {
            name: "cursor fill",
            at: Point {
                x: CURSOR_HOTSPOT.x + 2,
                y: CURSOR_HOTSPOT.y + 5,
            },
            expected: p.cursor_fill,
        },
    ]
}
