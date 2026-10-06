//! First desktop shell: zones, surface plan, wallpaper, left rail and rail interaction.
//!
//! The shell is an ordinary compositor client (`desktop-shell/`, integration with #112/#115).
//! This module is everything that does not need the compositor: it decides zone geometry,
//! which surfaces and buffers the shell needs, paints each surface into a client-owned buffer,
//! and turns rail input into bounded damage. Nothing here animates or redraws on a timer.
//!
//! Coordinates: the background surface covers the output, so its buffer coordinates equal
//! output coordinates. The rail surface sits at the output origin, so rail-local coordinates
//! also equal output coordinates within the rail.

use clean_slate_graphics::pixel::PixelFormat;
use clean_slate_graphics::{Point, Rect, Size, SurfaceRole};
use clean_slate_raster::Canvas;

use crate::icon::{paint_icon, Icon};
use crate::layout::{offset, Flow, Insets, RectExt};
use crate::paint::{fill, fill_rounded, stroke_rounded, Corners};
use crate::quality::{QualityTier, Style};
use crate::surface::Damage;
use crate::tokens::{Rgba, TextTone, Theme};
use crate::widgets::{Card, RailItem, SearchField, Text, WidgetState};

/// Optional zones. The left rail and workspace are always present; there is no dock zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellConfig {
    /// Static global-search placeholder at the top of the workspace column.
    pub search_placeholder: bool,
    /// Static contextual stack on the right.
    pub context_placeholder: bool,
}

impl ShellConfig {
    /// M10 shell: both placeholders shown.
    pub const M10: Self = Self {
        search_placeholder: true,
        context_placeholder: true,
    };
    /// Rail and workspace only.
    pub const MINIMAL: Self = Self {
        search_placeholder: false,
        context_placeholder: false,
    };
}

/// Shell zone geometry in output coordinates.
///
/// ```text
/// ┌───────┬──────────────────────────────┬─────────┐
/// │       │ search (optional)            │         │
/// │ rail  ├──────────────────────────────┤ context │
/// │       │ workspace                    │ (opt.)  │
/// └───────┴──────────────────────────────┴─────────┘
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellZones {
    /// Whole output.
    pub output: Rect,
    /// Persistent left rail (full height).
    pub rail: Rect,
    /// Global-search band.
    pub search: Option<Rect>,
    /// Central workspace / content region; extends to the bottom edge (no dock).
    pub workspace: Rect,
    /// Right contextual stack.
    pub context: Option<Rect>,
}

impl ShellZones {
    /// Zones for an output of `size`.
    pub fn compute(theme: &Theme, size: Size, config: ShellConfig) -> Self {
        let m = theme.shell;
        let output = Rect {
            x: 0,
            y: 0,
            width: size.width,
            height: size.height,
        };
        let (rail, rest) = output.split_left(m.rail_width);
        let (column, context) = if config.context_placeholder {
            let (column, context) = rest.split_right(m.context_width);
            (column, Some(context))
        } else {
            (rest, None)
        };
        let (search, workspace) = if config.search_placeholder {
            let (band, workspace) = column.split_top(m.search_band_height);
            (Some(band), workspace)
        } else {
            (None, column)
        };
        Self {
            output,
            rail,
            search,
            workspace,
            context,
        }
    }

    /// Area the window manager should keep toplevels inside: the column between rail and
    /// context stack (windows may cover the search band).
    pub fn window_area(&self) -> Rect {
        match self.search {
            Some(band) => Rect {
                y: band.y,
                height: band.height + self.workspace.height,
                ..self.workspace
            },
            None => self.workspace,
        }
    }

    /// The search field inside the search band.
    pub fn search_field(&self, theme: &Theme) -> Option<Rect> {
        let m = theme.shell;
        self.search.map(|band| {
            band.centered(Size {
                width: m.search_field_width,
                height: m.search_field_height,
            })
        })
    }
}

/// What a shell surface is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellSurfaceKind {
    /// Wallpaper, workspace panel and static placeholders (`Background` layer).
    Background,
    /// Persistent left rail (`ShellFurniture` layer, above windows).
    Rail,
}

/// One surface the shell creates, with its buffer needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellSurface {
    /// Purpose.
    pub kind: ShellSurfaceKind,
    /// Role requested with `AssignRole` (both need the root `GFX_SHELL` grant).
    pub role: SurfaceRole,
    /// Placement and size in output coordinates.
    pub rect: Rect,
    /// Buffer pixel format.
    pub format: PixelFormat,
    /// Buffers to register: 1 for static content, 2 for content that changes with input.
    pub buffers: u32,
}

/// Rail destinations, top group.
pub const RAIL_PRIMARY: [RailEntry; 5] = [
    RailEntry {
        icon: Icon::Home,
        label: "Home",
    },
    RailEntry {
        icon: Icon::Apps,
        label: "Apps",
    },
    RailEntry {
        icon: Icon::Spaces,
        label: "Spaces",
    },
    RailEntry {
        icon: Icon::Files,
        label: "Files",
    },
    RailEntry {
        icon: Icon::System,
        label: "System",
    },
];

/// Rail destinations anchored to the bottom.
pub const RAIL_SECONDARY: [RailEntry; 1] = [RailEntry {
    icon: Icon::Settings,
    label: "Settings",
}];

/// Total rail items (indices `0..RAIL_ITEMS`: primary first, then secondary).
pub const RAIL_ITEMS: usize = RAIL_PRIMARY.len() + RAIL_SECONDARY.len();

/// A rail destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RailEntry {
    /// Icon.
    pub icon: Icon,
    /// Caption.
    pub label: &'static str,
}

/// Rail entry `index` (primary first).
pub fn rail_entry(index: usize) -> Option<RailEntry> {
    if index < RAIL_PRIMARY.len() {
        Some(RAIL_PRIMARY[index])
    } else {
        RAIL_SECONDARY.get(index - RAIL_PRIMARY.len()).copied()
    }
}

/// Rail item geometry in rail-local coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RailLayout {
    /// Whole rail.
    pub bounds: Rect,
    /// Brand mark block.
    pub brand: Rect,
    /// Item slots.
    pub items: [Rect; RAIL_ITEMS],
}

impl RailLayout {
    /// Layout for a rail of `bounds`.
    pub fn compute(theme: &Theme, bounds: Rect) -> Self {
        let m = theme.shell;
        let (brand, rest) = bounds.split_top(m.rail_brand_height);
        let mut items = [Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; RAIL_ITEMS];
        let mut top = Flow::column(rest, m.rail_item_gap);
        for slot in items.iter_mut().take(RAIL_PRIMARY.len()) {
            *slot = top.next(m.rail_item_height);
        }
        let secondary_h = RAIL_SECONDARY.len() as u32 * (m.rail_item_height + m.rail_item_gap);
        let bottom_pad = theme.spacing.lg;
        let remaining = top.remaining();
        let anchored = remaining.inset(Insets {
            top: remaining
                .height
                .saturating_sub(secondary_h + bottom_pad)
                .max(m.rail_item_gap),
            bottom: bottom_pad,
            ..Insets::default()
        });
        let mut bottom = Flow::column(anchored, m.rail_item_gap);
        for slot in items.iter_mut().skip(RAIL_PRIMARY.len()) {
            *slot = bottom.next(m.rail_item_height);
        }
        Self {
            bounds,
            brand,
            items,
        }
    }

    /// Item under `p`.
    pub fn hit(&self, p: Point) -> Option<usize> {
        self.items
            .iter()
            .position(|r| !r.is_empty() && r.contains(p))
    }

    /// Slot of item `index`.
    pub fn item(&self, index: usize) -> Option<Rect> {
        self.items.get(index).copied()
    }
}

/// Rail input in rail-surface-local coordinates, as the compositor delivers it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RailInput {
    /// Pointer moved to a point inside the rail surface.
    PointerMotion(Point),
    /// Pointer left the rail surface.
    PointerLeave,
    /// Primary button changed.
    PointerButton {
        /// True on press, false on release.
        pressed: bool,
    },
    /// Keyboard focus to the next item (wraps).
    FocusNext,
    /// Keyboard focus to the previous item (wraps).
    FocusPrevious,
    /// Activate the focused item.
    Activate,
}

/// Rail interaction state. The selected destination persists; hover/press/focus are transient.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RailState {
    /// Current destination.
    pub selected: usize,
    /// Item under the pointer.
    pub hovered: Option<usize>,
    /// Item held by the pointer.
    pub pressed: Option<usize>,
    /// Item with keyboard focus.
    pub focused: Option<usize>,
}

/// Result of one [`RailState::apply`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RailUpdate {
    /// Rail-local damage to repaint and commit; empty when nothing visible changed.
    pub damage: Damage,
    /// Destination activated by this input.
    pub activated: Option<usize>,
}

impl RailState {
    /// Widget state of item `index`.
    pub fn widget_state(&self, index: usize) -> WidgetState {
        let hovered = self.hovered == Some(index);
        WidgetState {
            hovered,
            pressed: hovered && self.pressed == Some(index),
            focused: self.focused == Some(index),
            disabled: false,
        }
    }

    /// Applies `input`; damage covers exactly the items whose appearance changed.
    pub fn apply(&mut self, layout: &RailLayout, input: RailInput) -> RailUpdate {
        let before = *self;
        let mut activated = None;
        match input {
            RailInput::PointerMotion(p) => self.hovered = layout.hit(p),
            RailInput::PointerLeave => {
                self.hovered = None;
                self.pressed = None;
            }
            RailInput::PointerButton { pressed: true } => self.pressed = self.hovered,
            RailInput::PointerButton { pressed: false } => {
                if let (Some(p), Some(h)) = (self.pressed, self.hovered) {
                    if p == h {
                        activated = Some(p);
                    }
                }
                self.pressed = None;
            }
            RailInput::FocusNext => {
                self.focused = Some(self.focused.map_or(0, |i| (i + 1) % RAIL_ITEMS));
            }
            RailInput::FocusPrevious => {
                self.focused = Some(
                    self.focused
                        .map_or(RAIL_ITEMS - 1, |i| (i + RAIL_ITEMS - 1) % RAIL_ITEMS),
                );
            }
            RailInput::Activate => activated = self.focused,
        }
        if let Some(index) = activated {
            self.selected = index;
        }
        let mut damage = Damage::new();
        for index in 0..RAIL_ITEMS {
            let changed = before.widget_state(index) != self.widget_state(index)
                || (before.selected == index) != (self.selected == index);
            if changed {
                if let Some(r) = layout.item(index) {
                    damage.add(r);
                }
            }
        }
        RailUpdate { damage, activated }
    }
}

/// Wallpaper colour of row `y` for an output `height` rows tall: a three-stop vertical
/// gradient with a one-pixel accent line on the horizon row. Row-constant, so it is cheap to
/// paint and easy to probe.
pub fn wallpaper_color(theme: &Theme, height: u32, y: u32) -> Rgba {
    let p = &theme.palette;
    let horizon = height * 5 / 8;
    if y == horizon {
        p.wallpaper_horizon_line
    } else if y < horizon {
        lerp(p.wallpaper_top, p.wallpaper_horizon, y, horizon)
    } else {
        lerp(
            p.wallpaper_horizon,
            p.wallpaper_bottom,
            y - horizon,
            height - horizon,
        )
    }
}

fn lerp(a: Rgba, b: Rgba, num: u32, den: u32) -> Rgba {
    if den == 0 {
        return a;
    }
    let ch = |x: u8, y: u8| {
        let x = i64::from(x);
        let y = i64::from(y);
        (x + (y - x) * i64::from(num) / i64::from(den)) as u8
    };
    Rgba::rgb(ch(a.r, b.r), ch(a.g, b.g), ch(a.b, b.b))
}

/// The desktop shell model: configuration, zones, rail layout and rail state.
#[derive(Clone, Copy)]
pub struct Shell<'t> {
    style: Style<'t>,
    tier: QualityTier,
    config: ShellConfig,
    zones: ShellZones,
    rail: RailLayout,
    state: RailState,
}

impl<'t> Shell<'t> {
    /// Shell for an output of `size` at `tier` (clamped to the M10 maximum).
    pub fn new(theme: &'t Theme, tier: QualityTier, size: Size, config: ShellConfig) -> Self {
        let tier = tier.clamp_m10();
        let zones = ShellZones::compute(theme, size, config);
        let rail = RailLayout::compute(
            theme,
            Rect {
                x: 0,
                y: 0,
                ..zones.rail
            },
        );
        Self {
            style: Style::new(theme, tier),
            tier,
            config,
            zones,
            rail,
            state: RailState::default(),
        }
    }

    /// Style in force.
    pub fn style(&self) -> Style<'t> {
        self.style
    }

    /// Effective tier.
    pub fn tier(&self) -> QualityTier {
        self.tier
    }

    /// Zone configuration.
    pub fn config(&self) -> ShellConfig {
        self.config
    }

    /// Zones.
    pub fn zones(&self) -> &ShellZones {
        &self.zones
    }

    /// Rail layout (rail-local).
    pub fn rail_layout(&self) -> &RailLayout {
        &self.rail
    }

    /// Rail state.
    pub fn rail_state(&self) -> &RailState {
        &self.state
    }

    /// Surfaces the shell creates. Total buffers stay within the theme budget.
    pub fn surfaces(&self) -> [ShellSurface; 2] {
        [
            ShellSurface {
                kind: ShellSurfaceKind::Background,
                role: SurfaceRole::Background,
                rect: self.zones.output,
                format: PixelFormat::Xrgb8888,
                buffers: 1,
            },
            ShellSurface {
                kind: ShellSurfaceKind::Rail,
                role: SurfaceRole::ShellPanel,
                rect: self.zones.rail,
                format: self.tier.translucent_surface_format(),
                buffers: 2,
            },
        ]
    }

    /// Feeds rail input; repaint [`RailUpdate::damage`] with [`Self::paint_rail`].
    pub fn handle_rail_input(&mut self, input: RailInput) -> RailUpdate {
        self.state.apply(&self.rail, input)
    }

    /// Paints the background surface (output coordinates) within the canvas clip.
    pub fn paint_background(&self, canvas: &mut Canvas<'_>) {
        let style = self.style;
        let t = style.theme;
        paint_wallpaper(canvas, t, self.zones.output.height);
        if let Some(field) = self.zones.search_field(t) {
            SearchField {
                placeholder: "Search",
            }
            .paint(canvas, style, field, WidgetState::REST);
        }
        self.paint_workspace(canvas);
        if let Some(context) = self.zones.context {
            self.paint_context(canvas, context);
        }
    }

    fn paint_workspace(&self, canvas: &mut Canvas<'_>) {
        let style = self.style;
        let t = style.theme;
        let area = self.zones.workspace.shrink(t.shell.zone_padding);
        let mut col = Flow::column(area, t.spacing.sm);
        let display = Text::display("Clean-Slate");
        display.paint(canvas, style, col.next(display.measure(style).height));
        let tagline = Text::body("A calm, focused desktop, built from a clean slate.");
        tagline.paint(canvas, style, col.next(tagline.measure(style).height));
        col.skip(t.spacing.lg);
        let panel = col.next(176);
        let panel = Rect {
            width: panel.width.min(560),
            ..panel
        };
        let card = Card::titled("Workspace");
        let content = card.paint(canvas, style, panel, WidgetState::REST);
        let mut inner = Flow::column(content, t.spacing.xs);
        for line in [
            Text::body("Windows open and float here."),
            Text::body("The rail on the left stays put; there is no dock."),
            Text::caption("M10 preview - software composition"),
        ] {
            line.paint(canvas, style, inner.next(line.measure(style).height));
        }
    }

    fn paint_context(&self, canvas: &mut Canvas<'_>, context: Rect) {
        let style = self.style;
        let t = style.theme;
        let area = context.inset(Insets {
            top: t.spacing.xl,
            right: t.spacing.xl,
            bottom: t.spacing.xl,
            left: 0,
        });
        let mut col = Flow::column(area, t.spacing.md);
        let today = Card::titled("Today");
        let content = today.paint(canvas, style, col.next(104), WidgetState::REST);
        let mut inner = Flow::column(content, t.spacing.xs);
        let note = Text::caption("Context modules arrive");
        note.paint(canvas, style, inner.next(note.measure(style).height));
        let later = Text::caption("in later milestones.");
        later.paint(canvas, style, inner.next(later.measure(style).height));

        let system = Card::titled("System");
        let content = system.paint(canvas, style, col.next(104), WidgetState::REST);
        let mut inner = Flow::column(content, t.spacing.xs);
        let composition = Text::body("Software composition");
        composition.paint(canvas, style, inner.next(composition.measure(style).height));
        let quality = if style.effects.translucency {
            "Quality Q1 - translucent"
        } else {
            "Quality Q0 - opaque"
        };
        let q = Text::caption(quality).with_tone(TextTone::Accent);
        q.paint(canvas, style, inner.next(q.measure(style).height));
    }

    /// Paints the rail surface (rail-local coordinates) within the canvas clip.
    pub fn paint_rail(&self, canvas: &mut Canvas<'_>) {
        let style = self.style;
        let t = style.theme;
        let p = &t.palette;
        let bounds = self.rail.bounds;
        fill(canvas, bounds, style.surface(p.rail));
        fill(
            canvas,
            Rect {
                x: bounds.right() - 1,
                width: 1,
                ..bounds
            },
            p.border_subtle,
        );
        let mark = self.rail.brand.centered(Size {
            width: 40,
            height: 40,
        });
        fill_rounded(canvas, mark, t.radius.md, Corners::ALL, p.surface_raised);
        stroke_rounded(
            canvas,
            mark,
            t.radius.md,
            Corners::ALL,
            t.stroke.focus,
            p.accent_cyan,
        );
        paint_icon(
            canvas,
            t,
            Icon::Monogram('C'),
            Point {
                x: offset(mark.x, 4),
                y: offset(mark.y, 4),
            },
            2,
            p.text_primary,
        );
        for index in 0..RAIL_ITEMS {
            let (Some(entry), Some(slot)) = (rail_entry(index), self.rail.item(index)) else {
                continue;
            };
            RailItem {
                icon: entry.icon,
                label: entry.label,
                selected: self.state.selected == index,
            }
            .paint(canvas, style, slot, self.state.widget_state(index));
        }
    }
}

fn paint_wallpaper(canvas: &mut Canvas<'_>, theme: &Theme, height: u32) {
    let clip = canvas.clip();
    if clip.is_empty() {
        return;
    }
    let first = u32::try_from(clip.y.max(0)).unwrap_or(0);
    let last = u32::try_from(clip.bottom().max(0)).unwrap_or(0).min(height);
    for y in first..last {
        fill(
            canvas,
            Rect {
                x: clip.x,
                y: y as i32,
                width: clip.width,
                height: 1,
            },
            wallpaper_color(theme, height, y),
        );
    }
}
