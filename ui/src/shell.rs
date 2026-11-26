//! First desktop shell: zones, surface plan, wallpaper, the app rail and rail interaction.
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
use crate::layout::{offset, Flow, RectExt};
use crate::paint::{fill, fill_rounded, stroke_rounded, Corners};
use crate::quality::{QualityTier, Style};
use crate::surface::Damage;
use crate::tokens::{Rgba, Theme};
use crate::widgets::{RailItem, Text, WidgetState};

/// Optional zones. The left rail and workspace are always present; there is no dock zone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShellConfig {
    /// Static global-search placeholder at the top of the workspace column.
    pub search_placeholder: bool,
    /// Static contextual stack on the right.
    pub context_placeholder: bool,
}

impl ShellConfig {
    /// M10 shell: rail and workspace. The search and context placeholders are gone until
    /// there is live data for them (#237).
    pub const M10: Self = Self {
        search_placeholder: false,
        context_placeholder: false,
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
    /// Wallpaper and the workspace heading (`Background` layer).
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

/// App slots on the rail: one per launchable manifest row the shell is told about (#237).
pub const RAIL_APPS: usize = 8;
/// Longest rail caption, in bytes (a launcher name is at most 32).
pub const RAIL_LABEL_BYTES: usize = 32;

/// One app on the rail: what the shell learned from init's launcher and the compositor's
/// window list. The rail paints it; the shell decides what a click on it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RailApp {
    label: [u8; RAIL_LABEL_BYTES],
    len: u8,
    /// Icon.
    pub icon: Icon,
    /// The app has a running instance (a dot marks it).
    pub running: bool,
}

impl RailApp {
    /// `label` is truncated on a character boundary at [`RAIL_LABEL_BYTES`].
    pub fn new(label: &str, icon: Icon, running: bool) -> Self {
        let mut end = label.len().min(RAIL_LABEL_BYTES);
        while end > 0 && !label.is_char_boundary(end) {
            end -= 1;
        }
        let mut bytes = [0u8; RAIL_LABEL_BYTES];
        bytes[..end].copy_from_slice(&label.as_bytes()[..end]);
        Self {
            label: bytes,
            len: end as u8,
            icon,
            running,
        }
    }

    /// Caption.
    pub fn label(&self) -> &str {
        core::str::from_utf8(&self.label[..usize::from(self.len)]).unwrap_or("")
    }
}

/// What the rail shows: the apps in slot order and which one owns the focused window.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RailApps {
    /// Apps, packed from slot 0.
    pub apps: [Option<RailApp>; RAIL_APPS],
    /// Slot whose app owns the focused window.
    pub selected: Option<usize>,
}

impl RailApps {
    /// Apps on the rail.
    pub fn len(&self) -> usize {
        self.apps.iter().flatten().count()
    }

    /// No apps.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// App in `slot`.
    pub fn get(&self, slot: usize) -> Option<&RailApp> {
        self.apps.get(slot).and_then(Option::as_ref)
    }
}

/// Rail item geometry in rail-local coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RailLayout {
    /// Whole rail.
    pub bounds: Rect,
    /// Brand mark block.
    pub brand: Rect,
    /// App slots, top to bottom.
    pub items: [Rect; RAIL_APPS],
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
        }; RAIL_APPS];
        let mut column = Flow::column(rest, m.rail_item_gap);
        for slot in &mut items {
            *slot = column.next(m.rail_item_height);
        }
        Self {
            bounds,
            brand,
            items,
        }
    }

    /// Slot under `p`, among the first `count`.
    pub fn hit(&self, p: Point, count: usize) -> Option<usize> {
        self.items
            .iter()
            .take(count)
            .position(|r| !r.is_empty() && r.contains(p))
    }

    /// Rect of slot `index`.
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

/// Transient rail interaction state. Which app is selected is not here: it follows the
/// focused window ([`RailApps::selected`]), not the last click.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RailState {
    /// Item under the pointer.
    pub hovered: Option<usize>,
    /// Item held by the pointer.
    pub pressed: Option<usize>,
    /// Item with keyboard focus.
    pub focused: Option<usize>,
}

/// Result of one [`RailState::apply`] or [`Shell::set_apps`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RailUpdate {
    /// Rail-local damage to repaint and commit; empty when nothing visible changed.
    pub damage: Damage,
    /// Slot activated by this input.
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

    /// Applies `input` over the first `count` slots; damage covers exactly the items whose
    /// appearance changed.
    pub fn apply(&mut self, layout: &RailLayout, input: RailInput, count: usize) -> RailUpdate {
        let before = *self;
        let mut activated = None;
        match input {
            RailInput::PointerMotion(p) => self.hovered = layout.hit(p, count),
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
            RailInput::FocusNext if count > 0 => {
                self.focused = Some(self.focused.map_or(0, |i| (i + 1) % count));
            }
            RailInput::FocusPrevious if count > 0 => {
                self.focused = Some(self.focused.map_or(count - 1, |i| (i + count - 1) % count));
            }
            RailInput::FocusNext | RailInput::FocusPrevious => {}
            RailInput::Activate => activated = self.focused.filter(|&i| i < count),
        }
        let mut damage = Damage::new();
        for index in 0..RAIL_APPS {
            if before.widget_state(index) != self.widget_state(index) {
                if let Some(r) = layout.item(index) {
                    damage.add(r);
                }
            }
        }
        RailUpdate { damage, activated }
    }

    /// Drops references to slots at or past `count` (apps went away).
    fn clamp(&mut self, count: usize) {
        for slot in [&mut self.hovered, &mut self.pressed, &mut self.focused] {
            if slot.is_some_and(|i| i >= count) {
                *slot = None;
            }
        }
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
    apps: RailApps,
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
            apps: RailApps::default(),
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

    /// Apps on the rail.
    pub fn apps(&self) -> &RailApps {
        &self.apps
    }

    /// Feeds rail input; repaint [`RailUpdate::damage`] with [`Self::paint_rail`].
    pub fn handle_rail_input(&mut self, input: RailInput) -> RailUpdate {
        let count = self.apps.len();
        self.state.apply(&self.rail, input, count)
    }

    /// Replaces what the rail shows; the damage covers exactly the slots that changed.
    pub fn set_apps(&mut self, apps: RailApps) -> RailUpdate {
        let before = (self.apps, self.state);
        self.apps = apps;
        self.state.clamp(apps.len());
        let mut damage = Damage::new();
        for index in 0..RAIL_APPS {
            let changed = before.0.get(index) != apps.get(index)
                || (before.0.selected == Some(index)) != (apps.selected == Some(index))
                || before.1.widget_state(index) != self.state.widget_state(index);
            if changed {
                if let Some(r) = self.rail.item(index) {
                    damage.add(r);
                }
            }
        }
        RailUpdate {
            damage,
            activated: None,
        }
    }

    /// Paints the background surface (output coordinates) within the canvas clip: the
    /// wallpaper and the workspace heading. The search band and context column, when a
    /// configuration reserves them, stay wallpaper until there is live data to show (#237).
    pub fn paint_background(&self, canvas: &mut Canvas<'_>) {
        let style = self.style;
        let t = style.theme;
        paint_wallpaper(canvas, t, self.zones.output.height);
        let area = self.zones.workspace.shrink(t.shell.zone_padding);
        let mut col = Flow::column(area, t.spacing.sm);
        let display = Text::display("Clean-Slate");
        display.paint(canvas, style, col.next(display.measure(style).height));
        let tagline = Text::body("A calm, focused desktop, built from a clean slate.");
        tagline.paint(canvas, style, col.next(tagline.measure(style).height));
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
        for index in 0..RAIL_APPS {
            let (Some(app), Some(slot)) = (self.apps.get(index), self.rail.item(index)) else {
                continue;
            };
            RailItem {
                icon: app.icon,
                label: app.label(),
                selected: self.apps.selected == Some(index),
                running: app.running,
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
