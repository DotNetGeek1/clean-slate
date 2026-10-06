//! Window management (#115): window state, z-order, focus, hit targets, interactive move and
//! resize, server-side decorations and the software cursor.
//!
//! The compositor owns mechanism: surface tables, damage, composition and presentation. This
//! module owns behaviour. Look comes only from a [`WindowPolicy`]: placement, the #116
//! [`ChromeStyle`] whose metrics define every decoration hit target, and the cursor image. The
//! seat routing that drives the state here lives in `compositor::routing`.
//!
//! **Authority.** Nothing a client sends names a position, a focus target or another
//! connection's object. Focus changes only on pointer presses (hit-tested here), on map of a
//! window from the focused client (or with nothing focused), and when the focused window goes
//! away. Interactive move/resize starts from a decoration press, or from `BeginMove` /
//! `BeginResize` carrying the serial of a still-held press on that same window.
//!
//! **Repaint.** Moving a window only changes its scene origin; the client is not asked to
//! repaint. Resizing sends `Configure` with the new size. Focus changes damage only the chrome
//! strips around the two affected windows.

use clean_slate_graphics::geometry::{Point, Rect, Size};
use clean_slate_graphics::limits::{MAX_SURFACE_EXTENT, MAX_WINDOWS};
use clean_slate_graphics::role::{Layer, SurfaceRole};
use clean_slate_graphics::window::ResizeEdges;
use clean_slate_raster::Canvas;
use clean_slate_ui::chrome::{ChromeControl, ChromeStyle, CleanSlateChrome};
use clean_slate_ui::cursor;
use clean_slate_ui::shell::{ShellConfig, ShellZones};
use clean_slate_ui::{QualityTier, Style, Theme, CLEAN_SLATE_DARK};

use crate::compose;
use crate::scene::SurfaceKey;

/// Facts available when a surface maps for the first time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlaceRequest {
    pub key: SurfaceKey,
    pub role: SurfaceRole,
    pub layer: Layer,
    pub size: Size,
    pub output: Size,
    /// Global origin of a popup's parent, if it is placed.
    pub parent_origin: Option<Point>,
}

/// Placement and look consulted by the compositor core. Behaviour (focus, stacking, hit
/// testing, gestures) never depends on the implementation beyond these answers.
pub trait WindowPolicy {
    /// Global origin of a surface's content on its first map.
    fn place(&mut self, request: PlaceRequest) -> Point;

    /// Server-side decoration style for toplevels; `None` leaves them undecorated.
    fn chrome(&self) -> Option<&dyn ChromeStyle> {
        None
    }

    /// Screen rect of the software cursor with its hotspot at `hotspot`; `None` disables the
    /// cursor layer.
    fn cursor_rect(&self, _hotspot: Point) -> Option<Rect> {
        None
    }

    /// Paints the cursor; `canvas` is already clipped to the damage being repainted.
    fn paint_cursor(&self, _canvas: &mut Canvas<'_>, _hotspot: Point) {}

    /// Shows the cursor at the output centre from start-up rather than on first pointer input.
    fn cursor_at_start(&self) -> bool {
        false
    }
}

/// Cascade step between successive toplevels.
pub const CASCADE_STEP: i32 = 32;
/// Cascade wraps after this many steps.
pub const CASCADE_WRAP: u32 = 8;
/// Pixels of a moved frame that stay on the output (horizontally and below the top edge).
pub const MIN_VISIBLE: u32 = 32;

/// The Clean-Slate desktop policy: #116 chrome and cursor, toplevels cascaded inside the shell
/// window area (right of the rail), popups at their parent's origin, shell surfaces at the
/// output origin.
#[derive(Clone, Copy)]
pub struct DefaultPolicy {
    chrome: CleanSlateChrome<'static>,
    shell: ShellConfig,
    placed_toplevels: u32,
}

impl DefaultPolicy {
    /// [`CLEAN_SLATE_DARK`] at [`QualityTier::M10_MAX`] with the M10 shell zones.
    pub const fn new() -> Self {
        Self::with_theme(&CLEAN_SLATE_DARK, QualityTier::M10_MAX, ShellConfig::M10)
    }

    pub const fn with_theme(theme: &'static Theme, tier: QualityTier, shell: ShellConfig) -> Self {
        Self {
            chrome: CleanSlateChrome::new(Style::new(theme, tier)),
            shell,
            placed_toplevels: 0,
        }
    }

    pub fn theme(&self) -> &'static Theme {
        self.chrome.style.theme
    }
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl WindowPolicy for DefaultPolicy {
    fn place(&mut self, request: PlaceRequest) -> Point {
        match request.role {
            SurfaceRole::Toplevel => {
                let step = self.placed_toplevels % CASCADE_WRAP;
                self.placed_toplevels = self.placed_toplevels.wrapping_add(1);
                let area =
                    ShellZones::compute(self.theme(), request.output, self.shell).window_area();
                cascade(&self.chrome, area, request.size, step)
            }
            SurfaceRole::Popup => request.parent_origin.unwrap_or(Point { x: 0, y: 0 }),
            _ => Point { x: 0, y: 0 },
        }
    }

    fn chrome(&self) -> Option<&dyn ChromeStyle> {
        Some(&self.chrome)
    }

    fn cursor_rect(&self, hotspot: Point) -> Option<Rect> {
        Some(cursor::cursor_rect(&cursor::ARROW, hotspot))
    }

    fn paint_cursor(&self, canvas: &mut Canvas<'_>, hotspot: Point) {
        cursor::paint_cursor(canvas, self.theme(), &cursor::ARROW, hotspot);
    }

    fn cursor_at_start(&self) -> bool {
        true
    }
}

/// Content origin for the `step`th cascaded toplevel of `size` inside `area`: the frame starts
/// one cascade step in from the area corner per step and is pulled back inside the area when
/// it would overhang (never above or left of the area).
pub fn cascade(chrome: &dyn ChromeStyle, area: Rect, size: Size, step: u32) -> Point {
    let content = Rect {
        x: 0,
        y: 0,
        width: size.width,
        height: size.height,
    };
    let frame = chrome.frame_rect(content);
    let inset = i64::from(CASCADE_STEP) * (i64::from(step) + 1);
    let fit = |start: i32, extent: u32, frame_extent: u32| -> i64 {
        let start = i64::from(start);
        let latest = start + i64::from(extent) - i64::from(frame_extent);
        (start + inset).min(latest).max(start)
    };
    let frame_x = fit(area.x, area.width, frame.width);
    let frame_y = fit(area.y, area.height, frame.height);
    Point {
        x: to_i32(frame_x - i64::from(frame.x)),
        y: to_i32(frame_y - i64::from(frame.y)),
    }
}

/// What a pointer position means for one window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    /// The surface's input region, at `local` surface coordinates.
    Content { local: Point },
    /// The title bar outside the controls: press to move.
    TitleBar,
    /// A window control: press and release on it to act.
    Control(ChromeControl),
    /// Border or outer resize margin: press to resize along these edges.
    Resize(ResizeEdges),
}

/// The topmost window-manager target under the pointer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WmHit {
    pub key: SurfaceKey,
    pub target: Target,
}

/// `true` iff the half-open `rect` contains `point`.
pub fn contains(rect: Rect, point: Point) -> bool {
    compose::contains(
        rect,
        Rect {
            x: point.x,
            y: point.y,
            width: 1,
            height: 1,
        },
    )
}

/// Decoration target at `point` for a toplevel whose content is at `content`. Content points
/// are never decoration (an input region that refuses them lets the pointer fall through).
pub fn decoration_target(chrome: &dyn ChromeStyle, content: Rect, point: Point) -> Option<Target> {
    if contains(content, point) {
        return None;
    }
    let frame = chrome.frame_rect(content);
    if !contains(chrome.resize_rect(frame), point) {
        return None;
    }
    for control in ChromeControl::ALL {
        if contains(chrome.control_rect(frame, control), point) {
            return Some(Target::Control(control));
        }
    }
    if contains(chrome.title_bar_rect(frame), point) {
        return Some(Target::TitleBar);
    }
    resize_edges(chrome, frame, point).map(Target::Resize)
}

/// Edges grabbed at `point` in the border or outer margin of `frame`. Within a corner band
/// (twice border plus margin) along an edge, the adjacent edge is grabbed too.
pub fn resize_edges(chrome: &dyn ChromeStyle, frame: Rect, point: Point) -> Option<ResizeEdges> {
    let m = chrome.metrics();
    let border = i64::from(m.border_width.max(1));
    let corner = 2 * (border + i64::from(m.resize_margin));
    let (px, py) = (i64::from(point.x), i64::from(point.y));
    let (left, top) = (i64::from(frame.x), i64::from(frame.y));
    let (right, bottom) = (left + i64::from(frame.width), top + i64::from(frame.height));
    let horizontal = |band: i64| {
        if px < left + band {
            ResizeEdges::LEFT
        } else if px >= right - band {
            ResizeEdges::RIGHT
        } else {
            0
        }
    };
    let vertical = |band: i64| {
        if py < top + band {
            ResizeEdges::TOP
        } else if py >= bottom - band {
            ResizeEdges::BOTTOM
        } else {
            0
        }
    };
    let (h, v) = (horizontal(border), vertical(border));
    let edges = match (h, v) {
        (0, 0) => 0,
        (0, v) => v | horizontal(corner),
        (h, 0) => h | vertical(corner),
        (h, v) => h | v,
    };
    ResizeEdges::from_u8(edges)
}

/// Content origin after moving a frame so that its top-left lands at `desired` (content
/// coordinates, i64 so pointer deltas cannot overflow). At least [`MIN_VISIBLE`] pixels of the
/// frame stay on the output horizontally, the title bar never goes above the output, and the
/// frame top stays [`MIN_VISIBLE`] pixels above the bottom edge.
pub fn constrain_move(
    frame_offset: Point,
    frame_size: Size,
    desired: (i64, i64),
    output: Size,
) -> Point {
    let keep_x = i64::from(MIN_VISIBLE.min(frame_size.width.max(1)));
    let keep_y = i64::from(MIN_VISIBLE.min(frame_size.height.max(1)));
    let frame_x = desired.0 + i64::from(frame_offset.x);
    let frame_y = desired.1 + i64::from(frame_offset.y);
    let x = frame_x
        .min(i64::from(output.width) - keep_x)
        .max(keep_x - i64::from(frame_size.width));
    let y = frame_y.min(i64::from(output.height) - keep_y).max(0);
    Point {
        x: to_i32(x - i64::from(frame_offset.x)),
        y: to_i32(y - i64::from(frame_offset.y)),
    }
}

/// Client limits as an inclusive range: `0` means unbounded; never 0 or above the protocol
/// extent; a min above the max yields the max.
fn axis_range(min: u32, max: u32, bound: u32) -> (u32, u32) {
    let mut hi = MAX_SURFACE_EXTENT;
    for limit in [max, bound] {
        if limit != 0 {
            hi = hi.min(limit);
        }
    }
    let hi = hi.max(1);
    (min.clamp(1, hi), hi)
}

/// Content size for a resize of `start` along `edges` by pointer delta `(dx, dy)`, clamped to
/// the window's size limits and the output bounds.
pub fn resize_size(
    start: Size,
    edges: u8,
    delta: (i64, i64),
    min: Size,
    max: Size,
    bounds: Size,
) -> Size {
    let axis = |start: u32, grow: i64, min: u32, max: u32, bound: u32| -> u32 {
        let (lo, hi) = axis_range(min, max, bound);
        (i64::from(start) + grow).clamp(i64::from(lo), i64::from(hi)) as u32
    };
    let grow_x = if edges & ResizeEdges::RIGHT != 0 {
        delta.0
    } else if edges & ResizeEdges::LEFT != 0 {
        -delta.0
    } else {
        0
    };
    let grow_y = if edges & ResizeEdges::BOTTOM != 0 {
        delta.1
    } else if edges & ResizeEdges::TOP != 0 {
        -delta.1
    } else {
        0
    };
    let width = if grow_x == 0 && edges & (ResizeEdges::LEFT | ResizeEdges::RIGHT) == 0 {
        start.width
    } else {
        axis(start.width, grow_x, min.width, max.width, bounds.width)
    };
    let height = if grow_y == 0 && edges & (ResizeEdges::TOP | ResizeEdges::BOTTOM) == 0 {
        start.height
    } else {
        axis(start.height, grow_y, min.height, max.height, bounds.height)
    };
    Size { width, height }
}

/// The four strips of `visual` outside `content` (top, bottom, left, right): the only pixels a
/// focus change repaints.
pub fn chrome_strips(visual: Rect, content: Rect) -> [Rect; 4] {
    let (vx, vy) = (i64::from(visual.x), i64::from(visual.y));
    let (vr, vb) = (vx + i64::from(visual.width), vy + i64::from(visual.height));
    let (cx, cy) = (
        i64::from(content.x).clamp(vx, vr),
        i64::from(content.y).clamp(vy, vb),
    );
    let (cr, cb) = (
        (i64::from(content.x) + i64::from(content.width)).clamp(cx, vr),
        (i64::from(content.y) + i64::from(content.height)).clamp(cy, vb),
    );
    let strip = |x0: i64, y0: i64, x1: i64, y1: i64| Rect {
        x: to_i32(x0),
        y: to_i32(y0),
        width: (x1 - x0).max(0) as u32,
        height: (y1 - y0).max(0) as u32,
    };
    [
        strip(vx, vy, vr, cy),
        strip(vx, cb, vr, vb),
        strip(vx, cy, cx, cb),
        strip(cr, cy, vr, cb),
    ]
}

pub(crate) fn to_i32(v: i64) -> i32 {
    v.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Which interactive operation is in progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrabKind {
    Move,
    Resize { edges: u8 },
}

/// A move or resize gesture: the pointer is captured by the window manager until every button
/// is released.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Grab {
    pub key: SurfaceKey,
    pub kind: GrabKind,
    /// Pointer position at the press.
    pub pointer: Point,
    /// Content rect at the press.
    pub content: Rect,
    pub min: Size,
    pub max: Size,
    /// Last size sent in a resize `Configure`.
    pub requested: Option<Size>,
}

/// Keeps the right and/or bottom content edge fixed while a left/top resize lands: the client
/// commits the new size later, and the origin is derived from it then.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Anchor {
    pub key: SurfaceKey,
    pub edges: u8,
    /// Content right and bottom at the press.
    pub far: (i64, i64),
    /// The size the gesture last requested; reaching it after release retires the anchor.
    pub target: Size,
}

impl Anchor {
    /// Content origin for a committed `size` given the current `origin`.
    pub fn origin_for(&self, origin: Point, size: Size) -> Point {
        let mut at = origin;
        if self.edges & ResizeEdges::LEFT != 0 {
            at.x = to_i32(self.far.0 - i64::from(size.width));
        }
        if self.edges & ResizeEdges::TOP != 0 {
            at.y = to_i32(self.far.1 - i64::from(size.height));
        }
        at
    }
}

/// The compositor-owned software cursor (layer `Cursor`, above trusted overlays).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cursor {
    pub position: Point,
    pub visible: bool,
    /// Where it was last placed (and damaged); `None` while hidden.
    pub shown: Option<Rect>,
}

/// Window-manager state. Every reference is a generation-safe [`SurfaceKey`] and is dropped by
/// `Compositor::wm_refresh` as soon as the surface stops being visible or its client goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wm {
    /// Toplevel surface with keyboard focus (`ACTIVATED`).
    pub focus: Option<SurfaceKey>,
    /// Surface that last received `PointerEnter`.
    pub pointer_focus: Option<SurfaceKey>,
    /// Surface receiving every pointer event while a button pressed on it is held.
    pub capture: Option<SurfaceKey>,
    pub grab: Option<Grab>,
    pub anchor: Option<Anchor>,
    /// Window control pressed and not yet released.
    pub control_press: Option<(SurfaceKey, ChromeControl)>,
    /// Window control under the pointer.
    pub hover: Option<(SurfaceKey, ChromeControl)>,
    /// Visible toplevels already seen mapped, so a map is acted on once.
    pub mapped: [Option<SurfaceKey>; MAX_WINDOWS],
    pub cursor: Cursor,
}

impl Wm {
    pub const fn new() -> Self {
        Self {
            focus: None,
            pointer_focus: None,
            capture: None,
            grab: None,
            anchor: None,
            control_press: None,
            hover: None,
            mapped: [None; MAX_WINDOWS],
            cursor: Cursor {
                position: Point { x: 0, y: 0 },
                visible: false,
                shown: None,
            },
        }
    }

    pub fn is_mapped(&self, key: SurfaceKey) -> bool {
        self.mapped.contains(&Some(key))
    }

    /// Records a map; `false` (state unchanged) if the set is full, which the global window
    /// budget rules out.
    pub(crate) fn note_mapped(&mut self, key: SurfaceKey) -> bool {
        if self.is_mapped(key) {
            return true;
        }
        match self.mapped.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(key);
                true
            }
            None => false,
        }
    }
}

impl Default for Wm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::ConnectionId;

    fn rect(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    fn chrome() -> CleanSlateChrome<'static> {
        CleanSlateChrome::new(Style::new(&CLEAN_SLATE_DARK, QualityTier::Q1))
    }

    /// Hit targets come from the #116 metrics: controls, title bar, border and outer margin.
    #[test]
    fn decoration_targets_follow_clean_slate_metrics() {
        let chrome = chrome();
        let m = CLEAN_SLATE_DARK.chrome;
        let content = rect(300, 200, 400, 300);
        let frame = chrome.frame_rect(content);
        for control in ChromeControl::ALL {
            let r = chrome.control_rect(frame, control);
            let centre = Point {
                x: r.x + (r.width / 2) as i32,
                y: r.y + (r.height / 2) as i32,
            };
            assert_eq!(
                decoration_target(&chrome, content, centre),
                Some(Target::Control(control))
            );
        }
        let bar = chrome.title_bar_rect(frame);
        assert_eq!(
            decoration_target(
                &chrome,
                content,
                Point {
                    x: bar.x + 40,
                    y: bar.y + 4
                }
            ),
            Some(Target::TitleBar)
        );
        assert_eq!(
            decoration_target(&chrome, content, Point { x: 400, y: 300 }),
            None
        );
        let mid_y = content.y + 100;
        let margin = m.resize_margin as i32;
        assert_eq!(
            decoration_target(
                &chrome,
                content,
                Point {
                    x: frame.x - margin,
                    y: mid_y
                }
            ),
            Some(Target::Resize(
                ResizeEdges::from_u8(ResizeEdges::LEFT).unwrap()
            ))
        );
        assert_eq!(
            decoration_target(
                &chrome,
                content,
                Point {
                    x: frame.x - margin - 1,
                    y: mid_y
                }
            ),
            None,
            "outside the resize margin"
        );
        let right = frame.x + frame.width as i32;
        let bottom = frame.y + frame.height as i32;
        assert_eq!(
            decoration_target(
                &chrome,
                content,
                Point {
                    x: right + 2,
                    y: bottom + 2
                }
            ),
            Some(Target::Resize(
                ResizeEdges::from_u8(ResizeEdges::RIGHT | ResizeEdges::BOTTOM).unwrap()
            ))
        );
        assert_eq!(
            decoration_target(
                &chrome,
                content,
                Point {
                    x: frame.x + 100,
                    y: frame.y - 1
                }
            ),
            Some(Target::Resize(
                ResizeEdges::from_u8(ResizeEdges::TOP).unwrap()
            ))
        );
        assert_eq!(
            decoration_target(
                &chrome,
                content,
                Point {
                    x: frame.x + 3,
                    y: frame.y - 2
                }
            ),
            Some(Target::Resize(
                ResizeEdges::from_u8(ResizeEdges::TOP | ResizeEdges::LEFT).unwrap()
            ))
        );
    }

    #[test]
    fn cascade_keeps_frames_inside_the_window_area() {
        let chrome = chrome();
        let theme = &CLEAN_SLATE_DARK;
        let output = Size {
            width: 1280,
            height: 800,
        };
        let area = ShellZones::compute(theme, output, ShellConfig::M10).window_area();
        let size = Size {
            width: 480,
            height: 320,
        };
        for step in 0..CASCADE_WRAP {
            let at = cascade(&chrome, area, size, step);
            let frame = chrome.frame_rect(rect(at.x, at.y, size.width, size.height));
            assert!(
                frame.x >= area.x && frame.y >= area.y,
                "{frame:?} in {area:?}"
            );
            assert!(frame.x + frame.width as i32 <= area.x + area.width as i32);
            assert!(frame.y + frame.height as i32 <= area.y + area.height as i32);
        }
        // A window larger than the area is pinned to its top-left corner.
        let huge = Size {
            width: 4096,
            height: 4096,
        };
        let at = cascade(&chrome, area, huge, 3);
        let frame = chrome.frame_rect(rect(at.x, at.y, huge.width, huge.height));
        assert_eq!((frame.x, frame.y), (area.x, area.y));
    }

    #[test]
    fn move_is_clamped_without_overflow() {
        let output = Size {
            width: 640,
            height: 480,
        };
        let offset = Point { x: -1, y: -33 };
        let size = Size {
            width: 202,
            height: 134,
        };
        assert_eq!(
            constrain_move(offset, size, (100, 100), output),
            Point { x: 100, y: 100 }
        );
        for desired in [
            (i64::MIN / 2, i64::MIN / 2),
            (i64::MAX / 2, i64::MAX / 2),
            (i64::from(i32::MAX), i64::from(i32::MIN)),
        ] {
            let at = constrain_move(offset, size, desired, output);
            let frame_x = i64::from(at.x) + i64::from(offset.x);
            let frame_y = i64::from(at.y) + i64::from(offset.y);
            assert!(frame_x + i64::from(size.width) >= i64::from(MIN_VISIBLE));
            assert!(frame_x <= i64::from(output.width - MIN_VISIBLE));
            assert!((0..=i64::from(output.height - MIN_VISIBLE)).contains(&frame_y));
        }
    }

    #[test]
    fn resize_respects_limits_bounds_and_extent() {
        let start = Size {
            width: 100,
            height: 80,
        };
        let none = Size {
            width: 0,
            height: 0,
        };
        let bounds = Size {
            width: 640,
            height: 480,
        };
        let right_bottom = ResizeEdges::RIGHT | ResizeEdges::BOTTOM;
        assert_eq!(
            resize_size(start, right_bottom, (20, -30), none, none, bounds),
            Size {
                width: 120,
                height: 50
            }
        );
        assert_eq!(
            resize_size(start, ResizeEdges::LEFT, (20, 999), none, none, bounds),
            Size {
                width: 80,
                height: 80
            },
            "left edge shrinks on a rightward drag; height untouched"
        );
        assert_eq!(
            resize_size(
                start,
                right_bottom,
                (i64::MAX / 4, i64::MIN / 4),
                none,
                none,
                bounds
            ),
            Size {
                width: 640,
                height: 1
            }
        );
        let min = Size {
            width: 50,
            height: 60,
        };
        let max = Size {
            width: 150,
            height: 70,
        };
        assert_eq!(
            resize_size(start, right_bottom, (-500, 500), min, max, bounds),
            Size {
                width: 50,
                height: 70
            }
        );
        let inverted = Size {
            width: 200,
            height: 200,
        };
        assert_eq!(
            resize_size(start, right_bottom, (0, 0), inverted, max, none).width,
            150,
            "a min above the max yields the max"
        );
    }

    #[test]
    fn chrome_strips_partition_visual_minus_content() {
        let visual = rect(10, 10, 100, 80);
        let content = rect(12, 40, 96, 48);
        let strips = chrome_strips(visual, content);
        let area: u64 = strips
            .iter()
            .map(|r| u64::from(r.width) * u64::from(r.height))
            .sum();
        assert_eq!(area, 100 * 80 - 96 * 48);
        for s in strips {
            assert_eq!(s.intersect(content).unwrap(), None);
        }
    }

    #[test]
    fn mapped_set_is_bounded() {
        let mut wm = Wm::new();
        let key = |slot: u16| SurfaceKey {
            connection: ConnectionId::new(slot, 1).unwrap(),
            surface: clean_slate_graphics::ids::SurfaceId(
                clean_slate_graphics::ids::ObjectId::new(0, 1).unwrap(),
            ),
        };
        for slot in 0..MAX_WINDOWS as u16 {
            assert!(wm.note_mapped(key(slot)));
        }
        assert!(wm.note_mapped(key(0)), "already present");
        assert!(!wm.note_mapped(key(MAX_WINDOWS as u16)));
    }
}
