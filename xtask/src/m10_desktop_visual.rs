//! Structural screenshot checks for the #119 desktop lane.
//!
//! The host renders what the compositor must show for a known scene (shell wallpaper and
//! workspace, the focused window's server-side chrome, the rail over it and the cursor) with the
//! same `ui`/`compositor` code the guest runs, then compares named regions of a QMP screendump
//! against it. Client content is never rendered here: it is excluded from every comparison, and
//! the lane proves it changed by diffing two captures. Each region has its own mismatch budget,
//! so a failure names what is wrong (rail, dock band, chrome, focus) instead of a frame hash.

use clean_slate_compositor::wm::cascade;
use clean_slate_graphics::pixel::{BufferLayout, PixelFormat};
use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_playground::{PanelLayout, PANEL_SIZE, WINDOW_TITLE};
use clean_slate_raster::{BlitMode, Canvas};
use clean_slate_ui::cursor::{cursor_rect, paint_cursor, ARROW};
use clean_slate_ui::layout::RectExt;
use clean_slate_ui::{
    ChromeState, ChromeStyle, CleanSlateChrome, QualityTier, Shell, ShellConfig, Style,
    CLEAN_SLATE_DARK,
};

use crate::qmp::image::Screenshot;

/// Both desktop runs pin GOP and VirtIO-GPU to the #111 reference mode.
pub(crate) const OUTPUT: Size = Size {
    width: 1280,
    height: 800,
};

/// Rows at the bottom of the output where a dock would sit; they must show only wallpaper.
pub(crate) const DOCK_BAND_ROWS: u32 = 64;

/// What the compositor should be showing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Scene {
    pub(crate) tier: QualityTier,
    /// Content origin of the one app window, if mapped.
    pub(crate) window: Option<Point>,
    /// Pointer hotspot (the software cursor is drawn there).
    pub(crate) pointer: Point,
}

fn style(tier: QualityTier) -> Style<'static> {
    Style::new(&CLEAN_SLATE_DARK, tier)
}

fn shell(tier: QualityTier) -> Shell<'static> {
    Shell::new(&CLEAN_SLATE_DARK, tier, OUTPUT, ShellConfig::M10)
}

pub(crate) fn chrome(tier: QualityTier) -> CleanSlateChrome<'static> {
    CleanSlateChrome::new(style(tier))
}

/// The rail rect and the window area of the M10 shell zones.
pub(crate) fn rail(tier: QualityTier) -> Rect {
    shell(tier).zones().rail
}

/// Content origin of the `step`th toplevel the compositor placed since it started.
pub(crate) fn window_origin(tier: QualityTier, step: u32) -> Point {
    let area = shell(tier).zones().window_area();
    cascade(&chrome(tier), area, PANEL_SIZE, step)
}

pub(crate) fn content_rect(origin: Point) -> Rect {
    Rect {
        x: origin.x,
        y: origin.y,
        width: PANEL_SIZE.width,
        height: PANEL_SIZE.height,
    }
}

pub(crate) fn frame_rect(tier: QualityTier, origin: Point) -> Rect {
    chrome(tier).frame_rect(content_rect(origin))
}

/// Panel layout in surface-local coordinates.
pub(crate) fn panel(tier: QualityTier) -> PanelLayout {
    PanelLayout::compute(style(tier), PANEL_SIZE)
}

pub(crate) fn translate(rect: Rect, by: Point) -> Rect {
    Rect {
        x: rect.x + by.x,
        y: rect.y + by.y,
        ..rect
    }
}

pub(crate) fn center(rect: Rect) -> Point {
    Point {
        x: rect.x + (rect.width / 2) as i32,
        y: rect.y + (rect.height / 2) as i32,
    }
}

fn output_rect() -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: OUTPUT.width,
        height: OUTPUT.height,
    }
}

fn output_layout() -> BufferLayout {
    BufferLayout::packed(OUTPUT.width, OUTPUT.height, PixelFormat::Xrgb8888).expect("output")
}

/// One host render, as screendump RGB.
pub(crate) struct Render {
    rgb: Vec<u8>,
}

impl Render {
    fn pixel(&self, x: u32, y: u32) -> [u8; 3] {
        let at = (y * OUTPUT.width + x) as usize * 3;
        [self.rgb[at], self.rgb[at + 1], self.rgb[at + 2]]
    }
}

/// Which layers [`render`] paints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Layers {
    /// The shell background surface only (what any region with nothing above it shows).
    Background,
    /// Background, the window frame (`focused` as given), rail and cursor.
    Desktop { focused: bool },
}

/// Paints `scene` in compositor order: background surface, window frame, (client content left
/// as background), rail surface over it, cursor.
pub(crate) fn render(scene: &Scene, layers: Layers) -> Render {
    let shell = shell(scene.tier);
    let layout = output_layout();
    let mut bytes = vec![0u8; layout.byte_len()];
    {
        let mut canvas = Canvas::new(&mut bytes, layout).expect("output canvas");
        shell.paint_background(&mut canvas);
        if let Layers::Desktop { focused } = layers {
            if let Some(origin) = scene.window {
                let state = ChromeState {
                    focused,
                    ..ChromeState::default()
                };
                chrome(scene.tier).paint_frame(
                    &mut canvas,
                    frame_rect(scene.tier, origin),
                    WINDOW_TITLE,
                    state,
                );
            }
            let surfaces = shell.surfaces();
            let rail = surfaces[1];
            let rail_layout =
                BufferLayout::packed(rail.rect.width, rail.rect.height, rail.format).expect("rail");
            let mut rail_bytes = vec![0u8; rail_layout.byte_len()];
            shell.paint_rail(&mut Canvas::new(&mut rail_bytes, rail_layout).expect("rail canvas"));
            let mode = match rail.format {
                PixelFormat::Xrgb8888 => BlitMode::Copy,
                PixelFormat::Argb8888Premultiplied => BlitMode::Over,
            };
            let whole = Rect {
                x: 0,
                y: 0,
                width: rail.rect.width,
                height: rail.rect.height,
            };
            canvas
                .blit(
                    &rail_bytes,
                    rail_layout,
                    whole,
                    (rail.rect.x, rail.rect.y),
                    mode,
                )
                .expect("rail blit");
            paint_cursor(&mut canvas, &CLEAN_SLATE_DARK, &ARROW, scene.pointer);
        }
    }
    let rgb = bytes
        .chunks_exact(4)
        .flat_map(|bgrx| [bgrx[2], bgrx[1], bgrx[0]])
        .collect();
    Render { rgb }
}

/// [`render`]'s pixels, for tests that build synthetic captures.
#[cfg(test)]
pub(crate) fn render_rgb(scene: &Scene, layers: Layers) -> Vec<u8> {
    render(scene, layers).rgb
}

pub(crate) fn cursor(pointer: Point) -> Rect {
    cursor_rect(&ARROW, pointer)
}

/// Pixels of `region` (clipped to the output) outside every `exclude` rect.
fn pixels(region: Rect, exclude: &[Rect]) -> impl Iterator<Item = (u32, u32)> + '_ {
    let x0 = region.x.max(0) as u32;
    let y0 = region.y.max(0) as u32;
    let x1 = (region.right().max(0) as u32).min(OUTPUT.width);
    let y1 = (region.bottom().max(0) as u32).min(OUTPUT.height);
    (y0..y1)
        .flat_map(move |y| (x0..x1).map(move |x| (x, y)))
        .filter(move |&(x, y)| {
            let p = Point {
                x: x as i32,
                y: y as i32,
            };
            !exclude.iter().any(|r| r.contains(p))
        })
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct RegionDiff {
    pub(crate) compared: u64,
    pub(crate) mismatched: u64,
    pub(crate) first: Option<(u32, u32, [u8; 3], [u8; 3])>,
}

impl RegionDiff {
    /// Mismatches allowed per million compared pixels.
    fn within(&self, per_million: u64) -> bool {
        self.compared > 0 && self.mismatched * 1_000_000 <= self.compared * per_million
    }

    fn describe(&self, what: &str) -> String {
        let first = self.first.map_or(String::new(), |(x, y, got, want)| {
            format!("; first at ({x},{y}) rgb={got:02x?} expected={want:02x?}")
        });
        format!(
            "{what}: {} of {} pixels differ from the host render{first}",
            self.mismatched, self.compared
        )
    }
}

pub(crate) fn diff(
    shot: &Screenshot,
    expected: &Render,
    region: Rect,
    exclude: &[Rect],
) -> RegionDiff {
    let mut result = RegionDiff::default();
    for (x, y) in pixels(region, exclude) {
        result.compared += 1;
        let got = shot.pixel(x, y).unwrap_or([0; 3]);
        let want = expected.pixel(x, y);
        if got != want {
            result.mismatched += 1;
            result.first.get_or_insert((x, y, got, want));
        }
    }
    result
}

/// Share (per million) of `region` pixels where `shot` differs from `other`.
fn differing_per_million(shot: &Screenshot, other: &Render, region: Rect, exclude: &[Rect]) -> u64 {
    let d = diff(shot, other, region, exclude);
    if d.compared == 0 {
        0
    } else {
        d.mismatched * 1_000_000 / d.compared
    }
}

/// Everything outside client content: ≤ 0.5% may differ (a cursor or a few edge pixels).
const DESKTOP_BUDGET: u64 = 5_000;
/// The rail: ≤ 0.1% may differ (cursor only).
const RAIL_BUDGET: u64 = 1_000;
/// Title bar: ≤ 1% may differ.
const TITLE_BAR_BUDGET: u64 = 10_000;

/// Every structural check of one capture of `scene`.
pub(crate) fn check_scene(shot: &Screenshot, scene: &Scene) -> Result<(), String> {
    if (shot.width(), shot.height()) != (OUTPUT.width, OUTPUT.height) {
        return Err(format!(
            "expected a {}x{} frame, got {}x{}",
            OUTPUT.width,
            OUTPUT.height,
            shot.width(),
            shot.height()
        ));
    }
    let background = render(scene, Layers::Background);
    let focused = render(scene, Layers::Desktop { focused: true });
    let cursor = cursor(scene.pointer);
    let content = scene.window.map(content_rect);
    let no_content: Vec<Rect> = content.into_iter().collect();

    let rail = rail(scene.tier);
    let rail_diff = diff(shot, &focused, rail, &[cursor]);
    if !rail_diff.within(RAIL_BUDGET) {
        return Err(rail_diff.describe("left rail"));
    }
    if differing_per_million(shot, &background, rail, &[cursor]) < 900_000 {
        return Err("left rail is not visible: its pixels match the bare wallpaper".into());
    }

    let mut dock_exclude = vec![cursor];
    if let Some(origin) = scene.window {
        dock_exclude.push(chrome(scene.tier).visual_rect(frame_rect(scene.tier, origin)));
    }
    let dock_band = Rect {
        x: rail.right(),
        y: (OUTPUT.height - DOCK_BAND_ROWS) as i32,
        width: OUTPUT.width - rail.width,
        height: DOCK_BAND_ROWS,
    };
    let dock = diff(shot, &background, dock_band, &dock_exclude);
    if dock.mismatched != 0 {
        return Err(dock.describe("bottom band (a dock would be here)"));
    }

    if let Some(origin) = scene.window {
        let chrome = chrome(scene.tier);
        let frame = frame_rect(scene.tier, origin);
        let bar = chrome.title_bar_rect(frame);
        let bar_diff = diff(shot, &focused, bar, &[cursor]);
        if !bar_diff.within(TITLE_BAR_BUDGET) {
            return Err(bar_diff.describe("server-side title bar"));
        }
        check_focused_chrome(
            shot,
            scene,
            &focused,
            frame,
            &[cursor, content_rect(origin)],
        )?;
        let content = content_rect(origin);
        if differing_per_million(shot, &background, content, &[cursor]) < 500_000 {
            return Err(
                "client content is missing: the window interior shows the wallpaper".into(),
            );
        }
    }

    let whole = diff(shot, &focused, output_rect(), &no_content);
    if !whole.within(DESKTOP_BUDGET) {
        return Err(whole.describe("desktop outside client content"));
    }
    Ok(())
}

/// Where the focused and unfocused chrome differ, the capture must show the focused one.
fn check_focused_chrome(
    shot: &Screenshot,
    scene: &Scene,
    focused: &Render,
    frame: Rect,
    exclude: &[Rect],
) -> Result<(), String> {
    let unfocused = render(scene, Layers::Desktop { focused: false });
    let visual = chrome(scene.tier).visual_rect(frame);
    let (mut distinct, mut as_focused) = (0u64, 0u64);
    for (x, y) in pixels(visual, exclude) {
        let want = focused.pixel(x, y);
        if want == unfocused.pixel(x, y) {
            continue;
        }
        distinct += 1;
        if shot.pixel(x, y) == Some(want) {
            as_focused += 1;
        }
    }
    if distinct == 0 {
        return Err("focused and unfocused chrome render identically".into());
    }
    if as_focused * 10 < distinct * 9 {
        return Err(format!(
            "window chrome is not shown focused: {as_focused} of {distinct} focus-dependent pixels match"
        ));
    }
    Ok(())
}

/// `true` when `region` (global) differs between two captures outside `exclude`.
pub(crate) fn region_changed(
    a: &Screenshot,
    b: &Screenshot,
    region: Rect,
    exclude: &[Rect],
) -> bool {
    pixels(region, exclude).any(|(x, y)| a.pixel(x, y) != b.pixel(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shot_of(render: &Render) -> Screenshot {
        Screenshot::new(OUTPUT.width, OUTPUT.height, render.rgb.clone()).unwrap()
    }

    /// A render with client content filled in, as a passing capture would look.
    fn passing_shot(scene: &Scene) -> Screenshot {
        let mut rgb = render(scene, Layers::Desktop { focused: true }).rgb;
        if let Some(origin) = scene.window {
            let pointer = cursor(scene.pointer);
            paint_except(
                &mut rgb,
                content_rect(origin),
                &[pointer],
                [0x20, 0x24, 0x2c],
            );
        }
        Screenshot::new(OUTPUT.width, OUTPUT.height, rgb).unwrap()
    }

    fn paint(rgb: &mut [u8], rect: Rect, color: [u8; 3]) {
        paint_except(rgb, rect, &[], color);
    }

    fn paint_except(rgb: &mut [u8], rect: Rect, exclude: &[Rect], color: [u8; 3]) {
        for (x, y) in pixels(rect, exclude) {
            let at = (y * OUTPUT.width + x) as usize * 3;
            rgb[at..at + 3].copy_from_slice(&color);
        }
    }

    fn scene(tier: QualityTier) -> Scene {
        Scene {
            tier,
            window: Some(window_origin(tier, 0)),
            pointer: Point { x: 1279, y: 799 },
        }
    }

    #[test]
    fn geometry_follows_the_shell_zones_and_cascade() {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let rail = rail(tier);
            assert_eq!((rail.x, rail.width, rail.height), (0, 88, OUTPUT.height));
            let first = frame_rect(tier, window_origin(tier, 0));
            let second = frame_rect(tier, window_origin(tier, 1));
            assert!(first.x >= rail.right(), "{first:?}");
            assert_eq!((second.x - first.x, second.y - first.y), (32, 32));
            assert!(first.bottom() < (OUTPUT.height - DOCK_BAND_ROWS) as i32);
        }
    }

    #[test]
    fn a_capture_of_the_expected_desktop_passes_at_both_tiers() {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let scene = scene(tier);
            assert_eq!(
                check_scene(&passing_shot(&scene), &scene),
                Ok(()),
                "{tier:?}"
            );
            let bare = Scene {
                window: None,
                ..scene
            };
            assert_eq!(check_scene(&passing_shot(&bare), &bare), Ok(()), "{tier:?}");
        }
    }

    #[test]
    fn a_missing_rail_or_a_dock_or_missing_content_is_named() {
        let scene = scene(QualityTier::Q1);
        let background = render(&scene, Layers::Background);
        let mut no_rail = passing_shot(&scene).rgb().to_vec();
        let rail = rail(scene.tier);
        for (x, y) in pixels(rail, &[]) {
            let at = (y * OUTPUT.width + x) as usize * 3;
            no_rail[at..at + 3].copy_from_slice(&background.pixel(x, y));
        }
        let err = check_scene(&Screenshot::new(1280, 800, no_rail).unwrap(), &scene).unwrap_err();
        assert!(err.contains("rail"), "{err}");

        let mut dock = passing_shot(&scene).rgb().to_vec();
        paint(
            &mut dock,
            Rect {
                x: 400,
                y: 760,
                width: 480,
                height: 40,
            },
            [0x30, 0x30, 0x30],
        );
        let err = check_scene(&Screenshot::new(1280, 800, dock).unwrap(), &scene).unwrap_err();
        assert!(
            err.contains("bottom band") || err.contains("desktop"),
            "{err}"
        );

        let empty = shot_of(&render(&scene, Layers::Desktop { focused: true }));
        let err = check_scene(&empty, &scene).unwrap_err();
        assert!(err.contains("client content"), "{err}");
    }

    #[test]
    fn unfocused_or_misplaced_chrome_fails() {
        let scene = scene(QualityTier::Q1);
        let mut rgb = render(&scene, Layers::Desktop { focused: false }).rgb;
        paint(
            &mut rgb,
            content_rect(scene.window.unwrap()),
            [0x20, 0x24, 0x2c],
        );
        let err = check_scene(&Screenshot::new(1280, 800, rgb).unwrap(), &scene).unwrap_err();
        assert!(err.contains("focus") || err.contains("title bar"), "{err}");

        let moved = Scene {
            window: Some(window_origin(scene.tier, 1)),
            ..scene
        };
        assert!(check_scene(&passing_shot(&moved), &scene).is_err());
    }

    #[test]
    fn region_change_ignores_excluded_pixels() {
        let scene = scene(QualityTier::Q0);
        let a = passing_shot(&scene);
        let mut rgb = a.rgb().to_vec();
        let counter = translate(panel(scene.tier).counter, scene.window.unwrap());
        paint(&mut rgb, counter, [0xff, 0x00, 0xff]);
        let b = Screenshot::new(1280, 800, rgb).unwrap();
        assert!(region_changed(&a, &b, counter, &[]));
        assert!(!region_changed(&a, &b, counter, &[counter]));
        assert!(!region_changed(&a, &a, counter, &[]));
    }
}
