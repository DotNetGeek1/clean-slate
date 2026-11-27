//! Structural screenshot checks for the #119 desktop lane.
//!
//! The host renders what the compositor must show for a known scene (shell wallpaper and
//! workspace, the focused window's server-side chrome, the rail of apps over it and the cursor) with the
//! same `ui`/`compositor` code the guest runs, then compares named regions of a QMP screendump
//! against it. Client content is never rendered here: it is excluded from every comparison, and
//! the lane proves it changed by diffing two captures. Each region has its own mismatch budget,
//! so a failure names what is wrong (rail, dock band, chrome, focus) instead of a frame hash.

use clean_slate_compositor::wm::cascade;
use clean_slate_desktop_shell::apps::Apps;
use clean_slate_graphics::pixel::{BufferLayout, PixelFormat};
use clean_slate_graphics::protocol::Event;
use clean_slate_graphics::window::WindowHandle;
use clean_slate_graphics::{Point, Rect, Size};
use clean_slate_native_abi::launcher::{AppEntry, AppName, AppState, LauncherEvent};
use clean_slate_playground::{PanelLayout, PANEL_SIZE, WINDOW_TITLE};
use clean_slate_raster::{BlitMode, Canvas};
use clean_slate_ui::cursor::{cursor_rect, paint_cursor, ARROW};
use clean_slate_ui::layout::RectExt;
use clean_slate_ui::shell::RailApps;
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
    /// Content origin of the one app window, if shown.
    pub(crate) window: Option<Point>,
    /// The app's one window is minimised (#357): not drawn (`window` is `None`) and marked on
    /// the rail, which then selects nothing.
    pub(crate) minimized: bool,
    /// Pointer hotspot (the software cursor is drawn there).
    pub(crate) pointer: Point,
    /// The output size: [`OUTPUT`] except in the display-mode lane (#314).
    pub(crate) output: Size,
}

fn style(tier: QualityTier) -> Style<'static> {
    Style::new(&CLEAN_SLATE_DARK, tier)
}

fn shell(tier: QualityTier) -> Shell<'static> {
    shell_at(tier, OUTPUT)
}

fn shell_at(tier: QualityTier, output: Size) -> Shell<'static> {
    Shell::new(&CLEAN_SLATE_DARK, tier, output, ShellConfig::M10)
}

/// The rail rect on an `output`-sized desktop.
pub(crate) fn rail_at(tier: QualityTier, output: Size) -> Rect {
    shell_at(tier, output).zones().rail
}

/// [`window_origin`] on an `output`-sized desktop (#314).
pub(crate) fn window_origin_at(tier: QualityTier, output: Size, step: u32) -> Point {
    let area = shell_at(tier, output).zones().window_area();
    cascade(&chrome(tier), area, PANEL_SIZE, step)
}

/// The desktop lanes' manifest names one launchable row, the playground, running at boot
/// (#237). The rail shows it running, selected while its window has focus, and marked while
/// its window is minimised (#357). Built with the shell's own model from what init and the
/// compositor tell it.
fn desktop_rail(window_focused: bool, minimized: bool) -> RailApps {
    const PID: u64 = 1;
    let mut apps = Apps::new();
    apps.on_launcher(&LauncherEvent::Entry(AppEntry {
        service: 1,
        state: AppState::Running,
        generation: 1,
        pid: PID,
        name: AppName::new(b"playground").expect("name"),
    }));
    let window = WindowHandle(1);
    if window_focused || minimized {
        apps.on_window(&Event::WindowAdded { window, pid: PID });
    }
    if window_focused {
        apps.on_window(&Event::WindowFocused {
            window: Some(window),
        });
    }
    if minimized {
        apps.on_window(&Event::WindowMinimized {
            window,
            minimized: true,
        });
    }
    apps.rail()
}

pub(crate) fn chrome(tier: QualityTier) -> CleanSlateChrome<'static> {
    CleanSlateChrome::new(style(tier))
}

/// The rail rect and the window area of the M10 shell zones.
#[cfg(test)]
pub(crate) fn rail(tier: QualityTier) -> Rect {
    shell(tier).zones().rail
}

/// Rail slot `slot` in output coordinates (the rail surface sits at the output's origin).
pub(crate) fn rail_item(tier: QualityTier, slot: usize) -> Option<Rect> {
    shell(tier)
        .rail_layout()
        .item(slot)
        .filter(|r| !r.is_empty())
}

/// Content origin of the `step`th toplevel the compositor placed since it started.
pub(crate) fn window_origin(tier: QualityTier, step: u32) -> Point {
    sized_window_origin(tier, PANEL_SIZE, step)
}

/// [`window_origin`] for a toplevel whose content is `size` (the terminal's, #311).
pub(crate) fn sized_window_origin(tier: QualityTier, size: Size, step: u32) -> Point {
    let area = shell(tier).zones().window_area();
    cascade(&chrome(tier), area, size, step)
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

fn output_rect(output: Size) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: output.width,
        height: output.height,
    }
}

fn output_layout(output: Size) -> BufferLayout {
    BufferLayout::packed(output.width, output.height, PixelFormat::Xrgb8888).expect("output")
}

/// One host render, as screendump RGB.
pub(crate) struct Render {
    rgb: Vec<u8>,
    output: Size,
}

impl Render {
    fn pixel(&self, x: u32, y: u32) -> [u8; 3] {
        let at = (y * self.output.width + x) as usize * 3;
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
    let mut shell = shell_at(scene.tier, scene.output);
    // The lanes capture only while the one window has focus, so the rail shows the playground
    // selected whenever there is a window; `focused` varies only the chrome, which is what the
    // focus check compares.
    if matches!(layers, Layers::Desktop { .. }) {
        shell.set_apps(desktop_rail(scene.window.is_some(), scene.minimized));
    }
    let layout = output_layout(scene.output);
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
    Render {
        rgb,
        output: scene.output,
    }
}

/// What a passing capture of `scene` looks like: the render with client content filled in.
#[cfg(test)]
pub(crate) fn passing_capture(scene: &Scene) -> Screenshot {
    let output = scene.output;
    let mut rgb = render(scene, Layers::Desktop { focused: true }).rgb;
    if let Some(origin) = scene.window {
        let pointer = cursor(scene.pointer);
        for (x, y) in pixels(content_rect(origin), &[pointer], output) {
            let at = (y * output.width + x) as usize * 3;
            rgb[at..at + 3].copy_from_slice(&[0x20, 0x24, 0x2c]);
        }
    }
    Screenshot::new(output.width, output.height, rgb).unwrap()
}

/// [`render`]'s pixels, for tests that build synthetic captures.
#[cfg(test)]
pub(crate) fn render_rgb(scene: &Scene, layers: Layers) -> Vec<u8> {
    render(scene, layers).rgb
}

pub(crate) fn cursor(pointer: Point) -> Rect {
    cursor_rect(&ARROW, pointer)
}

/// Pixels of `region` (clipped to an `output`-sized frame) outside every `exclude` rect.
fn pixels(region: Rect, exclude: &[Rect], output: Size) -> impl Iterator<Item = (u32, u32)> + '_ {
    let x0 = region.x.max(0) as u32;
    let y0 = region.y.max(0) as u32;
    let x1 = (region.right().max(0) as u32).min(output.width);
    let y1 = (region.bottom().max(0) as u32).min(output.height);
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
    for (x, y) in pixels(region, exclude, expected.output) {
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
    let output = scene.output;
    if (shot.width(), shot.height()) != (output.width, output.height) {
        return Err(format!(
            "expected a {}x{} frame, got {}x{}",
            output.width,
            output.height,
            shot.width(),
            shot.height()
        ));
    }
    let background = render(scene, Layers::Background);
    let focused = render(scene, Layers::Desktop { focused: true });
    let cursor = cursor(scene.pointer);
    let content = scene.window.map(content_rect);
    let no_content: Vec<Rect> = content.into_iter().collect();

    let rail = rail_at(scene.tier, output);
    let rail_diff = diff(shot, &focused, rail, &[cursor]);
    if !rail_diff.within(RAIL_BUDGET) {
        return Err(rail_diff.describe("left rail"));
    }
    // The app's rail item exactly, unless the pointer is on the rail (the host render has no
    // hover): its markers are a few pixels, well inside the rail's budget (#357).
    if let Some(item) = shell_at(scene.tier, output).rail_layout().item(0) {
        if !rail.contains(scene.pointer) {
            let item_diff = diff(shot, &focused, item, &[cursor]);
            if item_diff.mismatched != 0 {
                let what = if scene.minimized {
                    "the app's rail item (minimised-window marker expected)"
                } else {
                    "the app's rail item"
                };
                return Err(item_diff.describe(what));
            }
        }
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
        y: (output.height - DOCK_BAND_ROWS) as i32,
        width: output.width - rail.width,
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

    let whole = diff(shot, &focused, output_rect(output), &no_content);
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
    for (x, y) in pixels(visual, exclude, scene.output) {
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
    let output = Size {
        width: a.width(),
        height: a.height(),
    };
    pixels(region, exclude, output).any(|(x, y)| a.pixel(x, y) != b.pixel(x, y))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shot_of(render: &Render) -> Screenshot {
        Screenshot::new(OUTPUT.width, OUTPUT.height, render.rgb.clone()).unwrap()
    }

    /// A render with client content filled in, as a passing capture would look.
    fn passing_shot(scene: &Scene) -> Screenshot {
        passing_capture(scene)
    }

    fn paint(rgb: &mut [u8], rect: Rect, color: [u8; 3]) {
        paint_except(rgb, rect, &[], color);
    }

    fn paint_except(rgb: &mut [u8], rect: Rect, exclude: &[Rect], color: [u8; 3]) {
        for (x, y) in pixels(rect, exclude, OUTPUT) {
            let at = (y * OUTPUT.width + x) as usize * 3;
            rgb[at..at + 3].copy_from_slice(&color);
        }
    }

    fn scene(tier: QualityTier) -> Scene {
        Scene {
            tier,
            window: Some(window_origin(tier, 0)),
            minimized: false,
            pointer: Point { x: 1279, y: 799 },
            output: OUTPUT,
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
            let minimized = Scene {
                minimized: true,
                ..bare
            };
            assert_eq!(
                check_scene(&passing_shot(&minimized), &minimized),
                Ok(()),
                "{tier:?}"
            );
        }
    }

    /// #357: the rail marker is a handful of pixels, so the rail's budget alone would pass a
    /// capture without it (or with it left over after a restore); the app's item is exact.
    #[test]
    fn the_minimised_marker_must_be_there_and_only_then() {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let bare = Scene {
                window: None,
                ..scene(tier)
            };
            let minimized = Scene {
                minimized: true,
                ..bare
            };
            let err = check_scene(&passing_shot(&bare), &minimized).unwrap_err();
            assert!(err.contains("minimised-window marker"), "{tier:?}: {err}");
            let err = check_scene(&passing_shot(&minimized), &bare).unwrap_err();
            assert!(err.contains("rail item"), "{tier:?}: {err}");
            let focused = scene(tier);
            assert!(check_scene(&passing_shot(&minimized), &focused).is_err());
        }
    }

    #[test]
    fn a_missing_rail_or_a_dock_or_missing_content_is_named() {
        let scene = scene(QualityTier::Q1);
        let background = render(&scene, Layers::Background);
        let mut no_rail = passing_shot(&scene).rgb().to_vec();
        let rail = rail(scene.tier);
        for (x, y) in pixels(rail, &[], OUTPUT) {
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
