//! Icon placeholder strategy: a handful of 16×16 one-bit marks for the shell's own
//! affordances, and a monogram fallback for anything else, so M10 never waits on an icon set.

use clean_slate_graphics::{Point, Rect};
use clean_slate_raster::Canvas;

use crate::layout::offset;
use crate::paint::fill;
use crate::tokens::{Rgba, Theme};

/// Icon edge length in pixels at scale 1.
pub const ICON_SIZE: u32 = 16;

/// Icons available to primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Icon {
    /// House.
    Home,
    /// Application grid.
    Apps,
    /// Overlapping workspaces.
    Spaces,
    /// Folder.
    Files,
    /// Display.
    System,
    /// Sliders.
    Settings,
    /// Magnifier.
    Search,
    /// Generic "icon pending" mark.
    Placeholder,
    /// First letter of a name inside the icon cell; the fallback for unlisted icons.
    Monogram(char),
}

impl Icon {
    /// The 1-bit mask, or `None` for [`Icon::Monogram`].
    pub fn mask(self) -> Option<&'static [u16; 16]> {
        Some(match self {
            Self::Home => &HOME,
            Self::Apps => &APPS,
            Self::Spaces => &SPACES,
            Self::Files => &FILES,
            Self::System => &SYSTEM,
            Self::Settings => &SETTINGS,
            Self::Search => &SEARCH,
            Self::Placeholder => &PLACEHOLDER,
            Self::Monogram(_) => return None,
        })
    }
}

/// Paints `icon` with its cell top-left at `origin`, each mask pixel `scale`×`scale`.
pub fn paint_icon(
    canvas: &mut Canvas<'_>,
    theme: &Theme,
    icon: Icon,
    origin: Point,
    scale: u32,
    color: Rgba,
) {
    let scale = scale.max(1);
    let Some(mask) = icon.mask() else {
        if let Icon::Monogram(ch) = icon {
            paint_monogram(canvas, theme, ch, origin, scale, color);
        }
        return;
    };
    for (y, bits) in mask.iter().enumerate() {
        for x in 0..ICON_SIZE {
            if bits & (0x8000 >> x) == 0 {
                continue;
            }
            fill(
                canvas,
                Rect {
                    x: offset(origin.x, x * scale),
                    y: offset(origin.y, y as u32 * scale),
                    width: scale,
                    height: scale,
                },
                color,
            );
        }
    }
}

fn paint_monogram(
    canvas: &mut Canvas<'_>,
    theme: &Theme,
    ch: char,
    origin: Point,
    scale: u32,
    color: Rgba,
) {
    let mut buf = [0u8; 4];
    let letter = ch.to_ascii_uppercase().encode_utf8(&mut buf);
    let style = crate::tokens::TextStyle {
        scale,
        ..theme.type_scale.heading
    };
    let size = crate::text::measure(theme, style, letter);
    let cell = ICON_SIZE * scale;
    let at = Point {
        x: offset(origin.x, cell.saturating_sub(size.width) / 2),
        y: offset(origin.y, cell.saturating_sub(size.height) / 2),
    };
    crate::text::draw(canvas, theme, at, letter, style, color);
}

const fn mask(rows: [&str; 16]) -> [u16; 16] {
    let mut out = [0u16; 16];
    let mut y = 0;
    while y < 16 {
        let row = rows[y].as_bytes();
        assert!(row.len() == 16, "icon rows are 16 pixels wide");
        let mut x = 0;
        while x < 16 {
            if row[x] == b'#' {
                out[y] |= 0x8000 >> x;
            }
            x += 1;
        }
        y += 1;
    }
    out
}

const HOME: [u16; 16] = mask([
    "................",
    ".......##.......",
    "......####......",
    ".....##..##.....",
    "....##....##....",
    "...##......##...",
    "..##........##..",
    ".##..........##.",
    "..#..........#..",
    "..#..........#..",
    "..#...####...#..",
    "..#...#..#...#..",
    "..#...#..#...#..",
    "..#...#..#...#..",
    "..#####..#####..",
    "................",
]);

const APPS: [u16; 16] = mask([
    "................",
    ".#####....#####.",
    ".#...#....#...#.",
    ".#...#....#...#.",
    ".#...#....#...#.",
    ".#####....#####.",
    "................",
    "................",
    "................",
    "................",
    ".#####....#####.",
    ".#...#....#...#.",
    ".#...#....#...#.",
    ".#...#....#...#.",
    ".#####....#####.",
    "................",
]);

const SPACES: [u16; 16] = mask([
    "................",
    "................",
    ".#########......",
    ".#.......#......",
    ".#.......#......",
    ".#...##########.",
    ".#...#........#.",
    ".#...#........#.",
    ".#####........#.",
    ".....#........#.",
    ".....#........#.",
    ".....#........#.",
    ".....##########.",
    "................",
    "................",
    "................",
]);

const FILES: [u16; 16] = mask([
    "................",
    "................",
    ".#####..........",
    ".#....#.........",
    ".#.....########.",
    ".#............#.",
    ".##############.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".##############.",
    "................",
    "................",
    "................",
]);

const SYSTEM: [u16; 16] = mask([
    "................",
    "................",
    ".##############.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".#............#.",
    ".##############.",
    "......####......",
    "......####......",
    "....########....",
    "................",
    "................",
    "................",
]);

const SETTINGS: [u16; 16] = mask([
    "................",
    "................",
    "...###..........",
    ".##############.",
    "...###..........",
    "................",
    ".........###....",
    ".##############.",
    ".........###....",
    "................",
    "......###.......",
    ".##############.",
    "......###.......",
    "................",
    "................",
    "................",
]);

const SEARCH: [u16; 16] = mask([
    "................",
    "................",
    "....#####.......",
    "...#.....#......",
    "..#.......#.....",
    "..#.......#.....",
    "..#.......#.....",
    "..#.......#.....",
    "...#.....#......",
    "....#####.#.....",
    "...........#....",
    "............#...",
    ".............#..",
    "................",
    "................",
    "................",
]);

const PLACEHOLDER: [u16; 16] = mask([
    "................",
    "................",
    "...##########...",
    "..#..........#..",
    "..#..........#..",
    "..#..........#..",
    "..#..........#..",
    "..#....##....#..",
    "..#....##....#..",
    "..#..........#..",
    "..#..........#..",
    "..#..........#..",
    "..#..........#..",
    "...##########...",
    "................",
    "................",
]);
