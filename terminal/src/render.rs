//! Paints the screen's view into a pixel buffer with the Spleen 8x16 font.
//!
//! The window is the grid plus a [`PADDING`] border. Row `r` of the view covers
//! [`row_rect`]`(r)`, so a changed row repaints exactly its band. Painting is a pure function
//! of the screen and the focus, so a repaint of some rows equals a full repaint there.

use clean_slate_graphics::{Rect, Size};
use clean_slate_raster::{Canvas, Color as Rgb, GlyphAtlas, SPLEEN_8X16};
use clean_slate_ui::{Rgba, CLEAN_SLATE_DARK};

use crate::screen::{Attr, Cell, Color, Screen, COLS, ROWS};

pub const CELL_WIDTH: u32 = 8;
pub const CELL_HEIGHT: u32 = 16;
/// Border between the grid and the window edge.
pub const PADDING: u32 = 6;

/// The window's size: the grid and its border.
pub const WINDOW_SIZE: Size = Size {
    width: COLS as u32 * CELL_WIDTH + 2 * PADDING,
    height: ROWS as u32 * CELL_HEIGHT + 2 * PADDING,
};

const fn rgb(c: Rgba) -> Rgb {
    Rgb::opaque(c.r, c.g, c.b)
}

/// Default text and background: the theme's primary text on its sunken surface.
pub const DEFAULT_FG: Rgb = rgb(CLEAN_SLATE_DARK.palette.text_primary);
pub const DEFAULT_BG: Rgb = rgb(CLEAN_SLATE_DARK.palette.surface_sunken);
/// The cursor, in the theme's accent.
pub const CURSOR: Rgb = rgb(CLEAN_SLATE_DARK.palette.accent_cyan);

/// The 16 ANSI colours, toned for the dark theme.
pub const ANSI: [Rgb; 16] = [
    Rgb::opaque(0x1A, 0x1F, 0x2B),
    Rgb::opaque(0xE0, 0x5A, 0x5A),
    Rgb::opaque(0x6C, 0xC6, 0x6C),
    Rgb::opaque(0xD8, 0xB4, 0x4A),
    Rgb::opaque(0x4E, 0x8C, 0xE8),
    Rgb::opaque(0xB0, 0x6E, 0xD8),
    Rgb::opaque(0x3C, 0xC0, 0xD0),
    Rgb::opaque(0xC8, 0xCE, 0xDA),
    Rgb::opaque(0x5A, 0x64, 0x78),
    Rgb::opaque(0xFF, 0x7A, 0x7A),
    Rgb::opaque(0x8E, 0xE6, 0x8E),
    Rgb::opaque(0xF2, 0xD0, 0x6A),
    Rgb::opaque(0x7A, 0xAE, 0xFF),
    Rgb::opaque(0xD0, 0x96, 0xF2),
    Rgb::opaque(0x6C, 0xE4, 0xF2),
    Rgb::opaque(0xF4, 0xF6, 0xFA),
];

/// The band of view row `row`, padding included at the window's edges, so painting every row
/// covers the whole window.
pub fn row_rect(row: usize) -> Rect {
    let top = if row == 0 {
        0
    } else {
        PADDING + row as u32 * CELL_HEIGHT
    };
    let bottom = if row + 1 == ROWS {
        WINDOW_SIZE.height
    } else {
        PADDING + (row as u32 + 1) * CELL_HEIGHT
    };
    Rect {
        x: 0,
        y: top as i32,
        width: WINDOW_SIZE.width,
        height: bottom - top,
    }
}

/// The pixel rect of cell (`row`, `col`) of the view.
pub fn cell_rect(row: usize, col: usize) -> Rect {
    Rect {
        x: (PADDING + col as u32 * CELL_WIDTH) as i32,
        y: (PADDING + row as u32 * CELL_HEIGHT) as i32,
        width: CELL_WIDTH,
        height: CELL_HEIGHT,
    }
}

/// Foreground and background of a cell. Bold brightens the eight normal colours.
pub fn colors(attr: Attr) -> (Rgb, Rgb) {
    let fg = match attr.fg {
        Color::Default => DEFAULT_FG,
        Color::Ansi(index) if attr.bold && index < 8 => ANSI[usize::from(index) + 8],
        Color::Ansi(index) => ANSI[usize::from(index & 15)],
    };
    let bg = match attr.bg {
        Color::Default => DEFAULT_BG,
        Color::Ansi(index) => ANSI[usize::from(index & 15)],
    };
    if attr.inverse {
        (bg, fg)
    } else {
        (fg, bg)
    }
}

fn paint_cell(canvas: &mut Canvas<'_>, rect: Rect, cell: Cell, fg: Rgb, bg: Rgb) {
    canvas.fill_rect(rect, bg);
    if cell.ch != ' ' {
        let mut utf8 = [0u8; 4];
        let text = cell.ch.encode_utf8(&mut utf8);
        canvas.draw_text(&SPLEEN_8X16, (rect.x, rect.y), text, fg);
    }
}

/// Paints view row `row`. With `focused`, the cursor is a solid block; without, an outline.
pub fn paint_row(canvas: &mut Canvas<'_>, screen: &Screen, row: usize, focused: bool) {
    canvas.fill_rect(row_rect(row), DEFAULT_BG);
    let cursor = screen.view_cursor();
    for (col, &cell) in screen.view_row(row).iter().enumerate() {
        let rect = cell_rect(row, col);
        let (fg, bg) = colors(cell.attr);
        if cursor == Some((row, col)) {
            if focused {
                paint_cell(canvas, rect, cell, DEFAULT_BG, CURSOR);
            } else {
                paint_cell(canvas, rect, cell, fg, bg);
                canvas.stroke_rect(rect, 1, CURSOR);
            }
        } else if bg != DEFAULT_BG || cell.ch != ' ' {
            paint_cell(canvas, rect, cell, fg, bg);
        }
    }
}

/// Paints every view row whose bit is set in `rows`.
pub fn paint_rows(canvas: &mut Canvas<'_>, screen: &Screen, rows: u32, focused: bool) {
    for row in 0..ROWS {
        if rows & (1 << row) != 0 {
            paint_row(canvas, screen, row, focused);
        }
    }
}

/// The cell size [`SPLEEN_8X16`] draws, which the layout here assumes.
pub fn font_cell() -> (u32, u32) {
    SPLEEN_8X16.cell()
}
