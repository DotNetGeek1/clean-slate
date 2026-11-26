//! The character grid: [`ROWS`] screen rows over a ring of [`SCROLLBACK`] history rows, a cursor,
//! the current drawing attributes, and which rows of the visible view changed since the last
//! repaint.
//!
//! The screen knows nothing about escape sequences ([`crate::vt`] turns bytes into these
//! operations) or about pixels ([`crate::render`] paints the view).

/// Columns of the grid.
pub const COLS: usize = 80;
/// Rows of the live screen.
pub const ROWS: usize = 25;
/// Rows kept above the live screen once they scroll off.
pub const SCROLLBACK: usize = 200;

const RING: usize = ROWS + SCROLLBACK;

/// A colour: the default for its role, or one of the 16 ANSI colours (8..16 are the bright ones).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    Default,
    Ansi(u8),
}

/// How a cell is drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attr {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub inverse: bool,
}

impl Attr {
    pub const DEFAULT: Self = Self {
        fg: Color::Default,
        bg: Color::Default,
        bold: false,
        inverse: false,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub attr: Attr,
}

impl Cell {
    pub const BLANK: Self = Self {
        ch: ' ',
        attr: Attr::DEFAULT,
    };

    /// A blank drawn with `attr`'s background, as erasing does.
    const fn erased(attr: Attr) -> Self {
        Self {
            ch: ' ',
            attr: Attr {
                fg: Color::Default,
                bg: attr.bg,
                bold: false,
                inverse: attr.inverse,
            },
        }
    }
}

type Row = [Cell; COLS];

/// Rows of the view as a bit set: bit `r` is view row `r`.
const ALL_ROWS: u32 = (1 << ROWS) - 1;
const _: () = assert!(ROWS < 32);

pub struct Screen {
    ring: [Row; RING],
    /// Ring index of live row 0.
    top: usize,
    /// History rows filled, at most [`SCROLLBACK`].
    history: usize,
    row: usize,
    col: usize,
    /// The last write filled the last column: the next printable starts a new line first.
    wrap_pending: bool,
    attr: Attr,
    saved: (usize, usize, Attr),
    cursor_visible: bool,
    /// History rows the view is scrolled back by; 0 shows the live screen.
    view_offset: usize,
    dirty: u32,
}

impl Default for Screen {
    fn default() -> Self {
        Self::new()
    }
}

impl Screen {
    pub const fn new() -> Self {
        Self {
            ring: [[Cell::BLANK; COLS]; RING],
            top: 0,
            history: 0,
            row: 0,
            col: 0,
            wrap_pending: false,
            attr: Attr::DEFAULT,
            saved: (0, 0, Attr::DEFAULT),
            cursor_visible: true,
            view_offset: 0,
            dirty: ALL_ROWS,
        }
    }

    // ---- reading ----------------------------------------------------------------------------

    /// The cursor as (row, column) of the live screen.
    pub const fn cursor(&self) -> (usize, usize) {
        (self.row, self.col)
    }

    pub const fn cursor_visible(&self) -> bool {
        self.cursor_visible
    }

    pub const fn attr(&self) -> Attr {
        self.attr
    }

    pub const fn history(&self) -> usize {
        self.history
    }

    pub const fn view_offset(&self) -> usize {
        self.view_offset
    }

    /// Live row `row`.
    pub fn live_row(&self, row: usize) -> &Row {
        &self.ring[(self.top + row) % RING]
    }

    /// View row `row`: a live row, or a history row while scrolled back.
    pub fn view_row(&self, row: usize) -> &Row {
        let index = (self.top + RING + row - self.view_offset) % RING;
        &self.ring[index]
    }

    /// The text of live row `row`, trailing blanks removed (tests and diagnostics).
    pub fn live_text(&self, row: usize, out: &mut [u8; COLS * 4]) -> usize {
        row_text(self.live_row(row), out)
    }

    /// Where the cursor shows in the view, if it does: hidden, or scrolled out of the view.
    pub fn view_cursor(&self) -> Option<(usize, usize)> {
        let row = self.row + self.view_offset;
        (self.cursor_visible && row < ROWS).then_some((row, self.col))
    }

    /// View rows changed since the last [`Self::take_dirty`], as a bit set.
    pub const fn dirty(&self) -> u32 {
        self.dirty
    }

    pub fn take_dirty(&mut self) -> u32 {
        core::mem::take(&mut self.dirty)
    }

    /// Marks every view row changed (focus change, theme change, first paint).
    pub fn touch_all(&mut self) {
        self.dirty = ALL_ROWS;
    }

    // ---- scrollback view --------------------------------------------------------------------

    /// Scrolls the view back by `rows` (towards older output), as far as history goes.
    pub fn scroll_view_back(&mut self, rows: usize) {
        self.set_view_offset(self.view_offset.saturating_add(rows));
    }

    /// Scrolls the view forward by `rows`, back to the live screen at most.
    pub fn scroll_view_forward(&mut self, rows: usize) {
        self.set_view_offset(self.view_offset.saturating_sub(rows));
    }

    /// Shows the live screen.
    pub fn reset_view(&mut self) {
        self.set_view_offset(0);
    }

    fn set_view_offset(&mut self, offset: usize) {
        let offset = offset.min(self.history);
        if offset != self.view_offset {
            self.view_offset = offset;
            self.dirty = ALL_ROWS;
        }
    }

    // ---- writing ----------------------------------------------------------------------------

    fn touch_live(&mut self, row: usize) {
        let view = row + self.view_offset;
        if view < ROWS {
            self.dirty |= 1 << view;
        }
    }

    fn touch_live_from(&mut self, row: usize) {
        for r in row..ROWS {
            self.touch_live(r);
        }
    }

    fn live_row_mut(&mut self, row: usize) -> &mut Row {
        self.touch_live(row);
        &mut self.ring[(self.top + row) % RING]
    }

    /// Moves the cursor; the rows it leaves and enters repaint.
    fn move_to(&mut self, row: usize, col: usize) {
        self.touch_live(self.row);
        self.row = row.min(ROWS - 1);
        self.col = col.min(COLS - 1);
        self.wrap_pending = false;
        self.touch_live(self.row);
    }

    /// Writes one printable character at the cursor and advances it.
    pub fn put(&mut self, ch: char) {
        if self.wrap_pending {
            self.carriage_return();
            self.line_feed();
        }
        let (row, col, attr) = (self.row, self.col, self.attr);
        self.live_row_mut(row)[col] = Cell { ch, attr };
        if col + 1 == COLS {
            self.wrap_pending = true;
        } else {
            self.col += 1;
        }
    }

    pub fn carriage_return(&mut self) {
        self.move_to(self.row, 0);
    }

    /// Moves down a row, scrolling the screen up at the bottom.
    pub fn line_feed(&mut self) {
        if self.row + 1 == ROWS {
            self.touch_live(self.row);
            self.scroll_up();
            self.wrap_pending = false;
        } else {
            self.move_to(self.row + 1, self.col);
        }
    }

    /// Moves up a row, scrolling the screen down at the top.
    pub fn reverse_line_feed(&mut self) {
        if self.row == 0 {
            self.insert_lines(1);
        } else {
            self.move_to(self.row - 1, self.col);
        }
    }

    pub fn backspace(&mut self) {
        self.move_to(self.row, self.col.saturating_sub(1));
    }

    pub fn tab(&mut self) {
        self.move_to(self.row, (self.col / 8 + 1) * 8);
    }

    /// Live row 0 goes into history; a blank row enters at the bottom.
    fn scroll_up(&mut self) {
        self.top = (self.top + 1) % RING;
        if self.history < SCROLLBACK {
            self.history += 1;
        }
        // A view scrolled back keeps showing the same rows, as far as history reaches.
        if self.view_offset > 0 {
            self.view_offset = (self.view_offset + 1).min(self.history);
        }
        let blank = Cell::erased(self.attr);
        let bottom = (self.top + ROWS - 1) % RING;
        self.ring[bottom] = [blank; COLS];
        self.dirty = ALL_ROWS;
    }

    pub fn cursor_up(&mut self, n: usize) {
        self.move_to(self.row.saturating_sub(n), self.col);
    }

    pub fn cursor_down(&mut self, n: usize) {
        self.move_to(self.row.saturating_add(n), self.col);
    }

    pub fn cursor_forward(&mut self, n: usize) {
        self.move_to(self.row, self.col.saturating_add(n));
    }

    pub fn cursor_back(&mut self, n: usize) {
        self.move_to(self.row, self.col.saturating_sub(n));
    }

    /// Moves to a 0-based position, clamped to the screen.
    pub fn cursor_to(&mut self, row: usize, col: usize) {
        self.move_to(row, col);
    }

    pub fn cursor_to_col(&mut self, col: usize) {
        self.move_to(self.row, col);
    }

    pub fn cursor_to_row(&mut self, row: usize) {
        self.move_to(row, self.col);
    }

    /// Erases columns `from..to` of live row `row`.
    fn erase_cells(&mut self, row: usize, from: usize, to: usize) {
        let blank = Cell::erased(self.attr);
        let cells = self.live_row_mut(row);
        for cell in &mut cells[from.min(COLS)..to.min(COLS)] {
            *cell = blank;
        }
    }

    /// `EL`: 0 from the cursor to the end of the line, 1 from the start to the cursor, 2 all.
    pub fn erase_in_line(&mut self, mode: u16) {
        let (row, col) = (self.row, self.col);
        match mode {
            0 => self.erase_cells(row, col, COLS),
            1 => self.erase_cells(row, 0, col + 1),
            2 => self.erase_cells(row, 0, COLS),
            _ => {}
        }
    }

    /// `ED`: 0 from the cursor to the end, 1 from the start to the cursor, 2 and 3 all (3 also
    /// forgets the history).
    pub fn erase_in_display(&mut self, mode: u16) {
        let (row, col) = (self.row, self.col);
        match mode {
            0 => {
                self.erase_cells(row, col, COLS);
                for r in row + 1..ROWS {
                    self.erase_cells(r, 0, COLS);
                }
            }
            1 => {
                for r in 0..row {
                    self.erase_cells(r, 0, COLS);
                }
                self.erase_cells(row, 0, col + 1);
            }
            2 | 3 => {
                for r in 0..ROWS {
                    self.erase_cells(r, 0, COLS);
                }
                if mode == 3 {
                    self.history = 0;
                    self.set_view_offset(0);
                }
            }
            _ => {}
        }
    }

    /// `ECH`: blanks `n` cells from the cursor without moving anything.
    pub fn erase_chars(&mut self, n: usize) {
        let (row, col) = (self.row, self.col);
        self.erase_cells(row, col, col.saturating_add(n));
    }

    /// `DCH`: deletes `n` cells at the cursor; the rest of the line moves left.
    pub fn delete_chars(&mut self, n: usize) {
        let (row, col, attr) = (self.row, self.col, self.attr);
        let n = n.min(COLS - col);
        let cells = self.live_row_mut(row);
        cells.copy_within(col + n.., col);
        for cell in &mut cells[COLS - n..] {
            *cell = Cell::erased(attr);
        }
        self.wrap_pending = false;
    }

    /// `ICH`: inserts `n` blanks at the cursor; the rest of the line moves right.
    pub fn insert_chars(&mut self, n: usize) {
        let (row, col, attr) = (self.row, self.col, self.attr);
        let n = n.min(COLS - col);
        let cells = self.live_row_mut(row);
        cells.copy_within(col..COLS - n, col + n);
        for cell in &mut cells[col..col + n] {
            *cell = Cell::erased(attr);
        }
        self.wrap_pending = false;
    }

    /// `IL`: inserts `n` blank rows at the cursor row; rows below move down and the bottom ones
    /// are lost.
    pub fn insert_lines(&mut self, n: usize) {
        let row = self.row;
        let n = n.min(ROWS - row);
        for r in (row + n..ROWS).rev() {
            let from = self.ring[(self.top + r - n) % RING];
            self.ring[(self.top + r) % RING] = from;
        }
        for r in row..row + n {
            self.erase_cells(r, 0, COLS);
        }
        self.touch_live_from(row);
    }

    /// `DL`: deletes `n` rows at the cursor row; rows below move up and blanks enter at the
    /// bottom.
    pub fn delete_lines(&mut self, n: usize) {
        let row = self.row;
        let n = n.min(ROWS - row);
        for r in row..ROWS - n {
            let from = self.ring[(self.top + r + n) % RING];
            self.ring[(self.top + r) % RING] = from;
        }
        for r in ROWS - n..ROWS {
            self.erase_cells(r, 0, COLS);
        }
        self.touch_live_from(row);
    }

    pub fn set_attr(&mut self, attr: Attr) {
        self.attr = attr;
    }

    pub fn set_cursor_visible(&mut self, visible: bool) {
        if visible != self.cursor_visible {
            self.cursor_visible = visible;
            self.touch_live(self.row);
        }
    }

    pub fn save_cursor(&mut self) {
        self.saved = (self.row, self.col, self.attr);
    }

    pub fn restore_cursor(&mut self) {
        let (row, col, attr) = self.saved;
        self.move_to(row, col);
        self.attr = attr;
    }

    /// `RIS`: a blank screen, no history, default attributes. Cleared in place: a fresh
    /// `Screen` is far larger than a CPL3 stack.
    pub fn reset(&mut self) {
        for row in &mut self.ring {
            *row = [Cell::BLANK; COLS];
        }
        self.top = 0;
        self.history = 0;
        self.row = 0;
        self.col = 0;
        self.wrap_pending = false;
        self.attr = Attr::DEFAULT;
        self.saved = (0, 0, Attr::DEFAULT);
        self.cursor_visible = true;
        self.view_offset = 0;
        self.dirty = ALL_ROWS;
    }
}

/// UTF-8 of `row`, trailing blanks removed; returns the length written.
pub fn row_text(row: &Row, out: &mut [u8; COLS * 4]) -> usize {
    let mut len = 0;
    let mut end = 0;
    for cell in row {
        len += cell.ch.encode_utf8(&mut out[len..]).len();
        if cell.ch != ' ' {
            end = len;
        }
    }
    end
}
