//! Host tests: the grid, the VT parser, line editing, key mapping, rendering and the session.

use std::boxed::Box;
use std::string::String;
use std::vec;
use std::vec::Vec;

use clean_slate_graphics::geometry::Size;
use clean_slate_graphics::ids::{ClientBufferId, ObjectId, OutputId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::input::{KeyState, KeyUsage, Modifiers};
use clean_slate_graphics::mode::{OutputInfo, REFERENCE_MODE};
use clean_slate_graphics::protocol::{Event, Features, ProtocolVersion, Request};
use clean_slate_graphics::window::{DecorationMode, WindowStates};
use clean_slate_graphics::Scale120;
use clean_slate_raster::{pixel_at, Canvas};

use crate::app::Terminal;
use crate::keys::{action, Action};
use crate::line::{Key, LineEditor, Sink};
use crate::render::{self, cell_rect, colors, CURSOR, DEFAULT_BG, WINDOW_SIZE};
use crate::screen::{Attr, Color, Screen, COLS, ROWS, SCROLLBACK};
use crate::session::{buffer_layout, BufferSlot, ExitReason, Host, HostError, Outcome, Session};
use crate::vt::Parser;

fn screen() -> Box<Screen> {
    Box::new(Screen::new())
}

fn feed(screen: &mut Screen, bytes: &[u8]) {
    Parser::new().feed(screen, bytes);
}

fn live(screen: &Screen, row: usize) -> String {
    let mut out = [0u8; COLS * 4];
    let len = screen.live_text(row, &mut out);
    String::from_utf8(out[..len].to_vec()).expect("utf-8")
}

fn view(screen: &Screen, row: usize) -> String {
    let mut out = [0u8; COLS * 4];
    let len = crate::screen::row_text(screen.view_row(row), &mut out);
    String::from_utf8(out[..len].to_vec()).expect("utf-8")
}

// ---- screen and parser ----------------------------------------------------------------------

#[test]
fn text_and_newlines_land_on_rows() {
    let mut s = screen();
    feed(&mut s, b"hello\r\nworld");
    assert_eq!(live(&s, 0), "hello");
    assert_eq!(live(&s, 1), "world");
    assert_eq!(s.cursor(), (1, 5));
}

#[test]
fn a_full_row_wraps_only_when_more_text_comes() {
    let mut s = screen();
    let row = [b'x'; COLS];
    feed(&mut s, &row);
    assert_eq!(
        s.cursor(),
        (0, COLS - 1),
        "the cursor waits on the last column"
    );
    feed(&mut s, b"\r\n");
    assert_eq!(
        s.cursor(),
        (1, 0),
        "CR LF after a full row does not leave a blank row"
    );
    feed(&mut s, &row);
    feed(&mut s, b"y");
    assert_eq!(live(&s, 2), "y");
}

#[test]
fn output_past_the_bottom_scrolls_into_history() {
    let mut s = screen();
    for line in 0..ROWS + 3 {
        feed(&mut s, std::format!("line {line}\r\n").as_bytes());
    }
    assert_eq!(s.history(), 4);
    assert_eq!(live(&s, 0), "line 4");
    assert_eq!(live(&s, ROWS - 2), std::format!("line {}", ROWS + 2));
    s.scroll_view_back(2);
    assert_eq!(view(&s, 0), "line 2");
    assert_eq!(s.view_cursor(), None, "the cursor row is below the view");
    s.scroll_view_back(100);
    assert_eq!(
        s.view_offset(),
        4,
        "the view stops at the oldest history row"
    );
    assert_eq!(view(&s, 0), "line 0");
    s.reset_view();
    assert_eq!(view(&s, 0), "line 4");
}

#[test]
fn a_scrolled_back_view_holds_still_while_output_scrolls() {
    let mut s = screen();
    for line in 0..ROWS + 5 {
        feed(&mut s, std::format!("{line}\r\n").as_bytes());
    }
    s.scroll_view_back(3);
    let before = view(&s, 0);
    feed(&mut s, b"more\r\n");
    assert_eq!(view(&s, 0), before);
}

#[test]
fn history_is_bounded() {
    let mut s = screen();
    for line in 0..SCROLLBACK + ROWS + 50 {
        feed(&mut s, std::format!("{line}\r\n").as_bytes());
    }
    assert_eq!(s.history(), SCROLLBACK);
    s.scroll_view_back(SCROLLBACK);
    assert_eq!(view(&s, 0), "51");
}

#[test]
fn cursor_movement_and_erasing() {
    let mut s = screen();
    feed(&mut s, b"abcdef\x1b[3D\x1b[K");
    assert_eq!(live(&s, 0), "abc");
    feed(&mut s, b"\x1b[5;10HX");
    assert_eq!(s.cursor(), (4, 10));
    assert_eq!(&live(&s, 4)[9..], "X");
    feed(&mut s, b"\x1b[H\x1b[2J");
    assert_eq!(s.cursor(), (0, 0));
    assert!((0..ROWS).all(|r| live(&s, r).is_empty()));
    feed(&mut s, b"12345\x1b[1G\x1b[2P");
    assert_eq!(live(&s, 0), "345");
    feed(&mut s, b"\x1b[2@");
    assert_eq!(live(&s, 0), "  345");
    feed(&mut s, b"\x1b[3X");
    assert_eq!(live(&s, 0), "   45");
    feed(&mut s, b"\x1b[4G\x1b[1K");
    assert_eq!(live(&s, 0), "    5");
}

#[test]
fn clamped_moves_stay_on_screen() {
    let mut s = screen();
    feed(&mut s, b"\x1b[999;999H");
    assert_eq!(s.cursor(), (ROWS - 1, COLS - 1));
    feed(&mut s, b"\x1b[999A\x1b[999D");
    assert_eq!(s.cursor(), (0, 0));
}

#[test]
fn lines_insert_and_delete() {
    let mut s = screen();
    feed(&mut s, b"one\r\ntwo\r\nthree\x1b[2;1H\x1b[L");
    assert_eq!(
        [live(&s, 0), live(&s, 1), live(&s, 2)],
        ["one", "", "two"].map(String::from)
    );
    feed(&mut s, b"\x1b[2M");
    assert_eq!([live(&s, 1), live(&s, 2)], ["three", ""].map(String::from));
}

#[test]
fn sgr_sets_colours_and_attributes() {
    let mut s = screen();
    feed(
        &mut s,
        b"\x1b[1;31;44mR\x1b[0mn\x1b[92;7mg\x1b[38;5;200mz\x1b[39;27m",
    );
    let row = s.live_row(0);
    assert_eq!(
        row[0].attr,
        Attr {
            fg: Color::Ansi(1),
            bg: Color::Ansi(4),
            bold: true,
            inverse: false
        }
    );
    assert_eq!(row[1].attr, Attr::DEFAULT);
    assert_eq!(row[2].attr.fg, Color::Ansi(10));
    assert!(row[2].attr.inverse);
    assert_eq!(
        row[3].attr.fg,
        Color::Ansi(10),
        "256-colour forms are skipped whole"
    );
    assert_eq!(s.attr().fg, Color::Default);
    assert!(!s.attr().inverse);
}

#[test]
fn unknown_sequences_and_strings_print_nothing() {
    let mut s = screen();
    feed(
        &mut s,
        b"\x1b]0;title\x07a\x1b]2;t\x1b\\b\x1b(Bc\x1b[?1049hd\x1b[6ne",
    );
    assert_eq!(live(&s, 0), "abcde");
}

#[test]
fn cursor_visibility_and_save_restore() {
    let mut s = screen();
    feed(&mut s, b"\x1b[?25l");
    assert!(!s.cursor_visible());
    feed(&mut s, b"\x1b[?25h\x1b[3;4H\x1b7\x1b[H\x1b8");
    assert!(s.cursor_visible());
    assert_eq!(s.cursor(), (2, 3));
    feed(&mut s, b"\x1b[s\x1b[H\x1b[u");
    assert_eq!(s.cursor(), (2, 3));
}

#[test]
fn utf8_decodes_and_broken_sequences_show_a_replacement() {
    let mut s = screen();
    feed(&mut s, "é→".as_bytes());
    feed(&mut s, b"\xC3x\xFF");
    let row = s.live_row(0);
    assert_eq!(
        [row[0].ch, row[1].ch, row[2].ch, row[3].ch, row[4].ch],
        ['é', '→', '\u{FFFD}', 'x', '\u{FFFD}']
    );
}

#[test]
fn a_sequence_split_across_feeds_still_applies() {
    let mut s = screen();
    let mut parser = Parser::new();
    parser.feed(&mut s, b"abc\x1b[");
    parser.feed(&mut s, b"2");
    parser.feed(&mut s, b"D!");
    assert_eq!(live(&s, 0), "a!c");
}

#[test]
fn only_changed_rows_are_dirty() {
    let mut s = screen();
    s.take_dirty();
    feed(&mut s, b"\x1b[3;1Hx");
    // Row 0 (where the cursor left) and row 2.
    assert_eq!(s.take_dirty(), 0b101);
    feed(&mut s, b"y");
    assert_eq!(s.take_dirty(), 0b100);
}

#[test]
fn reverse_index_at_the_top_scrolls_down() {
    let mut s = screen();
    feed(&mut s, b"top\x1b[H\x1bM");
    assert_eq!(live(&s, 0), "");
    assert_eq!(live(&s, 1), "top");
    assert_eq!(s.history(), 0);
}

// ---- line editor ----------------------------------------------------------------------------

#[derive(Default)]
struct Record {
    screen: Box<Screen>,
    parser: Parser,
    sent: Vec<u8>,
    ends: usize,
}

impl Sink for Record {
    fn echo(&mut self, bytes: &[u8]) {
        self.parser.feed(&mut self.screen, bytes);
    }
    fn send(&mut self, bytes: &[u8]) {
        self.sent.extend_from_slice(bytes);
    }
    fn end(&mut self) {
        self.ends += 1;
    }
}

fn type_str(editor: &mut LineEditor, sink: &mut Record, text: &str) {
    for ch in text.chars() {
        editor.key(Key::Char(ch), sink);
    }
}

#[test]
fn a_typed_line_is_echoed_then_sent_on_enter() {
    let mut editor = Box::new(LineEditor::new());
    let mut sink = Record::default();
    type_str(&mut editor, &mut sink, "echo hi");
    assert!(
        sink.sent.is_empty(),
        "nothing goes to the stream before Enter"
    );
    assert_eq!(live(&sink.screen, 0), "echo hi");
    editor.key(Key::Enter, &mut sink);
    assert_eq!(sink.sent, b"echo hi\n");
    assert_eq!(sink.screen.cursor(), (1, 0));
    assert!(editor.line().is_empty());
}

#[test]
fn editing_in_the_middle_redraws_the_tail() {
    let mut editor = Box::new(LineEditor::new());
    let mut sink = Record::default();
    type_str(&mut editor, &mut sink, "ehco");
    for key in [Key::Left, Key::Left, Key::Backspace, Key::Right] {
        editor.key(key, &mut sink);
    }
    type_str(&mut editor, &mut sink, "h");
    assert_eq!(live(&sink.screen, 0), "echo");
    assert_eq!(sink.screen.cursor(), (0, 3));
    editor.key(Key::Home, &mut sink);
    editor.key(Key::Delete, &mut sink);
    assert_eq!(live(&sink.screen, 0), "cho");
    assert_eq!(sink.screen.cursor(), (0, 0));
    editor.key(Key::End, &mut sink);
    assert_eq!(sink.screen.cursor(), (0, 3));
    editor.key(Key::Enter, &mut sink);
    assert_eq!(sink.sent, b"cho\n");
}

#[test]
fn backspace_and_delete_at_the_edges_do_nothing() {
    let mut editor = Box::new(LineEditor::new());
    let mut sink = Record::default();
    editor.key(Key::Backspace, &mut sink);
    editor.key(Key::Delete, &mut sink);
    editor.key(Key::Left, &mut sink);
    editor.key(Key::Right, &mut sink);
    assert_eq!(sink.screen.cursor(), (0, 0));
    assert!(sink.sent.is_empty());
}

#[test]
fn history_steps_back_and_returns_to_the_draft() {
    let mut editor = Box::new(LineEditor::new());
    let mut sink = Record::default();
    for line in ["ls", "pwd", "pwd"] {
        type_str(&mut editor, &mut sink, line);
        editor.key(Key::Enter, &mut sink);
    }
    type_str(&mut editor, &mut sink, "ec");
    editor.key(Key::Up, &mut sink);
    assert_eq!(
        editor.line(),
        ['p', 'w', 'd'],
        "a repeated line is kept once"
    );
    editor.key(Key::Up, &mut sink);
    assert_eq!(editor.line(), ['l', 's']);
    editor.key(Key::Up, &mut sink);
    assert_eq!(editor.line(), ['l', 's'], "no older entry");
    editor.key(Key::Down, &mut sink);
    editor.key(Key::Down, &mut sink);
    assert_eq!(editor.line(), ['e', 'c']);
    assert_eq!(live(&sink.screen, 3), "ec");
    editor.key(Key::Up, &mut sink);
    assert_eq!(
        live(&sink.screen, 3),
        "pwd",
        "the shorter line erased the longer one"
    );
}

#[test]
fn ctrl_keys_clear_drop_and_end() {
    let mut editor = Box::new(LineEditor::new());
    let mut sink = Record::default();
    type_str(&mut editor, &mut sink, "oops");
    editor.key(Key::Ctrl('u'), &mut sink);
    assert_eq!(live(&sink.screen, 0), "");
    type_str(&mut editor, &mut sink, "sleep");
    editor.key(Key::Ctrl('c'), &mut sink);
    assert_eq!(live(&sink.screen, 0), "sleep^C");
    assert_eq!(
        sink.sent, b"\n",
        "Ctrl-C sends a bare newline so the shell prompts"
    );
    type_str(&mut editor, &mut sink, "part");
    editor.key(Key::Ctrl('d'), &mut sink);
    assert_eq!(
        sink.sent, b"\npart",
        "Ctrl-D sends a non-empty line without a newline"
    );
    assert_eq!(sink.ends, 0);
    editor.key(Key::Ctrl('d'), &mut sink);
    assert_eq!(sink.ends, 1, "Ctrl-D on an empty line ends the input");
}

#[test]
fn the_line_holds_at_most_its_capacity() {
    let mut editor = Box::new(LineEditor::new());
    let mut sink = Record::default();
    for _ in 0..crate::line::LINE_CAPACITY + 10 {
        editor.key(Key::Char('a'), &mut sink);
    }
    assert_eq!(editor.line().len(), crate::line::LINE_CAPACITY);
    editor.key(Key::Char('\u{7}'), &mut sink);
    assert_eq!(editor.line().len(), crate::line::LINE_CAPACITY);
}

// ---- keys -----------------------------------------------------------------------------------

fn mods(bits: u16) -> Modifiers {
    Modifiers::from_bits(bits).expect("modifier bits")
}

#[test]
fn keys_map_to_edits() {
    let none = mods(0);
    let shift = mods(Modifiers::SHIFT);
    let ctrl = mods(Modifiers::CTRL);
    let edit = |k| Some(Action::Edit(k));
    assert_eq!(action(KeyUsage(0x04), none, false), edit(Key::Char('a')));
    assert_eq!(action(KeyUsage(0x04), shift, false), edit(Key::Char('A')));
    assert_eq!(action(KeyUsage(0x1E), shift, false), edit(Key::Char('!')));
    assert_eq!(action(KeyUsage(0x06), ctrl, false), edit(Key::Ctrl('c')));
    assert_eq!(action(KeyUsage(0x28), none, false), edit(Key::Enter));
    assert_eq!(action(KeyUsage(0x2A), none, false), edit(Key::Backspace));
    assert_eq!(action(KeyUsage(0x52), none, false), edit(Key::Up));
    assert_eq!(
        action(KeyUsage(0x4B), shift, false),
        Some(Action::ScrollBack)
    );
    assert_eq!(
        action(KeyUsage(0x4E), shift, false),
        Some(Action::ScrollForward)
    );
    assert_eq!(action(KeyUsage(0x4B), none, false), None);
    assert_eq!(
        action(KeyUsage(0xE1), none, false),
        None,
        "a modifier alone"
    );
}

#[test]
fn with_text_events_printable_keys_are_left_to_them() {
    let none = mods(0);
    assert_eq!(action(KeyUsage(0x04), none, true), None);
    assert_eq!(
        action(KeyUsage(0x28), none, true),
        Some(Action::Edit(Key::Enter))
    );
    assert_eq!(
        action(KeyUsage(0x06), mods(Modifiers::CTRL), true),
        Some(Action::Edit(Key::Ctrl('c')))
    );
}

// ---- terminal -------------------------------------------------------------------------------

#[test]
fn a_bare_newline_from_the_stream_also_returns_the_cursor() {
    let mut t = Box::new(Terminal::new());
    t.output(b"hello\nworld\r\n");
    assert_eq!(live(t.screen(), 0), "hello");
    assert_eq!(live(t.screen(), 1), "world");
    assert_eq!(t.screen().cursor(), (2, 0));
}

#[test]
fn the_terminal_queues_lines_for_the_stream() {
    let mut t = Box::new(Terminal::new());
    t.output(b"~ # ");
    for usage in [0x08, 0x06, 0x0B, 0x12] {
        t.key(KeyUsage(usage), mods(0));
    }
    t.key(KeyUsage(0x28), mods(0));
    assert_eq!(t.pending_input(), b"echo\n");
    assert_eq!(live(t.screen(), 0), "~ # echo");
    t.consume_input(2);
    assert_eq!(t.pending_input(), b"ho\n");
    t.text("é");
    t.key(KeyUsage(0x07), mods(Modifiers::CTRL));
    assert!(!t.end_pending(), "Ctrl-D on a non-empty line pushes it");
    t.key(KeyUsage(0x07), mods(Modifiers::CTRL));
    assert!(t.end_pending());
    t.consume_end();
    assert!(!t.end_pending());
    assert_eq!(t.pending_input(), "ho\né".as_bytes());
}

#[test]
fn typing_returns_a_scrolled_view_to_the_live_screen() {
    let mut t = Box::new(Terminal::new());
    for line in 0..ROWS * 2 {
        t.output(std::format!("{line}\r\n").as_bytes());
    }
    t.key(KeyUsage(0x4B), mods(Modifiers::SHIFT));
    assert_eq!(t.screen().view_offset(), ROWS / 2);
    t.key(KeyUsage(0x04), mods(0));
    assert_eq!(t.screen().view_offset(), 0);
}

// ---- rendering ------------------------------------------------------------------------------

fn pixels() -> Vec<u8> {
    vec![0u8; buffer_layout().expect("layout").byte_len()]
}

fn paint_all(screen: &Screen, focused: bool) -> Vec<u8> {
    let layout = buffer_layout().expect("layout");
    let mut bytes = pixels();
    let mut canvas = Canvas::new(&mut bytes, layout).expect("canvas");
    render::paint_rows(&mut canvas, screen, (1 << ROWS) - 1, focused);
    bytes
}

fn rgb_at(bytes: &[u8], x: i32, y: i32) -> [u8; 3] {
    let layout = buffer_layout().expect("layout");
    let px = pixel_at(bytes, layout, x as u32, y as u32).expect("pixel");
    // Xrgb8888 little endian: B, G, R, X.
    [px[2], px[1], px[0]]
}

fn rgb(c: clean_slate_raster::Color) -> [u8; 3] {
    [c.0[2], c.0[1], c.0[0]]
}

#[test]
fn the_window_fits_the_grid() {
    assert_eq!(render::font_cell(), (8, 16));
    assert_eq!(
        WINDOW_SIZE,
        Size {
            width: 652,
            height: 412
        }
    );
    let last = render::row_rect(ROWS - 1);
    assert_eq!(last.y as u32 + last.height, WINDOW_SIZE.height);
}

#[test]
fn the_cursor_is_a_block_when_focused_and_an_outline_when_not() {
    let s = screen();
    let cell = cell_rect(0, 0);
    let focused = paint_all(&s, true);
    assert_eq!(rgb_at(&focused, cell.x + 3, cell.y + 8), rgb(CURSOR));
    let unfocused = paint_all(&s, false);
    assert_eq!(rgb_at(&unfocused, cell.x, cell.y), rgb(CURSOR));
    assert_eq!(rgb_at(&unfocused, cell.x + 3, cell.y + 8), rgb(DEFAULT_BG));
}

#[test]
fn a_coloured_background_fills_its_cell() {
    let mut s = screen();
    feed(&mut s, b"\x1b[41m \x1b[0m");
    let bytes = paint_all(&s, true);
    let cell = cell_rect(0, 0);
    let (_, bg) = colors(s.live_row(0)[0].attr);
    assert_eq!(rgb_at(&bytes, cell.x + 4, cell.y + 4), rgb(bg));
}

#[test]
fn repainting_dirty_rows_equals_a_full_repaint() {
    let mut s = screen();
    feed(&mut s, b"first line\r\n\x1b[32msecond\x1b[0m");
    let layout = buffer_layout().expect("layout");
    let mut incremental = paint_all(&s, true);
    s.take_dirty();
    feed(&mut s, b"\x1b[1;7HXY\x1b[3;1Hthird");
    let dirty = s.take_dirty();
    assert_ne!(dirty, (1 << ROWS) - 1);
    {
        let mut canvas = Canvas::new(&mut incremental, layout).expect("canvas");
        render::paint_rows(&mut canvas, &s, dirty, true);
    }
    assert!(incremental == paint_all(&s, true));
}

// ---- session --------------------------------------------------------------------------------

struct FakeHost {
    sent: Vec<Request>,
    buffers: [Vec<u8>; 2],
    fail: bool,
}

impl FakeHost {
    fn new() -> Self {
        Self {
            sent: Vec::new(),
            buffers: [pixels(), pixels()],
            fail: false,
        }
    }

    fn take(&mut self) -> Vec<Request> {
        core::mem::take(&mut self.sent)
    }
}

impl Host for FakeHost {
    fn send(&mut self, request: &Request, _transfer: Option<BufferSlot>) -> Result<(), HostError> {
        if self.fail {
            return Err(HostError::Gone);
        }
        self.sent.push(*request);
        Ok(())
    }

    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]> {
        self.buffers
            .get_mut(usize::from(slot.0))
            .map(Vec::as_mut_slice)
    }
}

fn object(slot: u32) -> ObjectId {
    ObjectId::decode((1 << 8) | slot).expect("object id")
}

fn buffer(slot: u32) -> ClientBufferId {
    ClientBufferId(object(slot))
}

const SURFACE_SLOT: u32 = 5;
const WINDOW_SLOT: u32 = 6;

fn surface() -> SurfaceId {
    SurfaceId(object(SURFACE_SLOT))
}

fn window() -> WindowId {
    WindowId(object(WINDOW_SLOT))
}

fn welcome() -> Event {
    Event::Welcome {
        version: ProtocolVersion { major: 1, minor: 0 },
        features: Features(0),
        output: OutputInfo {
            id: OutputId::decode(1 << 8).expect("output id"),
            mode: REFERENCE_MODE,
            logical_size: Size {
                width: 1280,
                height: 800,
            },
        },
    }
}

fn configure(serial: u32, active: bool) -> Event {
    Event::Configure {
        window: window(),
        serial: Serial(serial),
        size: WINDOW_SIZE,
        scale: Scale120::ONE,
        decoration: DecorationMode::Server,
        states: WindowStates::from_bits(if active { WindowStates::ACTIVATED } else { 0 })
            .expect("states"),
        bounds: WINDOW_SIZE,
    }
}

fn running() -> (Box<Session>, FakeHost) {
    let mut session = Box::new(Session::new());
    let mut host = FakeHost::new();
    assert_eq!(session.start(&mut host), Outcome::Continue);
    for event in [
        welcome(),
        Event::BufferRegistered { buffer: buffer(1) },
        Event::BufferRegistered { buffer: buffer(2) },
        Event::SurfaceCreated { surface: surface() },
        Event::WindowCreated { window: window() },
        configure(1, true),
    ] {
        assert_eq!(session.handle(&event, &mut host), Outcome::Continue);
    }
    assert!(session.is_running());
    (session, host)
}

fn press(usage: u16) -> Event {
    Event::Key {
        serial: Serial(1),
        time_ns: 0,
        usage: KeyUsage(usage),
        state: KeyState::Pressed,
        modifiers: mods(0),
    }
}

#[test]
fn the_session_maps_a_fixed_size_window() {
    let (session, mut host) = running();
    let sent = host.take();
    assert!(matches!(sent[0], Request::Hello { .. }));
    assert!(sent.iter().any(|r| matches!(
        r,
        Request::SetSizeLimits { min, max, .. } if *min == WINDOW_SIZE && *max == WINDOW_SIZE
    )));
    assert!(sent.iter().any(|r| matches!(r, Request::Show { .. })));
    assert_eq!(session.busy(), [true, false]);
    assert!(session.terminal().focused());
}

#[test]
fn output_commits_only_the_rows_it_changed() {
    let (mut session, mut host) = running();
    host.take();
    assert_eq!(
        session.output(b"\x1b[4;1Hhello", &mut host),
        Outcome::Continue
    );
    let sent = host.take();
    let damage: Vec<_> = sent
        .iter()
        .filter_map(|r| match r {
            Request::Damage { rects, count, .. } => Some(rects[..usize::from(*count)].to_vec()),
            _ => None,
        })
        .flatten()
        .collect();
    let rows = [render::row_rect(0), render::row_rect(3)];
    assert_eq!(damage.len(), 2);
    assert!(damage.iter().all(|d| rows
        .iter()
        .any(|r| r.y as u32 == u32::from(d.y) && r.height == u32::from(d.height))));
    assert!(matches!(sent.last(), Some(Request::Commit { .. })));
    assert_eq!(session.busy(), [true, true]);
}

#[test]
fn a_change_with_both_buffers_busy_waits_for_a_release() {
    let (mut session, mut host) = running();
    session.output(b"a", &mut host);
    host.take();
    session.output(b"b", &mut host);
    assert!(host.take().is_empty());
    assert_eq!(session.stats().deferred, 1);
    session.handle(&Event::BufferReleased { buffer: buffer(1) }, &mut host);
    assert!(matches!(host.take().last(), Some(Request::Commit { .. })));
}

#[test]
fn keys_type_only_while_focused() {
    let (mut session, mut host) = running();
    session.handle(&press(0x04), &mut host);
    assert_eq!(live(session.terminal().screen(), 0), "a");
    session.handle(&Event::KeyboardFocus { surface: None }, &mut host);
    session.handle(&press(0x05), &mut host);
    assert_eq!(live(session.terminal().screen(), 0), "a");
    session.handle(
        &Event::KeyboardFocus {
            surface: Some(surface()),
        },
        &mut host,
    );
    session.handle(&press(0x28), &mut host);
    assert_eq!(session.terminal().pending_input(), b"a\n");
}

#[test]
fn close_destroys_everything_and_exits() {
    let (mut session, mut host) = running();
    host.take();
    let outcome = session.handle(&Event::CloseRequested { window: window() }, &mut host);
    assert_eq!(outcome, Outcome::Exit(ExitReason::Closed));
    let sent = host.take();
    assert!(matches!(sent[0], Request::DestroyWindow { .. }));
    assert!(matches!(sent[1], Request::DestroySurface { .. }));
    assert_eq!(
        sent.iter()
            .filter(|r| matches!(r, Request::UnregisterBuffer { .. }))
            .count(),
        2
    );
}

#[test]
fn a_compositor_that_is_gone_ends_the_session() {
    let (mut session, mut host) = running();
    host.fail = true;
    assert_eq!(
        session.output(b"x", &mut host),
        Outcome::Exit(ExitReason::HostFailed(HostError::Gone))
    );
}
