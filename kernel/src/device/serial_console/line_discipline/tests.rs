use std::vec::Vec;

use super::*;

#[derive(Default)]
struct Captured(Vec<u8>);

impl EchoSink for Captured {
    fn echo(&mut self, bytes: &[u8]) {
        self.0.extend_from_slice(bytes);
    }
}

/// Feeds `input` and returns the echo it produced.
fn feed(discipline: &mut LineDiscipline, input: &[u8]) -> Vec<u8> {
    let mut echo = Captured::default();
    for byte in input {
        discipline.feed(*byte, &mut echo);
    }
    echo.0
}

/// One read with a buffer of `size` bytes.
fn read(discipline: &mut LineDiscipline, size: usize) -> Vec<u8> {
    let mut buffer = std::vec![0u8; size];
    let copied = discipline.read(&mut buffer);
    buffer.truncate(copied);
    buffer
}

fn fresh() -> std::boxed::Box<LineDiscipline> {
    std::boxed::Box::new(LineDiscipline::new())
}

#[test]
fn printable_bytes_are_echoed_and_cr_commits_with_a_newline() {
    let mut discipline = fresh();
    assert_eq!(feed(&mut discipline, b"hi there"), b"hi there");
    assert!(discipline.would_block(), "an edit line is not readable");
    assert!(!discipline.take_wake());
    assert_eq!(feed(&mut discipline, b"\r"), b"\r\n");
    assert!(discipline.take_wake());
    assert!(!discipline.take_wake(), "the wake is taken once");
    assert!(!discipline.would_block());
    assert_eq!(read(&mut discipline, 64), b"hi there\n");
    assert!(discipline.would_block());
    assert_eq!(discipline.stats().lines, 1);
}

#[test]
fn lf_commits_like_cr_and_an_empty_line_is_a_lone_newline() {
    let mut discipline = fresh();
    assert_eq!(feed(&mut discipline, b"a\n\r"), b"a\r\n\r\n");
    assert_eq!(read(&mut discipline, 64), b"a\n");
    assert_eq!(read(&mut discipline, 64), b"\n");
    assert_eq!(read(&mut discipline, 64), b"");
    assert_eq!(discipline.stats().lines, 2);
}

#[test]
fn delete_and_backspace_erase_one_byte_and_do_nothing_on_an_empty_line() {
    let mut discipline = fresh();
    assert_eq!(feed(&mut discipline, b"\x08\x7f"), b"", "nothing to erase");
    assert_eq!(
        feed(&mut discipline, b"cat\x7f\x08ow\r"),
        b"cat\x08 \x08\x08 \x08ow\r\n"
    );
    assert_eq!(read(&mut discipline, 64), b"cow\n");
    assert_eq!(feed(&mut discipline, b"x\x08\x08\x08\r"), b"x\x08 \x08\r\n");
    assert_eq!(read(&mut discipline, 64), b"\n");
}

#[test]
fn ctrl_u_kills_the_edit_line_and_erases_it_on_screen() {
    let mut discipline = fresh();
    assert_eq!(
        feed(&mut discipline, b"\x15"),
        b"",
        "an empty kill echoes nothing"
    );
    assert_eq!(
        feed(&mut discipline, b"junk\x15ok\r"),
        b"junk\x08 \x08\x08 \x08\x08 \x08\x08 \x08ok\r\n"
    );
    assert_eq!(read(&mut discipline, 64), b"ok\n");
}

#[test]
fn other_control_bytes_and_non_ascii_are_dropped_without_echo() {
    let mut discipline = fresh();
    assert_eq!(
        feed(&mut discipline, b"o\x01\x1b\x03\x00\x80\xffk\t\r"),
        b"ok\r\n"
    );
    assert_eq!(read(&mut discipline, 64), b"ok\n");
    assert_eq!(discipline.stats().control_dropped, 7);
}

#[test]
fn ctrl_d_on_an_empty_line_gives_one_end_of_file() {
    let mut discipline = fresh();
    assert_eq!(feed(&mut discipline, b"\x04"), b"", "Ctrl-D echoes nothing");
    assert!(discipline.take_wake());
    assert!(
        !discipline.would_block(),
        "a pending end-of-file is readable"
    );
    assert_eq!(
        read(&mut discipline, 64),
        b"",
        "read never consumes the end-of-file"
    );
    assert!(discipline.take_eof());
    assert!(!discipline.take_eof(), "exactly one end-of-file");
    assert!(discipline.would_block());
    assert_eq!(discipline.stats().eofs, 1);
}

#[test]
fn ctrl_d_on_a_non_empty_line_commits_it_without_a_newline_and_bounds_the_read() {
    let mut discipline = fresh();
    assert_eq!(feed(&mut discipline, b"part\x04"), b"part");
    assert!(discipline.take_wake());
    assert_eq!(feed(&mut discipline, b"next\r"), b"next\r\n");
    assert_eq!(
        read(&mut discipline, 64),
        b"part",
        "the read stops at the pushed line"
    );
    assert!(
        !discipline.take_eof(),
        "a pushed line is not an end-of-file"
    );
    assert_eq!(read(&mut discipline, 64), b"next\n");
    assert_eq!(discipline.stats().lines, 2);
    assert_eq!(discipline.stats().eofs, 0);
}

#[test]
fn a_second_ctrl_d_while_one_end_of_file_is_unread_is_dropped_and_counted() {
    let mut discipline = fresh();
    feed(&mut discipline, b"\x04\x04");
    assert_eq!(discipline.stats().eofs, 1);
    assert_eq!(discipline.stats().eof_dropped, 1);
    assert!(discipline.take_eof());
    feed(&mut discipline, b"\x04");
    assert!(
        discipline.take_eof(),
        "after the first is taken, Ctrl-D counts again"
    );
}

#[test]
fn end_of_file_is_ordered_after_lines_typed_before_it_and_before_lines_typed_after() {
    let mut discipline = fresh();
    feed(&mut discipline, b"one\r\x04two\r");
    assert!(!discipline.take_eof(), "line one comes first");
    assert_eq!(read(&mut discipline, 64), b"one\n");
    assert_eq!(
        read(&mut discipline, 64),
        b"",
        "the end-of-file stops the read"
    );
    assert!(!discipline.would_block());
    assert!(discipline.take_eof());
    assert_eq!(read(&mut discipline, 64), b"two\n");
    assert!(discipline.would_block());
}

#[test]
fn a_read_stops_after_each_newline_even_with_room_for_more() {
    let mut discipline = fresh();
    feed(&mut discipline, b"one\rtwo\rthree\r");
    assert_eq!(read(&mut discipline, 64), b"one\n");
    assert_eq!(read(&mut discipline, 64), b"two\n");
    assert_eq!(read(&mut discipline, 64), b"three\n");
    assert_eq!(read(&mut discipline, 64), b"");
}

#[test]
fn a_small_buffer_splits_a_line_across_reads_without_losing_bytes() {
    let mut discipline = fresh();
    feed(&mut discipline, b"abcdefg\rxy\r");
    assert_eq!(read(&mut discipline, 3), b"abc");
    assert_eq!(read(&mut discipline, 3), b"def");
    assert_eq!(
        read(&mut discipline, 3),
        b"g\n",
        "the split read still stops at the newline"
    );
    assert_eq!(read(&mut discipline, 3), b"xy\n");
    assert_eq!(
        read(&mut discipline, 0),
        b"",
        "an empty buffer reads nothing"
    );
}

#[test]
fn a_split_read_counts_down_to_a_pending_end_of_file() {
    let mut discipline = fresh();
    feed(&mut discipline, b"abcdef\r\x04");
    assert_eq!(read(&mut discipline, 4), b"abcd");
    assert!(!discipline.take_eof());
    assert_eq!(read(&mut discipline, 4), b"ef\n");
    assert!(discipline.take_eof());
}

#[test]
fn an_overlong_line_keeps_its_first_256_bytes_and_counts_the_rest() {
    let mut discipline = fresh();
    let echo = feed(&mut discipline, &[b'x'; 300]);
    assert_eq!(echo, std::vec![b'x'; 256], "refused bytes are not echoed");
    assert_eq!(discipline.stats().edit_overflow, 44);
    assert_eq!(
        feed(&mut discipline, b"\x7fy"),
        b"\x08 \x08y",
        "erase still works on a full edit line"
    );
    assert_eq!(feed(&mut discipline, b"\r"), b"\r\n");
    let mut expected = std::vec![b'x'; 255];
    expected.extend_from_slice(b"y\n");
    assert_eq!(expected.len(), EDIT_CAPACITY + 1);
    assert_eq!(read(&mut discipline, 1024), expected);
}

#[test]
fn a_full_pushed_line_is_256_bytes() {
    let mut discipline = fresh();
    feed(&mut discipline, &[b'p'; 257]);
    feed(&mut discipline, b"\x04");
    assert_eq!(read(&mut discipline, 1024), std::vec![b'p'; 256]);
    assert_eq!(discipline.stats().edit_overflow, 1);
}

#[test]
fn ctrl_u_on_a_full_line_erases_every_byte() {
    let mut discipline = fresh();
    feed(&mut discipline, &[b'k'; 300]);
    let echo = feed(&mut discipline, b"\x15");
    assert_eq!(echo, ECHO_ERASE.repeat(EDIT_CAPACITY));
    assert_eq!(feed(&mut discipline, b"\r"), b"\r\n");
    assert_eq!(read(&mut discipline, 64), b"\n");
}

/// Eight 127-byte lines plus newline: exactly [`COMMITTED_CAPACITY`].
fn fill_committed(discipline: &mut LineDiscipline) {
    for letter in b'A'..=b'H' {
        let mut line = std::vec![letter; 127];
        line.push(b'\r');
        feed(discipline, &line);
    }
    assert_eq!(discipline.committed_len(), COMMITTED_CAPACITY);
    assert!(!discipline.has_deferred_line());
}

#[test]
fn a_line_that_does_not_fit_waits_whole_and_later_input_is_refused() {
    let mut discipline = fresh();
    fill_committed(&mut discipline);
    discipline.take_wake();
    assert_eq!(
        feed(&mut discipline, b"ninth\r"),
        b"ninth\r\n",
        "the line is accepted"
    );
    assert!(discipline.has_deferred_line());
    assert!(!discipline.take_wake(), "nothing new is readable yet");
    assert_eq!(discipline.stats().deferred, 1);
    assert_eq!(
        feed(&mut discipline, b"lost\x7f\x15\x04\r"),
        b"",
        "every byte is refused, editing and Ctrl-D included"
    );
    assert_eq!(discipline.stats().dropped_while_deferred, 8);

    assert_eq!(
        read(&mut discipline, 1024),
        [b'A'; 127]
            .iter()
            .copied()
            .chain([b'\n'])
            .collect::<Vec<_>>()
    );
    assert!(!discipline.has_deferred_line(), "the first read made room");
    assert!(
        discipline.take_wake(),
        "the deferred commit wakes other readers"
    );
    for letter in b'B'..=b'H' {
        let mut expected = std::vec![letter; 127];
        expected.push(b'\n');
        assert_eq!(read(&mut discipline, 1024), expected);
    }
    assert_eq!(read(&mut discipline, 1024), b"ninth\n");
    assert_eq!(
        feed(&mut discipline, b"ok\r"),
        b"ok\r\n",
        "input is accepted again"
    );
    assert_eq!(read(&mut discipline, 1024), b"ok\n");
    assert_eq!(discipline.stats().lines, 10);
}

#[test]
fn a_line_typed_while_the_committed_buffer_is_full_is_kept_and_editable() {
    let mut discipline = fresh();
    fill_committed(&mut discipline);
    assert_eq!(
        feed(&mut discipline, b"partly\x7f"),
        b"partly\x08 \x08",
        "a full committed buffer does not stop editing"
    );
    assert!(!discipline.has_deferred_line());
    assert_eq!(read(&mut discipline, 1024).len(), 128);
    assert_eq!(feed(&mut discipline, b"\r"), b"\r\n");
    assert!(!discipline.has_deferred_line(), "the freed space holds it");
    for _ in 0..7 {
        assert_eq!(read(&mut discipline, 1024).len(), 128);
    }
    assert_eq!(read(&mut discipline, 1024), b"partl\n");
    assert_eq!(discipline.stats().dropped_while_deferred, 0);
}

#[test]
fn a_deferred_line_waits_until_the_whole_line_fits() {
    let mut discipline = fresh();
    fill_committed(&mut discipline);
    feed(&mut discipline, &[b'z'; 200]);
    feed(&mut discipline, b"\r");
    assert!(discipline.has_deferred_line());
    assert_eq!(read(&mut discipline, 1024).len(), 128);
    assert!(
        discipline.has_deferred_line(),
        "128 free bytes do not hold 201"
    );
    assert_eq!(read(&mut discipline, 1024).len(), 128);
    assert!(!discipline.has_deferred_line(), "256 free bytes do");
    assert_eq!(discipline.committed_len(), 6 * 128 + 201);
}

#[test]
fn a_line_that_exactly_fills_the_remaining_space_commits() {
    let mut discipline = fresh();
    for _ in 0..4 {
        feed(&mut discipline, &[b'q'; 254]);
        feed(&mut discipline, b"\r");
    }
    assert_eq!(discipline.committed_len(), 1020);
    feed(&mut discipline, b"abc\r");
    assert_eq!(discipline.committed_len(), COMMITTED_CAPACITY);
    assert!(!discipline.has_deferred_line());
    feed(&mut discipline, b"\r");
    assert!(
        discipline.has_deferred_line(),
        "even an empty line needs one byte"
    );
}

#[test]
fn end_of_file_needs_no_committed_space() {
    let mut discipline = fresh();
    fill_committed(&mut discipline);
    feed(&mut discipline, b"\x04");
    assert_eq!(discipline.stats().eofs, 1);
    for _ in 0..8 {
        assert_eq!(read(&mut discipline, 1024).len(), 128);
    }
    assert!(discipline.take_eof());
}

#[test]
fn the_ring_wraps_and_pushed_line_ends_survive_the_wrap() {
    let mut discipline = fresh();
    for round in 0..50u8 {
        let letter = b'a' + round % 26;
        let mut line = std::vec![letter; 99];
        feed(&mut discipline, &line);
        feed(&mut discipline, b"\x04");
        line.clear();
        line.extend_from_slice(&[letter; 9]);
        feed(&mut discipline, &line);
        feed(&mut discipline, b"\r");
        assert_eq!(read(&mut discipline, 1024), std::vec![letter; 99]);
        let mut expected = std::vec![letter; 9];
        expected.push(b'\n');
        assert_eq!(read(&mut discipline, 1024), expected);
    }
    assert!(discipline.would_block());
    assert_eq!(discipline.stats().lines, 100);
}

#[test]
fn would_block_tracks_committed_bytes_and_the_end_of_file() {
    let mut discipline = fresh();
    assert!(discipline.would_block());
    feed(&mut discipline, b"partial");
    assert!(discipline.would_block());
    feed(&mut discipline, b"\r");
    assert!(!discipline.would_block());
    read(&mut discipline, 64);
    assert!(discipline.would_block());
    feed(&mut discipline, b"\x04");
    assert!(!discipline.would_block());
    discipline.take_eof();
    assert!(discipline.would_block());
}
