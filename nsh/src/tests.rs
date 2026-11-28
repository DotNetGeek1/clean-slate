use alloc::string::{String, ToString};
use alloc::vec::Vec;

use clean_slate_native_abi::console::{ConsoleBytes, ConsoleEvent, ConsoleRequest};
use clean_slate_runtime::console::ConsoleStream;
use clean_slate_runtime::fake::FakeKernel;

use crate::builtins::CLEAR_SCREEN;
use crate::parse::{parse, ErrorKind, Part, SyntaxError};
use crate::session::{run_session, End, Line, LineBuffer, LINE_MAX};
use crate::shell::{Command, Context, Output, Programs, Shell, Status};

const PID: u64 = 42;

/// Runs `line` on `shell` and returns its output.
fn run(shell: &mut Shell, line: &str) -> String {
    let mut out = Vec::new();
    shell.run_line(line, &mut out);
    String::from_utf8(out).unwrap()
}

fn one(line: &str) -> (String, Status) {
    let mut shell = Shell::new(PID);
    let out = run(&mut shell, line);
    (out, shell.state.status)
}

fn words(line: &str) -> Vec<Vec<Vec<Part>>> {
    parse(line)
        .unwrap()
        .chains
        .into_iter()
        .flat_map(|chain| chain.commands)
        .map(|command| command.into_iter().map(|word| word.parts).collect())
        .collect()
}

fn lit(text: &str) -> Part {
    Part::Literal(text.to_string())
}

fn error(line: &str) -> SyntaxError {
    parse(line).unwrap_err()
}

#[test]
fn words_split_on_blanks_and_quotes_join_them() {
    assert_eq!(
        words("echo  a\tb 'c d' \"e  f\" g'h'\"i\""),
        [[
            vec![lit("echo")],
            vec![lit("a")],
            vec![lit("b")],
            vec![lit("c d")],
            vec![lit("e  f")],
            vec![lit("ghi")],
        ]]
    );
}

#[test]
fn escapes_and_quotes_keep_their_characters() {
    assert_eq!(words(r"a\ b"), [[vec![lit("a b")]]]);
    assert_eq!(words(r"'a\b$c'"), [[vec![lit(r"a\b$c")]]]);
    assert_eq!(words(r#""a\"b\\c\$d\e""#), [[vec![lit(r#"a"b\c$d\e"#)]]]);
    assert_eq!(words(r"\;"), [[vec![lit(";")]]]);
    assert_eq!(words("'a;b&&c'"), [[vec![lit("a;b&&c")]]]);
}

#[test]
fn dollar_forms_become_parts() {
    assert_eq!(
        words("$A x$B_1y ${C}z \"$?-$$\" $ $1 a$"),
        [[
            vec![Part::Var("A".to_string())],
            vec![lit("x"), Part::Var("B_1y".to_string())],
            vec![Part::Var("C".to_string()), lit("z")],
            vec![Part::Status, lit("-"), Part::Pid],
            vec![lit("$")],
            vec![lit("$1")],
            vec![lit("a$")],
        ]]
    );
}

#[test]
fn separators_make_chains() {
    let script = parse("a; b && c ;d;").unwrap();
    let shape: Vec<usize> = script
        .chains
        .iter()
        .map(|chain| chain.commands.len())
        .collect();
    assert_eq!(shape, [1, 2, 1]);
    assert!(parse("").unwrap().chains.is_empty());
    assert!(parse("   # only a comment").unwrap().chains.is_empty());
    assert_eq!(
        words("echo a#b # c"),
        [[vec![lit("echo")], vec![lit("a#b")]]]
    );
    assert_eq!(words("a;b"), [[vec![lit("a")]], [vec![lit("b")]]]);
}

#[test]
fn syntax_errors_name_the_column() {
    let cases: [(&str, ErrorKind, usize); 12] = [
        ("echo 'abc", ErrorKind::UnterminatedSingleQuote, 6),
        ("echo \"ab'c", ErrorKind::UnterminatedDoubleQuote, 6),
        ("echo abc\\", ErrorKind::TrailingBackslash, 9),
        ("echo ${A", ErrorKind::UnterminatedBrace, 6),
        ("echo ${1A}", ErrorKind::BadSubstitution, 6),
        ("; echo", ErrorKind::MissingCommandBefore(";"), 1),
        ("a;; b", ErrorKind::MissingCommandBefore(";"), 3),
        ("&& a", ErrorKind::MissingCommandBefore("&&"), 1),
        ("a &&", ErrorKind::MissingCommandAfter("&&"), 3),
        ("a && ; b", ErrorKind::MissingCommandAfter("&&"), 3),
        ("ls | wc", ErrorKind::Unsupported('|'), 4),
        ("sleep 1 &", ErrorKind::Unsupported('&'), 9),
    ];
    for (line, kind, column) in cases {
        assert_eq!(error(line), SyntaxError { kind, column }, "{line:?}");
    }
    assert_eq!(error("echo é '").column, 8, "columns count characters");
    assert_eq!(error("a > b").kind, ErrorKind::Unsupported('>'));
    assert_eq!(
        one("echo 'abc"),
        (
            "nsh: syntax error at column 6: unterminated single quote\n".to_string(),
            2
        )
    );
}

#[test]
fn echo_prints_its_words() {
    assert_eq!(one("echo hello world"), ("hello world\n".to_string(), 0));
    assert_eq!(one("echo"), ("\n".to_string(), 0));
    assert_eq!(one("echo -n a b"), ("a b".to_string(), 0));
    assert_eq!(one("echo 'a  b'   c"), ("a  b c\n".to_string(), 0));
}

#[test]
fn pid_and_status_expand() {
    assert_eq!(one("echo hello-$$").0, "hello-42\n");
    let mut shell = Shell::new(PID);
    assert_eq!(run(&mut shell, "false; echo $?"), "1\n");
    assert_eq!(run(&mut shell, "echo $?"), "0\n");
    assert_eq!(
        run(&mut shell, "nope; echo \"st=$?\""),
        "nsh: nope: command not found\nst=127\n"
    );
    assert_eq!(
        run(&mut shell, "echo 'a"),
        "nsh: syntax error at column 6: unterminated single quote\n"
    );
    assert_eq!(run(&mut shell, "echo $?"), "2\n");
}

#[test]
fn variables_set_expand_and_unset() {
    let mut shell = Shell::new(PID);
    assert_eq!(run(&mut shell, "set NAME=world GREETING='hi there'"), "");
    assert_eq!(
        run(&mut shell, "echo $GREETING, ${NAME}!"),
        "hi there, world!\n"
    );
    assert_eq!(run(&mut shell, "echo '$NAME' \"$NAME\""), "$NAME world\n");
    assert_eq!(run(&mut shell, "X=1 Y=$NAME"), "");
    assert_eq!(run(&mut shell, "echo $X$Y"), "1world\n");
    assert_eq!(
        run(&mut shell, "set"),
        "GREETING=hi there\nNAME=world\nPS1=$ \nX=1\nY=world\n"
    );
    assert_eq!(run(&mut shell, "unset X Y GREETING; echo [$X]"), "[]\n");
    // An unquoted word that expands to nothing is dropped, a quoted one kept.
    assert_eq!(run(&mut shell, "echo a $X b \"$X\" c"), "a b  c\n");
    assert_eq!(
        run(&mut shell, "set 1x=2"),
        "nsh: set: not NAME=value: 1x=2\n"
    );
    assert_eq!(shell.state.status, 2);
    assert_eq!(
        run(&mut shell, "set A=1 bad"),
        "nsh: set: not NAME=value: bad\n"
    );
    assert_eq!(shell.state.var("A"), None, "a bad word sets nothing");
    assert_eq!(run(&mut shell, "unset"), "nsh: unset: name a variable\n");
    assert_eq!(
        run(&mut shell, "unset a-b"),
        "nsh: unset: not a variable name: a-b\n"
    );
    // A quoted `=` word is a command name, not an assignment.
    assert_eq!(run(&mut shell, "'A=1'"), "nsh: A=1: command not found\n");
}

#[test]
fn and_runs_only_after_success_and_semicolon_always() {
    let mut shell = Shell::new(PID);
    assert_eq!(run(&mut shell, "true && echo yes"), "yes\n");
    assert_eq!(run(&mut shell, "false && echo no"), "");
    assert_eq!(shell.state.status, 1);
    assert_eq!(
        run(&mut shell, "false && echo no; echo after $?"),
        "after 1\n"
    );
    assert_eq!(run(&mut shell, "true && false && echo no"), "");
    assert_eq!(run(&mut shell, "echo a; echo b && echo c"), "a\nb\nc\n");
}

#[test]
fn exit_stops_the_line_with_its_status() {
    let mut shell = Shell::new(PID);
    assert_eq!(run(&mut shell, "echo a; exit 3; echo b"), "a\n");
    assert_eq!(shell.exit_requested(), Some(3));
    let mut shell = Shell::new(PID);
    run(&mut shell, "false; exit");
    assert_eq!(shell.exit_requested(), Some(1));
    let mut shell = Shell::new(PID);
    assert_eq!(
        run(&mut shell, "exit 256"),
        "nsh: exit: bad status 256 (want 0-255)\n"
    );
    assert_eq!(
        run(&mut shell, "exit 1 2"),
        "nsh: exit: too many arguments\n"
    );
    assert_eq!(shell.exit_requested(), None);
    assert_eq!(shell.state.status, 2);
}

#[test]
fn clear_help_and_history() {
    assert_eq!(one("clear").0.as_bytes(), CLEAR_SCREEN);
    let (help, status) = one("help");
    assert_eq!(status, 0);
    assert!(help.starts_with("Commands:\n"));
    for name in ["echo", "help", "clear", "exit", "set", "unset", "history"] {
        assert!(
            help.contains(&alloc::format!("\n  {name} ")),
            "{name}: {help}"
        );
    }
    assert_eq!(
        one("help exit").0,
        "  exit [status]            end the shell (status 0-255, default $?)\n"
    );
    assert_eq!(
        one("help nope"),
        ("nsh: help: no command nope\n".to_string(), 1)
    );

    let mut shell = Shell::new(PID);
    run(&mut shell, "echo one");
    run(&mut shell, "   ");
    run(&mut shell, "true");
    assert_eq!(
        run(&mut shell, "history"),
        "    1  echo one\n    2  true\n    3  history\n"
    );
    for _ in 0..crate::shell::HISTORY_LINES {
        run(&mut shell, "true");
    }
    let listing = run(&mut shell, "history");
    assert_eq!(listing.lines().count(), crate::shell::HISTORY_LINES);
    assert!(listing.starts_with("    5  true\n"), "{listing}");
}

static EXTRA: &[Command] = &[
    Command {
        name: "greet",
        usage: "NAME",
        summary: "say hello",
        run: |cx: &mut Context<'_>, args: &[String]| {
            cx.out.write_str(&alloc::format!("hello {}\n", args[1]));
            0
        },
    },
    Command {
        name: "echo",
        usage: "",
        summary: "shadowed",
        run: |_, _| 9,
    },
];

#[test]
fn a_registered_group_adds_commands_and_never_shadows_earlier_ones() {
    let mut shell = Shell::new(PID);
    shell.state.commands.register(EXTRA);
    assert_eq!(run(&mut shell, "greet you"), "hello you\n");
    assert_eq!(run(&mut shell, "echo x"), "x\n");
    let help = run(&mut shell, "help");
    assert!(help.contains("greet NAME"));
    assert!(!help.contains("shadowed"));
}

struct Hello;

impl Programs for Hello {
    fn run(&mut self, name: &str, args: &[String], out: &mut dyn Output) -> Option<Status> {
        (name == "hello").then(|| {
            out.write_str(&alloc::format!("argv={args:?}\n"));
            5
        })
    }
}

#[test]
fn unknown_names_go_to_programs() {
    let mut shell = Shell::with_programs(PID, Hello);
    let mut out = Vec::new();
    shell.run_line("hello a 'b c'; echo $?; other", &mut out);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "argv=[\"a\", \"b c\"]\n5\nnsh: other: command not found\n"
    );
    assert_eq!(shell.state.status, 127);
}

#[test]
fn the_line_buffer_splits_lines_and_drops_long_ones() {
    let mut lines = LineBuffer::default();
    let mut done = Vec::new();
    for &byte in b"ab\n\ncd" {
        done.extend(lines.push(byte));
    }
    assert_eq!(
        done,
        [Line::Text("ab".to_string()), Line::Text(String::new())]
    );
    assert_eq!(lines.finish(), Some(Line::Text("cd".to_string())));
    assert_eq!(lines.finish(), None);
    for _ in 0..LINE_MAX + 1 {
        assert_eq!(lines.push(b'x'), None);
    }
    assert_eq!(lines.push(b'\n'), Some(Line::TooLong));
    assert_eq!(lines.push(b'\n'), Some(Line::Text(String::new())));
}

// The console session, over the runtime's fake kernel: the service's answers are posted ahead,
// and everything the shell wrote is read back from its requests.

fn stream(sys: &mut FakeKernel) -> ConsoleStream {
    ConsoleStream::connect(sys).expect("connect")
}

fn input(sys: &mut FakeKernel, bytes: &[u8]) {
    sys.server_post(&ConsoleEvent::Input(ConsoleBytes::new(bytes).unwrap()).encode());
}

/// What the shell wrote, in order.
fn written(sys: &mut FakeKernel) -> String {
    let mut text = Vec::new();
    while let Some(frame) = sys.server_recv_frame() {
        if let Ok(ConsoleRequest::Write(bytes)) = ConsoleRequest::decode(&frame) {
            text.extend_from_slice(bytes.as_slice());
        }
    }
    String::from_utf8(text).unwrap()
}

#[test]
fn a_session_prompts_runs_lines_and_ends_at_end_of_input() {
    let mut sys = FakeKernel::new();
    let stream = stream(&mut sys);
    input(&mut sys, b"echo hello-$$\n");
    // A line split across reads, then Ctrl-D on an empty line.
    input(&mut sys, b"echo a");
    input(&mut sys, b"b; false\n");
    sys.server_post(&ConsoleEvent::EndOfInput.encode());
    let mut shell = Shell::new(PID);
    assert_eq!(
        run_session(&mut sys, stream, &mut shell),
        End::EndOfInput(1)
    );
    assert_eq!(written(&mut sys), "$ hello-42\n$ ab\n$ \n");
}

#[test]
fn a_session_runs_the_last_partial_line_at_end_of_input() {
    let mut sys = FakeKernel::new();
    let stream = stream(&mut sys);
    input(&mut sys, b"set PS1='> '\necho tail");
    sys.server_post(&ConsoleEvent::EndOfInput.encode());
    let mut shell = Shell::new(PID);
    assert_eq!(
        run_session(&mut sys, stream, &mut shell),
        End::EndOfInput(0)
    );
    assert_eq!(written(&mut sys), "$ > tail\n\n");
}

#[test]
fn a_session_ends_at_exit_without_reading_further() {
    let mut sys = FakeKernel::new();
    let stream = stream(&mut sys);
    input(&mut sys, b"echo bye; exit 7\necho never\n");
    let mut shell = Shell::new(PID);
    assert_eq!(run_session(&mut sys, stream, &mut shell), End::Exit(7));
    assert_eq!(written(&mut sys), "$ bye\n");
    assert_eq!(End::Exit(7).reason(), "exit");
    assert_eq!(End::Exit(7).status(), Some(7));
}

#[test]
fn a_session_ends_when_the_console_goes() {
    let mut sys = FakeKernel::new();
    let stream = stream(&mut sys);
    input(&mut sys, b"echo one\n");
    sys.server_exit();
    let mut shell = Shell::new(PID);
    let end = run_session(&mut sys, stream, &mut shell);
    assert_eq!(end, End::ConsoleGone);
    assert_eq!(end.status(), None);
    assert_eq!(end.reason(), "console-gone");
}
