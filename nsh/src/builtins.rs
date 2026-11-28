//! The core builtins (#388).

use alloc::format;
use alloc::string::String;

use crate::parse::is_name;
use crate::shell::{Command, Context, Status, STATUS_USAGE};

/// VT100: cursor home, then erase the whole display.
pub const CLEAR_SCREEN: &[u8] = b"\x1b[H\x1b[2J";

pub static CORE: &[Command] = &[
    Command {
        name: "echo",
        usage: "[-n] [word ...]",
        summary: "print the words, separated by spaces (-n: no newline)",
        run: echo,
    },
    Command {
        name: "help",
        usage: "[command]",
        summary: "list the commands, or describe one",
        run: help,
    },
    Command {
        name: "clear",
        usage: "",
        summary: "clear the terminal",
        run: clear,
    },
    Command {
        name: "exit",
        usage: "[status]",
        summary: "end the shell (status 0-255, default $?)",
        run: exit,
    },
    Command {
        name: "set",
        usage: "[NAME=value ...]",
        summary: "list the shell variables, or set them",
        run: set,
    },
    Command {
        name: "unset",
        usage: "NAME ...",
        summary: "remove shell variables",
        run: unset,
    },
    Command {
        name: "history",
        usage: "",
        summary: "list the lines typed so far",
        run: history,
    },
    Command {
        name: "true",
        usage: "",
        summary: "succeed (status 0)",
        run: |_, _| 0,
    },
    Command {
        name: "false",
        usage: "",
        summary: "fail (status 1)",
        run: |_, _| 1,
    },
];

fn echo(cx: &mut Context<'_>, args: &[String]) -> Status {
    let (newline, words) = match args.get(1).map(String::as_str) {
        Some("-n") => (false, &args[2..]),
        _ => (true, &args[1..]),
    };
    let mut text = String::new();
    for (index, word) in words.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(word);
    }
    if newline {
        text.push('\n');
    }
    cx.out.write_str(&text);
    0
}

fn help(cx: &mut Context<'_>, args: &[String]) -> Status {
    let line = |command: &Command| {
        let mut synopsis = String::from(command.name);
        if !command.usage.is_empty() {
            synopsis.push(' ');
            synopsis.push_str(command.usage);
        }
        format!("  {synopsis:<24} {}\n", command.summary)
    };
    match args.get(1) {
        None => {
            cx.out.write_str("Commands:\n");
            let lines: String = cx.state.commands.iter().map(line).collect();
            cx.out.write_str(&lines);
            0
        }
        Some(name) => match cx.state.commands.find(name) {
            Some(command) => {
                cx.out.write_str(&line(command));
                0
            }
            None => {
                cx.error("help", &format!("no command {name}"));
                1
            }
        },
    }
}

fn clear(cx: &mut Context<'_>, _: &[String]) -> Status {
    cx.out.write(CLEAR_SCREEN);
    0
}

fn exit(cx: &mut Context<'_>, args: &[String]) -> Status {
    let status = match args {
        [_] => cx.state.status,
        [_, status] => match status.parse::<Status>() {
            Ok(status) => status,
            Err(_) => {
                cx.error("exit", &format!("bad status {status} (want 0-255)"));
                return STATUS_USAGE;
            }
        },
        _ => {
            cx.error("exit", "too many arguments");
            return STATUS_USAGE;
        }
    };
    cx.state.exit = Some(status);
    status
}

fn set(cx: &mut Context<'_>, args: &[String]) -> Status {
    if args.len() == 1 {
        let listing: String = cx
            .state
            .vars
            .iter()
            .map(|(name, value)| format!("{name}={value}\n"))
            .collect();
        cx.out.write_str(&listing);
        return 0;
    }
    // Check every word first, so a bad one sets nothing.
    for arg in &args[1..] {
        if !arg.split_once('=').is_some_and(|(name, _)| is_name(name)) {
            cx.error("set", &format!("not NAME=value: {arg}"));
            return STATUS_USAGE;
        }
    }
    for arg in &args[1..] {
        if let Some((name, value)) = arg.split_once('=') {
            cx.state.set_var(name, value);
        }
    }
    0
}

fn unset(cx: &mut Context<'_>, args: &[String]) -> Status {
    if args.len() == 1 {
        cx.error("unset", "name a variable");
        return STATUS_USAGE;
    }
    for name in &args[1..] {
        if !is_name(name) {
            cx.error("unset", &format!("not a variable name: {name}"));
            return STATUS_USAGE;
        }
    }
    for name in &args[1..] {
        cx.state.vars.remove(name);
    }
    0
}

fn history(cx: &mut Context<'_>, _: &[String]) -> Status {
    let first = cx.state.history_count + 1 - cx.state.history.len();
    let listing: String = cx
        .state
        .history
        .iter()
        .enumerate()
        .map(|(index, line)| format!("{:>5}  {line}\n", first + index))
        .collect();
    cx.out.write_str(&listing);
    0
}
