//! The shell's state and the runner: expands each parsed command and looks its name up in the
//! command table, then in [`Programs`].

use alloc::collections::{BTreeMap, VecDeque};
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::parse::{self, Part, Word};

/// A command's exit status, as `$?` reads it.
pub type Status = u8;

/// The status of a syntax error or a builtin's usage error.
pub const STATUS_USAGE: Status = 2;
/// The status when no builtin or program has the name.
pub const STATUS_NOT_FOUND: Status = 127;
/// Lines `history` keeps.
pub const HISTORY_LINES: usize = 100;
/// The prompt `PS1` starts as.
pub const DEFAULT_PROMPT: &str = "$ ";

/// Where command output and error messages go: the console session in the shipped shell. There
/// is no separate error stream.
pub trait Output {
    fn write(&mut self, bytes: &[u8]);

    fn write_str(&mut self, text: &str) {
        self.write(text.as_bytes());
    }
}

impl Output for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// What a command runs with: the shell's state and the output.
pub struct Context<'a> {
    pub state: &'a mut State,
    pub out: &'a mut dyn Output,
}

impl Context<'_> {
    /// `nsh: <name>: <message>` and a newline.
    pub fn error(&mut self, name: &str, message: &str) {
        self.out.write_str(&format!("nsh: {name}: {message}\n"));
    }
}

/// One command a table entry runs. `args[0]` is the command's name.
pub type Run = fn(&mut Context<'_>, &[String]) -> Status;

/// One entry of the command table.
#[derive(Clone, Copy)]
pub struct Command {
    pub name: &'static str,
    /// The arguments, for `help` (`"[status]"`); empty when it takes none.
    pub usage: &'static str,
    pub summary: &'static str,
    pub run: Run,
}

/// The commands the shell knows, as groups of static entries. A later issue adds its commands
/// with one [`CommandTable::register`] call; the first group that names a command wins.
#[derive(Clone, Default)]
pub struct CommandTable {
    groups: Vec<&'static [Command]>,
}

impl CommandTable {
    pub const fn new() -> Self {
        Self { groups: Vec::new() }
    }

    pub fn register(&mut self, commands: &'static [Command]) {
        self.groups.push(commands);
    }

    pub fn find(&self, name: &str) -> Option<&'static Command> {
        self.groups
            .iter()
            .flat_map(|group| group.iter())
            .find(|command| command.name == name)
    }

    /// Every command, in registration order, without the shadowed ones.
    pub fn iter(&self) -> impl Iterator<Item = &'static Command> + '_ {
        self.groups
            .iter()
            .flat_map(|group| group.iter())
            .enumerate()
            .filter(move |(index, command)| {
                self.groups
                    .iter()
                    .flat_map(|group| group.iter())
                    .position(|first| first.name == command.name)
                    == Some(*index)
            })
            .map(|(_, command)| command)
    }
}

/// Native programs the shell can start by name (#389). The shell asks for a name no builtin
/// has; `None` means there is no such program.
pub trait Programs {
    fn run(&mut self, name: &str, args: &[String], out: &mut dyn Output) -> Option<Status>;
}

/// No programs: every unknown name is "command not found".
#[derive(Clone, Copy, Debug, Default)]
pub struct NoPrograms;

impl Programs for NoPrograms {
    fn run(&mut self, _: &str, _: &[String], _: &mut dyn Output) -> Option<Status> {
        None
    }
}

/// Everything a command may read or change.
pub struct State {
    pub vars: BTreeMap<String, String>,
    /// `$?`.
    pub status: Status,
    /// `$$`.
    pub pid: u64,
    pub history: VecDeque<String>,
    /// How many lines were ever added to the history: the number of the newest one.
    pub history_count: usize,
    pub commands: CommandTable,
    /// Set by `exit`: the shell stops after the current command.
    pub exit: Option<Status>,
}

impl State {
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(String::as_str)
    }

    pub fn set_var(&mut self, name: &str, value: &str) {
        self.vars.insert(name.to_string(), value.to_string());
    }

    fn remember(&mut self, line: &str) {
        if self.history.len() == HISTORY_LINES {
            self.history.pop_front();
        }
        self.history.push_back(line.to_string());
        self.history_count += 1;
    }

    fn expand(&self, word: &Word) -> String {
        let mut text = String::new();
        for part in &word.parts {
            match part {
                Part::Literal(literal) => text.push_str(literal),
                Part::Var(name) => text.push_str(self.var(name).unwrap_or("")),
                Part::Status => text.push_str(&self.status.to_string()),
                Part::Pid => text.push_str(&self.pid.to_string()),
            }
        }
        text
    }
}

pub struct Shell<P: Programs = NoPrograms> {
    pub state: State,
    pub programs: P,
}

impl Shell<NoPrograms> {
    /// A shell with the core builtins and no programs.
    pub fn new(pid: u64) -> Self {
        Self::with_programs(pid, NoPrograms)
    }
}

impl<P: Programs> Shell<P> {
    pub fn with_programs(pid: u64, programs: P) -> Self {
        let mut commands = CommandTable::new();
        commands.register(crate::builtins::CORE);
        let mut vars = BTreeMap::new();
        vars.insert("PS1".to_string(), DEFAULT_PROMPT.to_string());
        Self {
            state: State {
                vars,
                status: 0,
                pid,
                history: VecDeque::new(),
                history_count: 0,
                commands,
                exit: None,
            },
            programs,
        }
    }

    /// The prompt: `$PS1`, or nothing when it is unset.
    pub fn prompt(&self) -> &str {
        self.state.var("PS1").unwrap_or("")
    }

    /// The status `exit` asked for, once it has.
    pub fn exit_requested(&self) -> Option<Status> {
        self.state.exit
    }

    /// Runs one input line: adds it to the history, parses it and runs its chains. Returns the
    /// last status, which is also `$?` from now on.
    pub fn run_line(&mut self, line: &str, out: &mut dyn Output) -> Status {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.trim().is_empty() {
            return self.state.status;
        }
        self.state.remember(line);
        let script = match parse::parse(line) {
            Ok(script) => script,
            Err(error) => {
                out.write_str(&format!("nsh: {error}\n"));
                self.state.status = STATUS_USAGE;
                return STATUS_USAGE;
            }
        };
        for chain in &script.chains {
            for (index, command) in chain.commands.iter().enumerate() {
                if index > 0 && self.state.status != 0 {
                    break;
                }
                let status = self.run_command(command, out);
                self.state.status = status;
                if self.state.exit.is_some() {
                    return status;
                }
            }
        }
        self.state.status
    }

    fn run_command(&mut self, words: &[Word], out: &mut dyn Output) -> Status {
        // A command made only of `NAME=value` words sets those variables.
        if words.iter().all(|word| word.assignment_name().is_some()) {
            for word in words {
                let text = self.state.expand(word);
                if let Some((name, value)) = text.split_once('=') {
                    self.state.set_var(name, value);
                }
            }
            return 0;
        }
        let args: Vec<String> = words
            .iter()
            .filter_map(|word| {
                let text = self.state.expand(word);
                // An unquoted expansion to nothing is no word at all.
                (word.quoted || !text.is_empty()).then_some(text)
            })
            .collect();
        let Some(name) = args.first() else {
            return 0;
        };
        if let Some(command) = self.state.commands.find(name) {
            let mut context = Context {
                state: &mut self.state,
                out,
            };
            return (command.run)(&mut context, &args);
        }
        match self.programs.run(name, &args[1..], out) {
            Some(status) => status,
            None => {
                out.write_str(&format!("nsh: {name}: command not found\n"));
                STATUS_NOT_FOUND
            }
        }
    }
}
