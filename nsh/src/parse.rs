//! The command-line parser: one input line to a [`Script`].
//!
//! ```text
//! script  = chain { ";" chain } [ ";" ]
//! chain   = command { "&&" command }
//! command = word { word }
//! ```
//!
//! Words are split on unquoted blanks. Inside a word:
//!
//! | Form | Meaning |
//! |------|---------|
//! | `'...'` | literal, no escapes |
//! | `"..."` | literal except `$` expansions and `\` before `$`, `"`, `\` |
//! | `\c` | the character `c`, literally |
//! | `$NAME`, `${NAME}` | the variable's value (empty when unset) |
//! | `$?` | the last command's status |
//! | `$$` | the shell's pid |
//!
//! A `$` before anything else is a literal `$`. An unquoted `#` at the start of a word starts a
//! comment. `|`, a lone `&`, `<` and `>` are refused, since pipes, background jobs and
//! redirections are not part of this shell. Columns count characters from 1.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

/// One piece of a word, before expansion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Part {
    Literal(String),
    Var(String),
    /// `$?`
    Status,
    /// `$$`
    Pid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Word {
    pub parts: Vec<Part>,
    /// Whether any part of it was quoted or escaped: such a word is kept even when it expands
    /// to nothing.
    pub quoted: bool,
    /// Whether it starts with an unquoted `NAME=`.
    pub assignment: bool,
    pub column: usize,
}

impl Word {
    /// The variable name when the word is an unquoted `NAME=value` assignment.
    pub fn assignment_name(&self) -> Option<&str> {
        if !self.assignment {
            return None;
        }
        let Some(Part::Literal(text)) = self.parts.first() else {
            return None;
        };
        text.split_once('=').map(|(name, _)| name)
    }
}

/// Simple commands joined by `&&`: each runs only if the one before it succeeded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub commands: Vec<Vec<Word>>,
}

/// Chains separated by `;`, run in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Script {
    pub chains: Vec<Chain>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorKind {
    UnterminatedSingleQuote,
    UnterminatedDoubleQuote,
    TrailingBackslash,
    UnterminatedBrace,
    BadSubstitution,
    /// `;` or `&&` with no command before it.
    MissingCommandBefore(&'static str),
    /// `&&` at the end of the line.
    MissingCommandAfter(&'static str),
    Unsupported(char),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyntaxError {
    pub kind: ErrorKind,
    /// 1-based character column of the offending character.
    pub column: usize,
}

impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "syntax error at column {}: ", self.column)?;
        match self.kind {
            ErrorKind::UnterminatedSingleQuote => f.write_str("unterminated single quote"),
            ErrorKind::UnterminatedDoubleQuote => f.write_str("unterminated double quote"),
            ErrorKind::TrailingBackslash => f.write_str("backslash at the end of the line"),
            ErrorKind::UnterminatedBrace => f.write_str("unterminated ${"),
            ErrorKind::BadSubstitution => f.write_str("bad variable name in ${...}"),
            ErrorKind::MissingCommandBefore(op) => write!(f, "expected a command before {op}"),
            ErrorKind::MissingCommandAfter(op) => write!(f, "expected a command after {op}"),
            ErrorKind::Unsupported('|') => f.write_str("pipes (|) are not supported"),
            ErrorKind::Unsupported('&') => f.write_str("background jobs (&) are not supported"),
            ErrorKind::Unsupported(c) => write!(f, "redirection ({c}) is not supported"),
        }
    }
}

/// Whether `name` is a variable name: a letter or `_`, then letters, digits or `_`.
pub fn is_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

const fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

const fn is_operator(c: char) -> bool {
    matches!(c, ';' | '&' | '|' | '<' | '>')
}

struct Parser {
    chars: Vec<char>,
    at: usize,
}

impl Parser {
    fn peek(&self, ahead: usize) -> Option<char> {
        self.chars.get(self.at + ahead).copied()
    }

    fn error(&self, kind: ErrorKind, at: usize) -> SyntaxError {
        SyntaxError {
            kind,
            column: at + 1,
        }
    }

    /// Whether the input from here reads `NAME=`, unquoted.
    fn at_assignment(&self) -> bool {
        let rest = &self.chars[self.at..];
        let Some(eq) = rest.iter().position(|&c| c == '=') else {
            return false;
        };
        let name: String = rest[..eq].iter().collect();
        is_name(&name)
    }

    fn word(&mut self) -> Result<Word, SyntaxError> {
        let mut word = Word {
            parts: Vec::new(),
            quoted: false,
            assignment: self.at_assignment(),
            column: self.at + 1,
        };
        let mut literal = String::new();
        while let Some(c) = self.peek(0) {
            if is_blank(c) || is_operator(c) {
                break;
            }
            match c {
                '\'' => {
                    let open = self.at;
                    self.at += 1;
                    loop {
                        match self.peek(0) {
                            Some('\'') => break,
                            Some(c) => literal.push(c),
                            None => {
                                return Err(self.error(ErrorKind::UnterminatedSingleQuote, open))
                            }
                        }
                        self.at += 1;
                    }
                    self.at += 1;
                    word.quoted = true;
                }
                '"' => {
                    let open = self.at;
                    self.at += 1;
                    loop {
                        match self.peek(0) {
                            Some('"') => break,
                            Some('\\') => match self.peek(1) {
                                Some(next @ ('$' | '"' | '\\')) => {
                                    literal.push(next);
                                    self.at += 2;
                                }
                                _ => {
                                    literal.push('\\');
                                    self.at += 1;
                                }
                            },
                            Some('$') => self.dollar(&mut word, &mut literal)?,
                            Some(c) => {
                                literal.push(c);
                                self.at += 1;
                            }
                            None => {
                                return Err(self.error(ErrorKind::UnterminatedDoubleQuote, open))
                            }
                        }
                    }
                    self.at += 1;
                    word.quoted = true;
                }
                '\\' => {
                    let Some(next) = self.peek(1) else {
                        return Err(self.error(ErrorKind::TrailingBackslash, self.at));
                    };
                    literal.push(next);
                    self.at += 2;
                    word.quoted = true;
                }
                '$' => self.dollar(&mut word, &mut literal)?,
                c => {
                    literal.push(c);
                    self.at += 1;
                }
            }
        }
        flush(&mut word, &mut literal);
        Ok(word)
    }

    /// At a `$`: one expansion, or a literal `$`.
    fn dollar(&mut self, word: &mut Word, literal: &mut String) -> Result<(), SyntaxError> {
        let start = self.at;
        let part = match self.peek(1) {
            Some('?') => {
                self.at += 2;
                Part::Status
            }
            Some('$') => {
                self.at += 2;
                Part::Pid
            }
            Some('{') => {
                self.at += 2;
                let mut name = String::new();
                loop {
                    match self.peek(0) {
                        Some('}') => break,
                        Some(c) => name.push(c),
                        None => return Err(self.error(ErrorKind::UnterminatedBrace, start)),
                    }
                    self.at += 1;
                }
                self.at += 1;
                if !is_name(&name) {
                    return Err(self.error(ErrorKind::BadSubstitution, start));
                }
                Part::Var(name)
            }
            Some(c) if c == '_' || c.is_ascii_alphabetic() => {
                self.at += 1;
                let mut name = String::new();
                while let Some(c) = self.peek(0) {
                    if c != '_' && !c.is_ascii_alphanumeric() {
                        break;
                    }
                    name.push(c);
                    self.at += 1;
                }
                Part::Var(name)
            }
            _ => {
                literal.push('$');
                self.at += 1;
                return Ok(());
            }
        };
        flush(word, literal);
        word.parts.push(part);
        Ok(())
    }
}

fn flush(word: &mut Word, literal: &mut String) {
    if !literal.is_empty() {
        word.parts.push(Part::Literal(core::mem::take(literal)));
    }
}

/// Parses one command line. An empty line, or one that is only a comment, is an empty script.
pub fn parse(line: &str) -> Result<Script, SyntaxError> {
    let mut parser = Parser {
        chars: line.chars().collect(),
        at: 0,
    };
    let mut script = Script::default();
    let mut chain: Vec<Vec<Word>> = Vec::new();
    let mut command: Vec<Word> = Vec::new();
    // The column of an `&&` still waiting for its right-hand command.
    let mut open_and: Option<usize> = None;
    while let Some(c) = parser.peek(0) {
        match c {
            c if is_blank(c) => parser.at += 1,
            ';' => {
                if command.is_empty() {
                    let kind = match open_and {
                        Some(at) => {
                            return Err(parser.error(ErrorKind::MissingCommandAfter("&&"), at))
                        }
                        None => ErrorKind::MissingCommandBefore(";"),
                    };
                    return Err(parser.error(kind, parser.at));
                }
                chain.push(core::mem::take(&mut command));
                script.chains.push(Chain {
                    commands: core::mem::take(&mut chain),
                });
                open_and = None;
                parser.at += 1;
            }
            '&' if parser.peek(1) == Some('&') => {
                if command.is_empty() {
                    return Err(parser.error(ErrorKind::MissingCommandBefore("&&"), parser.at));
                }
                chain.push(core::mem::take(&mut command));
                open_and = Some(parser.at);
                parser.at += 2;
            }
            '&' | '|' | '<' | '>' => {
                return Err(parser.error(ErrorKind::Unsupported(c), parser.at));
            }
            '#' => break,
            _ => {
                command.push(parser.word()?);
                open_and = None;
            }
        }
    }
    if let Some(at) = open_and {
        return Err(parser.error(ErrorKind::MissingCommandAfter("&&"), at));
    }
    if !command.is_empty() {
        chain.push(command);
    }
    if !chain.is_empty() {
        script.chains.push(Chain { commands: chain });
    }
    Ok(script)
}
