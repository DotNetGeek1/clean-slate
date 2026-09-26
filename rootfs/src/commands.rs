//! Parser for the frozen #100 BusyBox command contract (`commands.toml`).
//!
//! Shared by the kernel build script (which embeds the matrix the guest runs) and the
//! xtask acceptance validator (which checks the guest's exit statuses and stdout bytes),
//! so both sides consume one definition. Unknown keys are rejected: a new expectation
//! kind must be implemented here before the contract can use it.

use std::string::String;
use std::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandMatrix {
    pub busybox_sha256: String,
    pub commands: Vec<CommandSpec>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CommandSpec {
    pub name: String,
    /// Text the reference harness passes as `sh -c "export PATH=/bin; <shell>"`.
    pub shell: String,
    pub exit_status: u8,
    pub stdout: Option<Vec<u8>>,
    pub stdout_prefix: Option<Vec<u8>>,
    pub stdout_contains: Vec<Vec<u8>>,
    /// File the harness writes before running the command (`script-sh`).
    pub stage_path: Option<String>,
    pub stage_body: Option<Vec<u8>>,
}

/// The reference harness (`run-traces.sh`) runs every command through this prefix.
pub const SHELL_PREFIX: &str = "export PATH=/bin; ";

impl CommandSpec {
    /// Full `/bin/sh -c` argument, byte-identical to the reference harness invocation.
    pub fn invocation(&self) -> String {
        let mut out = String::from(SHELL_PREFIX);
        out.push_str(&self.shell);
        out
    }

    /// Checks captured stdout against every expectation the contract pins.
    pub fn check_stdout(&self, stdout: &[u8]) -> Result<(), String> {
        if let Some(exact) = &self.stdout {
            if stdout != exact.as_slice() {
                return Err(format!(
                    "{}: stdout {:?} != expected {:?}",
                    self.name,
                    String::from_utf8_lossy(stdout),
                    String::from_utf8_lossy(exact)
                ));
            }
        }
        if let Some(prefix) = &self.stdout_prefix {
            if !stdout.starts_with(prefix) {
                return Err(format!(
                    "{}: stdout {:?} lacks prefix {:?}",
                    self.name,
                    String::from_utf8_lossy(stdout),
                    String::from_utf8_lossy(prefix)
                ));
            }
        }
        for needle in &self.stdout_contains {
            if !contains(stdout, needle) {
                return Err(format!(
                    "{}: stdout {:?} lacks {:?}",
                    self.name,
                    String::from_utf8_lossy(stdout),
                    String::from_utf8_lossy(needle)
                ));
            }
        }
        Ok(())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty() || haystack.windows(needle.len()).any(|w| w == needle)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Meta,
    Command,
}

impl CommandMatrix {
    pub fn parse_toml(input: &str) -> Result<Self, String> {
        let mut busybox_sha256 = None;
        let mut commands: Vec<CommandSpec> = Vec::new();
        let mut seen: Vec<Vec<&'static str>> = Vec::new();
        let mut section = Section::None;

        for (index, raw) in input.lines().enumerate() {
            let line_no = index + 1;
            let line = strip_comment(raw).trim();
            if line.is_empty() {
                continue;
            }
            if line == "[meta]" {
                section = Section::Meta;
                continue;
            }
            if line == "[[command]]" {
                section = Section::Command;
                commands.push(CommandSpec::default());
                seen.push(Vec::new());
                continue;
            }
            if line.starts_with('[') {
                return Err(format!("line {line_no}: unknown section {line}"));
            }
            let (key, value) = line
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .ok_or_else(|| format!("line {line_no}: expected key = value"))?;
            match section {
                Section::None => return Err(format!("line {line_no}: key outside a section")),
                Section::Meta => match key {
                    "busybox_sha256" => busybox_sha256 = Some(parse_string(value, line_no)?),
                    "fixture_dns" | "fixture_http" | "fixture_hostname" => {
                        parse_string(value, line_no)?;
                    }
                    _ => return Err(format!("line {line_no}: unknown [meta] key {key}")),
                },
                Section::Command => {
                    let spec = commands.last_mut().expect("command section");
                    let keys = seen.last_mut().expect("command keys");
                    let known = COMMAND_KEYS
                        .iter()
                        .find(|k| **k == key)
                        .ok_or_else(|| format!("line {line_no}: unknown [[command]] key {key}"))?;
                    if keys.contains(known) {
                        return Err(format!("line {line_no}: duplicate key {key}"));
                    }
                    keys.push(known);
                    match key {
                        "name" => spec.name = parse_string(value, line_no)?,
                        "shell" => spec.shell = parse_string(value, line_no)?,
                        "exit_status" => {
                            spec.exit_status = value
                                .parse()
                                .map_err(|_| format!("line {line_no}: bad exit_status {value}"))?
                        }
                        "stdout" => spec.stdout = Some(parse_string(value, line_no)?.into_bytes()),
                        "stdout_prefix" => {
                            spec.stdout_prefix = Some(parse_string(value, line_no)?.into_bytes())
                        }
                        "stdout_contains" => {
                            spec.stdout_contains = parse_string_array(value, line_no)?
                                .into_iter()
                                .map(String::into_bytes)
                                .collect()
                        }
                        "stage_path" => spec.stage_path = Some(parse_string(value, line_no)?),
                        "stage_body" => {
                            spec.stage_body = Some(parse_string(value, line_no)?.into_bytes())
                        }
                        _ => unreachable!("key checked against COMMAND_KEYS"),
                    }
                }
            }
        }

        let busybox_sha256 = busybox_sha256.ok_or("missing [meta] busybox_sha256")?;
        if commands.is_empty() {
            return Err("no [[command]] entries".into());
        }
        for (index, spec) in commands.iter().enumerate() {
            let keys = &seen[index];
            for required in ["name", "shell", "exit_status"] {
                if !keys.contains(&required) {
                    return Err(format!("command #{}: missing {required}", index + 1));
                }
            }
            if spec.stdout.is_none()
                && spec.stdout_prefix.is_none()
                && spec.stdout_contains.is_empty()
            {
                return Err(format!("{}: no stdout expectation", spec.name));
            }
            if spec.stage_path.is_some() != spec.stage_body.is_some() {
                return Err(format!(
                    "{}: stage_path and stage_body go together",
                    spec.name
                ));
            }
            if commands[..index]
                .iter()
                .any(|other| other.name == spec.name)
            {
                return Err(format!("duplicate command name {}", spec.name));
            }
        }
        Ok(Self {
            busybox_sha256,
            commands,
        })
    }
}

const COMMAND_KEYS: &[&str] = &[
    "name",
    "shell",
    "exit_status",
    "stdout",
    "stdout_prefix",
    "stdout_contains",
    "stage_path",
    "stage_body",
];

/// Drops a trailing `#` comment that is not inside a basic string.
fn strip_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (index, c) in line.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
        } else if c == '#' {
            return &line[..index];
        }
    }
    line
}

fn parse_string(value: &str, line_no: usize) -> Result<String, String> {
    let (s, rest) = take_string(value, line_no)?;
    if !rest.trim().is_empty() {
        return Err(format!("line {line_no}: trailing text after string"));
    }
    Ok(s)
}

fn parse_string_array(value: &str, line_no: usize) -> Result<Vec<String>, String> {
    let inner = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or_else(|| format!("line {line_no}: expected [\"...\", ...]"))?;
    let mut out = Vec::new();
    let mut rest = inner.trim();
    while !rest.is_empty() {
        let (s, after) = take_string(rest, line_no)?;
        out.push(s);
        rest = after.trim_start();
        if let Some(after_comma) = rest.strip_prefix(',') {
            rest = after_comma.trim_start();
        } else if !rest.is_empty() {
            return Err(format!("line {line_no}: expected ',' between strings"));
        }
    }
    Ok(out)
}

/// Parses one TOML basic string; returns it and the remaining input.
fn take_string(value: &str, line_no: usize) -> Result<(String, &str), String> {
    let body = value
        .strip_prefix('"')
        .ok_or_else(|| format!("line {line_no}: expected a basic string"))?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((index, c)) = chars.next() {
        match c {
            '"' => return Ok((out, &body[index + 1..])),
            '\\' => {
                let (_, escape) = chars
                    .next()
                    .ok_or_else(|| format!("line {line_no}: dangling escape"))?;
                out.push(match escape {
                    'n' => '\n',
                    't' => '\t',
                    'r' => '\r',
                    '"' => '"',
                    '\\' => '\\',
                    other => return Err(format!("line {line_no}: unsupported escape \\{other}")),
                });
            }
            other => out.push(other),
        }
    }
    Err(format!("line {line_no}: unterminated string"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn frozen_matrix() -> CommandMatrix {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("fixtures/busybox/frozen/commands.toml");
        CommandMatrix::parse_toml(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[test]
    fn frozen_contract_parses_in_order() {
        let matrix = frozen_matrix();
        assert_eq!(
            matrix.busybox_sha256,
            "7ba56acec9fb89deace4ebfab6f4baaa8d1b778754b8f7ae3dbd7cf7990fe380"
        );
        let names: Vec<_> = matrix.commands.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names.first(), Some(&"true"));
        assert_eq!(names.last(), Some(&"grep-via-symlink"));
        assert_eq!(names.len(), 18);
        let exit = matrix.commands.iter().find(|c| c.name == "exit-3").unwrap();
        assert_eq!(exit.exit_status, 0);
        assert_eq!(exit.stdout.as_deref(), Some(&b"exit_code=3\n"[..]));
        assert_eq!(
            exit.invocation(),
            "export PATH=/bin; sh -c 'exit 3'; /bin/busybox echo exit_code=$?"
        );
        let heredoc = matrix
            .commands
            .iter()
            .find(|c| c.name == "grep-via-busybox")
            .unwrap();
        assert_eq!(heredoc.shell, "/bin/busybox grep hello <<EOF\nhello\nEOF");
        let script = matrix
            .commands
            .iter()
            .find(|c| c.name == "script-sh")
            .unwrap();
        assert_eq!(script.stage_path.as_deref(), Some("/tmp/script.sh"));
        assert!(script.stage_body.as_ref().unwrap().ends_with(b"exit 0\n"));
    }

    #[test]
    fn stdout_expectations() {
        let matrix = frozen_matrix();
        let ls = matrix
            .commands
            .iter()
            .find(|c| c.name == "ls-root")
            .unwrap();
        assert!(ls.check_stdout(b"tmp\netc\nbin\n").is_ok());
        assert!(ls.check_stdout(b"tmp\netc\n").is_err());
        let pwd = matrix.commands.iter().find(|c| c.name == "pwd").unwrap();
        assert!(pwd.check_stdout(b"/\n").is_ok());
        assert!(pwd.check_stdout(b"/\n\n").is_err());
        let list = matrix
            .commands
            .iter()
            .find(|c| c.name == "busybox-list")
            .unwrap();
        assert!(list.check_stdout(b"ash\ncat\n").is_ok());
        assert!(list.check_stdout(b"cat\n").is_err());
    }

    #[test]
    fn rejects_unknown_keys_and_missing_expectations() {
        let base = "[meta]\nbusybox_sha256 = \"x\"\n[[command]]\nname = \"a\"\nshell = \"true\"\nexit_status = 0\n";
        assert!(CommandMatrix::parse_toml(&format!("{base}stdout = \"\"\n")).is_ok());
        assert!(CommandMatrix::parse_toml(base).is_err());
        assert!(
            CommandMatrix::parse_toml(&format!("{base}stdout = \"\"\nstderr = \"\"\n")).is_err()
        );
        assert!(
            CommandMatrix::parse_toml(&format!("{base}stdout = \"\"\nstdout = \"\"\n")).is_err()
        );
        let dup = format!("{base}stdout = \"\"\n[[command]]\nname = \"a\"\nshell = \"true\"\nexit_status = 0\nstdout = \"\"\n");
        assert!(CommandMatrix::parse_toml(&dup).is_err());
    }

    #[test]
    fn comments_and_escapes() {
        assert_eq!(strip_comment("a = \"x # y\" # z"), "a = \"x # y\" ");
        assert_eq!(parse_string("\"a\\nb\\\"c\"", 1).unwrap(), "a\nb\"c");
        assert!(parse_string("\"a\\qb\"", 1).is_err());
        assert_eq!(
            parse_string_array("[\"bin\", \"etc\" , \"tmp\"]", 1).unwrap(),
            vec!["bin", "etc", "tmp"]
        );
    }
}
