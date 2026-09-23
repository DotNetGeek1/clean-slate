//! Minimal `rootfs.toml` parser (no extra workspace dependency).

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use super::RootfsError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: u16,
    pub entries: Vec<ManifestEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: Vec<u8>,
    pub kind: ManifestKind,
    pub writable: bool,
    pub source: Option<String>,
    pub sha256: Option<String>,
    pub target: Option<Vec<u8>>,
    pub inline: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestKind {
    Dir,
    File,
    Link,
}

impl Manifest {
    pub fn parse_toml(input: &str) -> Result<Self, RootfsError> {
        let mut version = 1u16;
        let mut entries = Vec::new();
        let mut current: Option<ManifestEntry> = None;

        for line in input.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with("[image]") {
                continue;
            }
            if line == "[[entry]]" {
                if let Some(entry) = current.take() {
                    entries.push(entry);
                }
                current = Some(ManifestEntry {
                    path: Vec::new(),
                    kind: ManifestKind::Dir,
                    writable: false,
                    source: None,
                    sha256: None,
                    target: None,
                    inline: None,
                });
                continue;
            }
            if let Some((key, value)) = parse_key_value(line) {
                if key == "version" && current.is_none() {
                    version = parse_u16(value)?;
                    continue;
                }
                let entry = current.as_mut().ok_or(RootfsError::BadPath)?;
                match key {
                    "path" => entry.path = parse_toml_path(value)?,
                    "kind" => entry.kind = parse_kind(value)?,
                    "writable" => entry.writable = parse_bool(value),
                    "source" => entry.source = Some(parse_string(value)?),
                    "sha256" => entry.sha256 = Some(parse_string(value)?.to_ascii_lowercase()),
                    "target" => entry.target = Some(parse_toml_path(value)?),
                    "inline" => entry.inline = Some(parse_inline_string(value)?),
                    _ => {}
                }
            }
        }
        if let Some(entry) = current.take() {
            entries.push(entry);
        }
        if entries.is_empty() {
            return Err(RootfsError::BadPath);
        }
        Ok(Self { version, entries })
    }
}

fn parse_key_value(line: &str) -> Option<(&str, &str)> {
    let mut parts = line.splitn(2, '=');
    let key = parts.next()?.trim();
    let value = parts.next()?.trim();
    Some((key, value))
}

fn parse_u16(s: &str) -> Result<u16, RootfsError> {
    s.trim()
        .parse()
        .map_err(|_| RootfsError::BadVersion)
}

fn parse_bool(s: &str) -> bool {
    matches!(s.trim(), "true" | "1")
}

fn parse_string(s: &str) -> Result<String, RootfsError> {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        Ok(unescape_toml_string(&s[1..s.len() - 1])?)
    } else {
        Err(RootfsError::BadPath)
    }
}

fn parse_inline_string(s: &str) -> Result<Vec<u8>, RootfsError> {
    Ok(parse_string(s)?.into_bytes())
}

fn parse_toml_path(s: &str) -> Result<Vec<u8>, RootfsError> {
    let s = s.trim();
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        return unescape_toml_path(inner);
    }
    Err(RootfsError::BadPath)
}

fn unescape_toml_string(s: &str) -> Result<String, RootfsError> {
    let mut out = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let next = chars.next().ok_or(RootfsError::BadPath)?;
            match next {
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                'x' => {
                    let h1 = chars.next().ok_or(RootfsError::BadPath)?;
                    let h2 = chars.next().ok_or(RootfsError::BadPath)?;
                    let byte = u8::from_str_radix(&format!("{h1}{h2}"), 16)
                        .map_err(|_| RootfsError::BadPath)?;
                    out.push(byte as char);
                }
                other => out.push(other),
            }
        } else {
            out.push(c);
        }
    }
    Ok(out)
}

fn unescape_toml_path(s: &str) -> Result<Vec<u8>, RootfsError> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            match bytes[i + 1] {
                b'n' => out.push(b'\n'),
                b'r' => out.push(b'\r'),
                b't' => out.push(b'\t'),
                b'\\' => out.push(b'\\'),
                b'"' => out.push(b'"'),
                b'x' if i + 3 < bytes.len() => {
                    let h = &s[i + 2..i + 4];
                    let byte = u8::from_str_radix(h, 16).map_err(|_| RootfsError::BadPath)?;
                    out.push(byte);
                    i += 4;
                    continue;
                }
                other => out.push(other),
            }
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn parse_kind(s: &str) -> Result<ManifestKind, RootfsError> {
    match s.trim().trim_matches('"') {
        "dir" => Ok(ManifestKind::Dir),
        "file" => Ok(ManifestKind::File),
        "link" => Ok(ManifestKind::Link),
        _ => Err(RootfsError::BadEntryKind),
    }
}
