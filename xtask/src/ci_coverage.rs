//! The PR workflow's `check` job lints every kernel configuration a lane builds (#223).
//!
//! Lanes name their kernel features as string literals: a slice such as
//! `&["m3-entry-self-test", "m3-syscall-self-test"]`, or a single literal handed to a helper
//! (`run_m6_constituent("m6-audit-self-test", …)`). Every such feature set, expanded through
//! the implications in `kernel/Cargo.toml`, must equal the expanded set of some
//! `cargo clippy -p clean-slate-kernel --target x86_64-unknown-uefi` line in `pr.yml`. A set
//! assembled at run time from separate literals is not seen here; write it as one slice.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::workspace_root;

const KERNEL_CLIPPY: &str = "cargo clippy -p clean-slate-kernel --target x86_64-unknown-uefi";

type FeatureSet = BTreeSet<String>;

/// `kernel/Cargo.toml` features, each with the kernel features it enables directly.
fn kernel_features(manifest: &str) -> BTreeMap<String, Vec<String>> {
    let manifest = manifest.replace("\r\n", "\n");
    let section = manifest
        .split("\n[features]\n")
        .nth(1)
        .expect("kernel/Cargo.toml has a [features] table");
    let section = section.split("\n[").next().unwrap_or(section);
    let mut features = BTreeMap::new();
    let mut entries = section.split('\n').peekable();
    while let Some(line) = entries.next() {
        let Some((name, value)) = line.split_once(" = [") else {
            continue;
        };
        let mut value = value.to_owned();
        while !value.contains(']') {
            value.push_str(entries.next().expect("feature list closes"));
        }
        let enabled = string_literals(&value)
            .into_iter()
            .filter(|item| !item.contains(':') && !item.contains('/'))
            .collect();
        features.insert(name.trim().to_owned(), enabled);
    }
    features
}

fn expand(set: &FeatureSet, features: &BTreeMap<String, Vec<String>>) -> FeatureSet {
    let mut expanded = set.clone();
    let mut pending: Vec<String> = set.iter().cloned().collect();
    while let Some(name) = pending.pop() {
        for implied in features.get(&name).into_iter().flatten() {
            if expanded.insert(implied.clone()) {
                pending.push(implied.clone());
            }
        }
    }
    expanded
}

/// The contents of every `"…"` literal in `source`, in order. Escapes are kept as written.
fn string_literals(source: &str) -> Vec<String> {
    literal_spans(source)
        .into_iter()
        .map(|(start, end)| source[start + 1..end - 1].to_owned())
        .collect()
}

/// Byte ranges of every `"…"` literal in `source`, quotes included. Comments, raw strings and
/// character literals such as `'"'` are skipped so they cannot open a string.
fn literal_spans(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let rest = &source[index..];
        let ident_before = index > 0 && {
            let before = bytes[index - 1];
            (before.is_ascii_alphanumeric() || before == b'_') && before != b'b'
        };
        match bytes[index] {
            _ if rest.starts_with("//") => {
                index += rest.find('\n').unwrap_or(rest.len());
            }
            _ if rest.starts_with("/*") => {
                index += rest.find("*/").map_or(rest.len(), |end| end + 2);
            }
            b'r' if !ident_before && rest[1..].trim_start_matches('#').starts_with('"') => {
                let hashes = rest[1..].len() - rest[1..].trim_start_matches('#').len();
                let close = format!("\"{}", "#".repeat(hashes));
                let body = 2 + hashes;
                index += body
                    + rest[body..]
                        .find(&close)
                        .map_or(rest.len() - body, |end| end + close.len());
            }
            b'\'' if bytes.get(index + 2) == Some(&b'\'') => index += 3,
            b'\''
                if bytes.get(index + 1) == Some(&b'\\') && bytes.get(index + 3) == Some(&b'\'') =>
            {
                index += 4
            }
            b'"' => {
                let start = index;
                index += 1;
                while index < bytes.len() && bytes[index] != b'"' {
                    index += if bytes[index] == b'\\' { 2 } else { 1 };
                }
                index += 1;
                spans.push((start, index.min(bytes.len())));
            }
            _ => index += 1,
        }
    }
    spans
}

/// The kernel feature sets `source` names: each `&[…]` slice made only of kernel feature
/// literals, and each lone literal that is a kernel feature name.
fn lane_feature_sets(source: &str, features: &BTreeMap<String, Vec<String>>) -> Vec<FeatureSet> {
    let spans = literal_spans(source);
    let literal = |&(start, end): &(usize, usize)| &source[start + 1..end - 1];
    let mut sets: Vec<FeatureSet> = spans
        .iter()
        .map(literal)
        .filter(|text| features.contains_key(*text))
        .map(|text| FeatureSet::from([text.to_owned()]))
        .collect();
    for (position, _) in source.match_indices("&[") {
        let mut cursor = position + 2;
        let mut members = FeatureSet::new();
        let mut closed = false;
        let first = spans.partition_point(|(start, _)| *start < cursor);
        for span in &spans[first..] {
            if !source[cursor..span.0].trim().is_empty() {
                break;
            }
            let text = literal(span);
            if !features.contains_key(text) {
                members.clear();
                break;
            }
            members.insert(text.to_owned());
            let rest = source[span.1..].trim_start();
            let after_comma = rest.strip_prefix(',').map(str::trim_start);
            if rest.starts_with(']') || after_comma.is_some_and(|rest| rest.starts_with(']')) {
                closed = true;
                break;
            }
            let Some(after_comma) = after_comma else {
                members.clear();
                break;
            };
            cursor = source.len() - after_comma.len();
        }
        if closed && members.len() > 1 {
            sets.push(members);
        }
    }
    sets
}

/// The feature set of every kernel UEFI clippy line in `workflow`.
fn linted_feature_sets(workflow: &str) -> Vec<FeatureSet> {
    workflow
        .lines()
        .filter_map(|line| line.trim().strip_prefix(KERNEL_CLIPPY))
        .map(|rest| {
            let mut words = rest.split_whitespace();
            let mut set = FeatureSet::new();
            while let Some(word) = words.next() {
                if word == "--features" {
                    let list = words.next().expect("--features takes a value");
                    set.extend(list.split(',').map(str::to_owned));
                }
            }
            set
        })
        .collect()
}

fn rust_sources(dir: &Path, out: &mut Vec<(String, String)>) {
    for entry in fs::read_dir(dir).expect("read xtask sources") {
        let path = entry.expect("xtask source entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let text = fs::read_to_string(&path).expect("read xtask source");
            out.push((path.display().to_string(), text));
        }
    }
}

/// Feature sets named in `sources` that no kernel clippy line in `workflow` lints, each with
/// the file that names it.
fn unlinted(
    manifest: &str,
    workflow: &str,
    sources: &[(String, String)],
) -> Vec<(String, FeatureSet)> {
    let features = kernel_features(manifest);
    let linted: Vec<FeatureSet> = linted_feature_sets(workflow)
        .iter()
        .map(|set| expand(set, &features))
        .collect();
    let mut missing: Vec<(String, FeatureSet)> = Vec::new();
    let required = std::iter::once(("the default image".to_owned(), FeatureSet::new())).chain(
        sources.iter().flat_map(|(file, text)| {
            lane_feature_sets(text, &features)
                .into_iter()
                .map(move |set| (file.clone(), set))
        }),
    );
    for (file, set) in required {
        if !linted.contains(&expand(&set, &features))
            && !missing.iter().any(|(_, seen)| *seen == set)
        {
            missing.push((file, set));
        }
    }
    missing
}

#[test]
fn ci_lints_every_kernel_feature_set_a_lane_builds() {
    let root = workspace_root();
    let manifest = fs::read_to_string(root.join("kernel/Cargo.toml")).expect("kernel manifest");
    let workflow = fs::read_to_string(root.join(".github/workflows/pr.yml")).expect("pr.yml");
    let mut sources = Vec::new();
    rust_sources(&root.join("xtask/src"), &mut sources);
    let missing = unlinted(&manifest, &workflow, &sources);
    let lines: Vec<String> = missing
        .iter()
        .map(|(file, set)| {
            let list: Vec<&str> = set.iter().map(String::as_str).collect();
            format!(
                "  {KERNEL_CLIPPY} --features {} -- -D warnings   ({file})",
                list.join(",")
            )
        })
        .collect();
    assert!(
        missing.is_empty(),
        "pr.yml's check job does not lint these kernel feature sets that xtask builds; add:\n{}",
        lines.join("\n")
    );
}

#[test]
fn feature_sets_expand_through_cargo_implications() {
    let manifest = "[package]\nname = \"k\"\n\n[features]\na = []\nb = [\"a\", \"dep:x\"]\nc = [\n    \"b\",\n    \"other/feature\",\n]\n\n[lib]\n";
    let features = kernel_features(manifest);
    assert_eq!(features.len(), 3);
    let c = expand(&FeatureSet::from(["c".to_owned()]), &features);
    assert_eq!(c, FeatureSet::from(["a", "b", "c"].map(str::to_owned)));
    let source = "build(&[\"a\", \"b\"]); one(\"c\"); other(&[\"a\", \"x\"]); text(\"[a]\");\n\
        // \"b\" in a comment, r#\"\"c\"\"# in a raw string and '\"' are not lane features\n\
        let q = '\"'; let raw = r#\"\"c\"\"#;";
    let sets = lane_feature_sets(source, &features);
    assert_eq!(
        sets,
        vec![
            FeatureSet::from(["a".to_owned()]),
            FeatureSet::from(["b".to_owned()]),
            FeatureSet::from(["c".to_owned()]),
            FeatureSet::from(["a".to_owned()]),
            FeatureSet::from(["a", "b"].map(str::to_owned)),
        ]
    );
    let workflow = "      run: |\n        cargo clippy -p clean-slate-kernel --target x86_64-unknown-uefi -- -D warnings\n        cargo clippy -p clean-slate-kernel --target x86_64-unknown-uefi --features a -- -D warnings\n        cargo clippy -p clean-slate-kernel --target x86_64-unknown-uefi --features b -- -D warnings\n";
    let sources = [("lane.rs".to_owned(), source.to_owned())];
    let missing = unlinted(manifest, workflow, &sources);
    assert_eq!(
        missing,
        vec![("lane.rs".to_owned(), FeatureSet::from(["c".to_owned()]))]
    );
}
