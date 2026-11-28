//! `cargo xtask kernel-host-tests`: the kernel's host tests under every kernel feature set (#213).
//!
//! The feature sets are the kernel UEFI clippy lines of `pr.yml`, the same list
//! [`crate::ci_coverage`] checks every lane against, so a new lane gets a host-test run as soon
//! as it gets its clippy line. [`SKIPPED`] names the sets that do not host-test, each with why.
//! `--shard I/N` runs every Nth set from the I-th (1-based), so CI can split the sweep across
//! runners.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::process::Command;

use crate::{
    build_m6_fixture_userspace, build_native_userspace_bin, build_recovery_userspace,
    build_supervisor_userspace, ensure_embedded_service_programs, run_host_test_command,
    workspace_root, XtaskError,
};

pub(crate) const KERNEL_CLIPPY: &str =
    "cargo clippy -p clean-slate-kernel --target x86_64-unknown-uefi";

pub(crate) type FeatureSet = BTreeSet<String>;

/// The feature set of every kernel UEFI clippy line in `workflow`.
pub(crate) fn linted_feature_sets(workflow: &str) -> Vec<FeatureSet> {
    workflow
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let command = line.strip_prefix("run:").map_or(line, str::trim_start);
            command.strip_prefix(KERNEL_CLIPPY)
        })
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

/// Feature sets that are linted but not host-tested, with the reason.
const SKIPPED: &[(&str, &str)] = &[(
    "m10-virtio-gpu-self-test",
    "the lane drives the real VirtIO-GPU MMIO backend, which host tests do not compile; \
     the backend's logic is host-tested through `virtio_gpu::fake` in every build",
)];

/// One `--features` value per kernel clippy line in `pr.yml` (empty for the default build),
/// in workflow order, without repeats.
pub(crate) fn feature_sets(workflow: &str) -> Vec<String> {
    let mut sets: Vec<String> = Vec::new();
    for set in linted_feature_sets(workflow) {
        let list = set.into_iter().collect::<Vec<_>>().join(",");
        if !sets.contains(&list) {
            sets.push(list);
        }
    }
    sets
}

fn parse_shard(args: &[OsString]) -> Result<(usize, usize), XtaskError> {
    let invalid = || XtaskError::InvalidOption("kernel-host-tests takes [--shard I/N]".to_owned());
    match args {
        [] => Ok((1, 1)),
        [flag, value] if flag == "--shard" => {
            let value = value.to_str().ok_or_else(invalid)?;
            let (index, count) = value.split_once('/').ok_or_else(invalid)?;
            let index: usize = index.parse().map_err(|_| invalid())?;
            let count: usize = count.parse().map_err(|_| invalid())?;
            if count == 0 || index == 0 || index > count {
                return Err(invalid());
            }
            Ok((index, count))
        }
        _ => Err(invalid()),
    }
}

/// Every userspace ELF some kernel feature set embeds (`kernel/build.rs`).
fn build_embedded_userspace() -> Result<(), XtaskError> {
    ensure_embedded_service_programs()?;
    build_supervisor_userspace(true)?;
    build_recovery_userspace(true)?;
    build_m6_fixture_userspace(true)?;
    build_native_userspace_bin(
        "clean-slate-storage-probe",
        "clean-slate-storage-probe-userspace",
    )?;
    build_native_userspace_bin("clean-slate-net-probe", "clean-slate-net-probe-userspace")
}

pub(crate) fn run(args: &[OsString]) -> Result<(), XtaskError> {
    let (index, count) = parse_shard(args)?;
    let workflow = fs::read_to_string(workspace_root().join(".github/workflows/pr.yml"))?;
    let sets: Vec<String> = feature_sets(&workflow)
        .into_iter()
        .filter(|set| !SKIPPED.iter().any(|(skipped, _)| skipped == set))
        .enumerate()
        .filter(|(position, _)| position % count == index - 1)
        .map(|(_, set)| set)
        .collect();
    build_embedded_userspace()?;
    let mut failed = Vec::new();
    for set in &sets {
        let label = if set.is_empty() { "(default)" } else { set };
        println!("[KHT ] cargo test -p clean-slate-kernel --lib, features {label}");
        let mut test = Command::new("cargo");
        test.current_dir(workspace_root())
            .args(["test", "-p", "clean-slate-kernel", "--lib"]);
        if !set.is_empty() {
            test.arg("--features").arg(set);
        }
        if let Err(error) = run_host_test_command(&mut test) {
            eprintln!("[KHT ] FAIL {label}: {error}");
            failed.push(label.to_owned());
        }
    }
    for (set, reason) in SKIPPED {
        println!("[KHT ] skipped {set}: {reason}");
    }
    if failed.is_empty() {
        println!(
            "[KHT ] PASS {} kernel feature sets (shard {index}/{count})",
            sets.len()
        );
        Ok(())
    } else {
        Err(XtaskError::CommandFailed {
            command: "cargo xtask kernel-host-tests".to_owned(),
            status: format!("host tests failed for: {}", failed.join(" ")),
        })
    }
}

#[test]
fn every_skipped_set_is_a_linted_set() {
    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/pr.yml")).expect("pr.yml");
    let sets = feature_sets(&workflow);
    assert!(
        sets.iter().any(String::is_empty),
        "the default build is a set"
    );
    for (skipped, _) in SKIPPED {
        assert!(
            sets.iter().any(|set| set == skipped),
            "SKIPPED names {skipped}, which pr.yml no longer lints; drop it"
        );
    }
}

#[test]
fn shards_split_the_sets() {
    let shard = |text: &str| parse_shard(&["--shard".into(), text.into()]);
    assert_eq!(parse_shard(&[]).ok(), Some((1, 1)));
    assert_eq!(shard("2/3").ok(), Some((2, 3)));
    for bad in ["0/3", "4/3", "1/0", "x/2", "2"] {
        assert!(shard(bad).is_err(), "{bad}");
    }
}
