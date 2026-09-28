//! Per-run OVMF variable-store copies under `target/` (#193).
//!
//! Every QEMU boot starts from a fresh copy of the pristine vars template.
//! [`RuntimeVarsCopy`] owns one copy and deletes it when dropped, and
//! [`sweep_stale`] removes copies whose owning xtask process is gone.
//!
//! Liveness is carried by a sidecar `<stem>.lock` file that the owner holds
//! an exclusive [`File::lock`] on for the whole run. The owner creates and
//! locks the sidecar before the `.fd` copy exists and removes the `.fd` before
//! releasing it, so a sidecar that can be locked means nobody owns that copy.
//! The lock is released by the OS when the owner exits for any reason
//! (error, abort, external kill), which pid checks cannot promise under pid
//! reuse.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime};

/// File-name prefix shared by every runtime copy and its sidecar lock.
pub(crate) const RUNTIME_VARS_PREFIX: &str = "OVMF_VARS.runtime.";
const VARS_SUFFIX: &str = ".fd";
const LOCK_SUFFIX: &str = ".lock";
/// Sequence numbers tried per process before giving up on a free name.
const MAX_NAME_ATTEMPTS: u32 = 1024;
/// A copy without a sidecar lock (written by an older xtask) is only removed
/// once it is at least this old, since nothing proves its owner has exited.
pub(crate) const UNLOCKED_COPY_MIN_AGE: Duration = Duration::from_secs(60 * 60);

static NEXT_SEQUENCE: AtomicU32 = AtomicU32::new(0);

/// A runtime OVMF vars copy, removed together with its sidecar lock on drop.
///
/// Drop this only after QEMU has exited: Windows refuses to delete a file
/// another process still has open.
#[derive(Debug)]
pub(crate) struct RuntimeVarsCopy {
    vars_path: PathBuf,
    lock_path: PathBuf,
    lock: Option<File>,
}

impl RuntimeVarsCopy {
    /// Copies `template` to a fresh, uniquely named runtime file in `dir`.
    pub(crate) fn create(dir: &Path, template: &Path) -> io::Result<Self> {
        fs::create_dir_all(dir)?;
        let pid = std::process::id();
        for _ in 0..MAX_NAME_ATTEMPTS {
            let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let stem = format!("{RUNTIME_VARS_PREFIX}{pid}.{sequence}");
            let lock_path = dir.join(format!("{stem}{LOCK_SUFFIX}"));
            let lock = match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(file) => file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            };
            let copy = Self {
                vars_path: dir.join(format!("{stem}{VARS_SUFFIX}")),
                lock_path,
                lock: Some(lock),
            };
            if let Some(lock) = &copy.lock {
                lock.lock()?;
            }
            fs::copy(template, &copy.vars_path)?;
            return Ok(copy);
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "no free OVMF runtime vars name in {} after {MAX_NAME_ATTEMPTS} attempts",
                dir.display()
            ),
        ))
    }

    pub(crate) fn path(&self) -> &Path {
        &self.vars_path
    }
}

impl Drop for RuntimeVarsCopy {
    fn drop(&mut self) {
        let removed = match fs::remove_file(&self.vars_path) {
            Ok(()) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => true,
            Err(error) => {
                eprintln!(
                    "[OVMF] warning: could not remove {}: {error}; left for the next sweep",
                    self.vars_path.display()
                );
                false
            }
        };
        // Keep the sidecar when the copy survived so a later sweep does not
        // mistake an orphan for a pre-lock legacy file and wait out its age.
        drop(self.lock.take());
        if removed {
            let _ = fs::remove_file(&self.lock_path);
        }
    }
}

/// What [`sweep_stale`] did with the runtime files it found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SweepReport {
    /// Stale copies deleted.
    pub(crate) removed: usize,
    /// Copies left alone because a live xtask still owns them, or because an
    /// unlocked copy is younger than [`UNLOCKED_COPY_MIN_AGE`].
    pub(crate) kept: usize,
    /// Stale copies that could not be deleted (for example still open).
    pub(crate) failed: usize,
}

/// Removes runtime vars copies in `dir` whose owner is gone.
///
/// Copies owned by a concurrent xtask in the same `target/` stay untouched.
pub(crate) fn sweep_stale(dir: &Path, now: SystemTime) -> io::Result<SweepReport> {
    let mut report = SweepReport::default();
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(report),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.starts_with(RUNTIME_VARS_PREFIX) {
            continue;
        }
        if let Some(stem) = name.strip_suffix(LOCK_SUFFIX) {
            sweep_locked_stem(dir, stem, &mut report);
        } else if let Some(stem) = name.strip_suffix(VARS_SUFFIX) {
            if !dir.join(format!("{stem}{LOCK_SUFFIX}")).exists() {
                sweep_unlocked_copy(&entry.path(), now, &mut report);
            }
        }
    }
    Ok(report)
}

fn sweep_locked_stem(dir: &Path, stem: &str, report: &mut SweepReport) {
    let lock_path = dir.join(format!("{stem}{LOCK_SUFFIX}"));
    let vars_path = dir.join(format!("{stem}{VARS_SUFFIX}"));
    let Ok(lock) = OpenOptions::new().write(true).open(&lock_path) else {
        // Owner finished and removed it between listing and open.
        return;
    };
    match lock.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => {
            report.kept += usize::from(vars_path.exists());
            return;
        }
        Err(fs::TryLockError::Error(_)) => {
            report.failed += 1;
            return;
        }
    }
    let vars_removed = match fs::remove_file(&vars_path) {
        Ok(()) => {
            report.removed += 1;
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(_) => {
            report.failed += 1;
            false
        }
    };
    drop(lock);
    if vars_removed {
        let _ = fs::remove_file(&lock_path);
    }
}

fn sweep_unlocked_copy(path: &Path, now: SystemTime, report: &mut SweepReport) {
    let Ok(metadata) = fs::metadata(path) else {
        return;
    };
    if !is_older_than(&metadata, now, UNLOCKED_COPY_MIN_AGE) {
        report.kept += 1;
        return;
    }
    match fs::remove_file(path) {
        Ok(()) => report.removed += 1,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => report.failed += 1,
    }
}

/// Age from the newer of creation and modification time: Windows `CopyFile`
/// keeps the template's modification time, so a fresh copy can look old.
fn is_older_than(metadata: &fs::Metadata, now: SystemTime, min_age: Duration) -> bool {
    let newest = match (metadata.modified(), metadata.created()) {
        (Ok(modified), Ok(created)) => modified.max(created),
        (Ok(time), Err(_)) | (Err(_), Ok(time)) => time,
        (Err(_), Err(_)) => return false,
    };
    now.duration_since(newest).is_ok_and(|age| age >= min_age)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    fn scratch_dir(tag: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("clean-slate-ovmf-vars-{tag}-{unique}"));
        fs::create_dir_all(&dir).expect("mkdir");
        dir
    }

    fn runtime_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .into_string()
                    .expect("utf8")
            })
            .filter(|name| name.starts_with(RUNTIME_VARS_PREFIX))
            .collect();
        names.sort();
        names
    }

    fn template(dir: &Path) -> PathBuf {
        let path = dir.join("template-vars.fd");
        fs::write(&path, b"pristine").expect("write template");
        path
    }

    #[test]
    fn copy_holds_template_bytes_and_is_removed_on_drop() {
        let dir = scratch_dir("drop");
        let template = template(&dir);
        let copy = RuntimeVarsCopy::create(&dir, &template).expect("create");
        assert_eq!(fs::read(copy.path()).expect("read copy"), b"pristine");
        assert_eq!(runtime_names(&dir).len(), 2, "copy plus sidecar lock");
        drop(copy);
        assert!(runtime_names(&dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copies_in_one_process_get_distinct_names() {
        let dir = scratch_dir("distinct");
        let template = template(&dir);
        let first = RuntimeVarsCopy::create(&dir, &template).expect("first");
        let second = RuntimeVarsCopy::create(&dir, &template).expect("second");
        assert_ne!(first.path(), second.path());
        drop(first);
        assert!(second.path().is_file());
        drop(second);
        assert!(runtime_names(&dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_skips_names_left_by_an_earlier_process() {
        let dir = scratch_dir("collide");
        let template = template(&dir);
        let pid = std::process::id();
        let next = NEXT_SEQUENCE.load(Ordering::Relaxed);
        let mut squatted = Vec::new();
        for sequence in next..next + 8 {
            let lock = dir.join(format!(
                "{RUNTIME_VARS_PREFIX}{pid}.{sequence}{LOCK_SUFFIX}"
            ));
            fs::write(&lock, b"").expect("squat");
            squatted.push(lock);
        }
        let copy = RuntimeVarsCopy::create(&dir, &template).expect("create");
        assert!(copy.path().is_file());
        drop(copy);
        for lock in squatted {
            assert!(
                lock.is_file(),
                "foreign sidecar {} untouched",
                lock.display()
            );
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_keeps_copy_owned_by_live_holder() {
        let dir = scratch_dir("live");
        let template = template(&dir);
        let copy = RuntimeVarsCopy::create(&dir, &template).expect("create");
        let report = sweep_stale(&dir, SystemTime::now()).expect("sweep");
        assert_eq!(
            report,
            SweepReport {
                removed: 0,
                kept: 1,
                failed: 0
            }
        );
        assert!(copy.path().is_file());
        drop(copy);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_removes_copy_whose_lock_is_free() {
        let dir = scratch_dir("orphan");
        let stem = format!("{RUNTIME_VARS_PREFIX}4294967295.0");
        fs::write(dir.join(format!("{stem}{VARS_SUFFIX}")), b"stale").expect("vars");
        fs::write(dir.join(format!("{stem}{LOCK_SUFFIX}")), b"").expect("lock");
        let report = sweep_stale(&dir, SystemTime::now()).expect("sweep");
        assert_eq!(report.removed, 1);
        assert_eq!(report.kept, 0);
        assert!(runtime_names(&dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_removes_lock_left_without_a_copy() {
        let dir = scratch_dir("bare-lock");
        let lock = dir.join(format!("{RUNTIME_VARS_PREFIX}4294967295.7{LOCK_SUFFIX}"));
        fs::write(&lock, b"").expect("lock");
        let report = sweep_stale(&dir, SystemTime::now()).expect("sweep");
        assert_eq!(report, SweepReport::default());
        assert!(!lock.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_ages_out_unlocked_legacy_copies_only() {
        let dir = scratch_dir("legacy");
        let legacy = dir.join(format!("{RUNTIME_VARS_PREFIX}1234{VARS_SUFFIX}"));
        fs::write(&legacy, b"legacy").expect("legacy");
        let unrelated = dir.join("OVMF_VARS.fd");
        fs::write(&unrelated, b"working").expect("unrelated");

        let fresh = sweep_stale(&dir, SystemTime::now()).expect("sweep fresh");
        assert_eq!(fresh.kept, 1);
        assert!(
            legacy.is_file(),
            "young unlocked copy may belong to a live run"
        );

        let later = SystemTime::now() + UNLOCKED_COPY_MIN_AGE + Duration::from_secs(1);
        let aged = sweep_stale(&dir, later).expect("sweep aged");
        assert_eq!(aged.removed, 1);
        assert!(!legacy.exists());
        assert!(unrelated.is_file(), "non-runtime files are never swept");
        let _ = fs::remove_dir_all(&dir);
    }

    /// QEMU on Windows opens pflash files without `FILE_SHARE_DELETE`, so a
    /// copy dropped while it is still open survives until a later sweep.
    #[cfg(windows)]
    #[test]
    fn copy_still_open_elsewhere_is_left_for_the_sweep() {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_READ_WRITE: u32 = 0x1 | 0x2;

        let dir = scratch_dir("open");
        let template = template(&dir);
        let copy = RuntimeVarsCopy::create(&dir, &template).expect("create");
        let vars = copy.path().to_path_buf();
        let held = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ_WRITE)
            .open(&vars)
            .expect("open like qemu");
        drop(copy);
        assert!(vars.is_file());
        assert_eq!(runtime_names(&dir).len(), 2, "sidecar kept for the sweep");

        let blocked = sweep_stale(&dir, SystemTime::now()).expect("sweep open");
        assert_eq!(blocked.failed, 1);
        assert!(vars.is_file());

        drop(held);
        let cleared = sweep_stale(&dir, SystemTime::now()).expect("sweep closed");
        assert_eq!(cleared.removed, 1);
        assert!(runtime_names(&dir).is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_of_missing_dir_is_empty() {
        let dir = std::env::temp_dir().join("clean-slate-ovmf-vars-does-not-exist-193");
        assert_eq!(
            sweep_stale(&dir, SystemTime::now()).expect("sweep"),
            SweepReport::default()
        );
    }
}
