//! #312 native storage probe, the app of the `test-m10-storage` lane.
//!
//! Each boot, [`run`] opens [`STORAGE_PROBE_FILE_NAME`] in the probe's directory and moves it
//! one [`ProbeStage`] along, using only the native storage interface
//! (`clean_slate_runtime::storage`): a missing entry is created and 1 MiB is written through
//! a shared buffer in offset writes, then committed; a 1 MiB entry is read back by name
//! through the buffer, checked, and truncated to 4 KiB; a 4 KiB entry is read back, checked,
//! and unlinked. The lane boots three times on one data disk, so every stage starts from what
//! the last boot committed.

#![cfg_attr(not(test), no_std)]

use clean_slate_native_abi::status::{
    STATUS_EAGAIN, STATUS_ENOENT, STATUS_ESTALE, STATUS_ETIMEDOUT,
};
use clean_slate_runtime::buffer::SharedBuffer;
use clean_slate_runtime::storage::{Directory, Entry};
use clean_slate_runtime::{Error, Syscalls};
use clean_slate_service_fixtures::storage_probe::{
    probe_byte, ProbeFailure, ProbeStage, ProbeStep, STORAGE_PROBE_FILE_BYTES,
    STORAGE_PROBE_FILE_NAME, STORAGE_PROBE_TRUNCATED_BYTES,
};

const FILE_BYTES: usize = STORAGE_PROBE_FILE_BYTES as usize;
const TRUNCATED_BYTES: usize = STORAGE_PROBE_TRUNCATED_BYTES as usize;

/// Runs one stage. `note` is called as each step starts, for the lane's progress lines.
pub fn run<S: Syscalls>(
    sys: &mut S,
    directory: Directory,
    mut note: impl FnMut(&mut S, ProbeStep),
) -> Result<ProbeStage, ProbeFailure> {
    note(sys, ProbeStep::OpenEntry);
    match directory.open(sys, STORAGE_PROBE_FILE_NAME) {
        // An empty entry is one a boot created and did not get to fill.
        Err(Error::Failed(STATUS_ENOENT)) => write_stage(sys, directory, &mut note),
        Ok(entry) if entry.len == 0 => write_stage(sys, directory, &mut note),
        Err(error) => Err(failure(ProbeStep::OpenEntry, error)),
        Ok(entry) if entry.len == STORAGE_PROBE_FILE_BYTES => {
            truncate_stage(sys, directory, entry, &mut note)
        }
        Ok(entry) if entry.len == STORAGE_PROBE_TRUNCATED_BYTES => {
            remove_stage(sys, directory, entry, &mut note)
        }
        Ok(entry) => Err(ProbeFailure {
            step: ProbeStep::UnexpectedLength,
            detail: entry.len,
        }),
    }
}

/// Creates the entry (or reuses an empty one) and writes 1 MiB into it through a shared buffer, eight 128 KiB offset
/// writes; recording the length commits the bytes and the name together.
fn write_stage<S: Syscalls>(
    sys: &mut S,
    directory: Directory,
    note: &mut impl FnMut(&mut S, ProbeStep),
) -> Result<ProbeStage, ProbeFailure> {
    note(sys, ProbeStep::CreateEntry);
    let entry = directory
        .create(sys, STORAGE_PROBE_FILE_NAME)
        .map_err(|error| failure(ProbeStep::CreateEntry, error))?;
    let mut buffer = allocate(sys, note)?;
    for (offset, byte) in buffer.bytes().iter_mut().enumerate() {
        *byte = probe_byte(offset as u64);
    }
    note(sys, ProbeStep::WriteBuffer);
    let written = entry
        .object
        .write_from(sys, 0, buffer.handle(), 0, STORAGE_PROBE_FILE_BYTES)
        .map_err(|error| failure(ProbeStep::WriteBuffer, error));
    let _ = buffer.release(sys);
    written?;
    note(sys, ProbeStep::CommitEntry);
    directory
        .set_len(sys, entry.slot, STORAGE_PROBE_FILE_BYTES)
        .map_err(|error| failure(ProbeStep::CommitEntry, error))?;
    expect_len(sys, directory, Some(STORAGE_PROBE_FILE_BYTES), note)?;
    Ok(ProbeStage::Wrote)
}

/// Reads the 1 MiB back by name through a shared buffer, checks every byte, then truncates
/// the entry to 4 KiB and commits.
fn truncate_stage<S: Syscalls>(
    sys: &mut S,
    directory: Directory,
    entry: Entry,
    note: &mut impl FnMut(&mut S, ProbeStep),
) -> Result<ProbeStage, ProbeFailure> {
    let mut buffer = allocate(sys, note)?;
    note(sys, ProbeStep::ReadBuffer);
    let read = entry
        .object
        .read_into(sys, 0, buffer.handle(), 0, STORAGE_PROBE_FILE_BYTES);
    let checked = match read {
        Ok(len) if len == STORAGE_PROBE_FILE_BYTES => {
            note(sys, ProbeStep::CheckBytes);
            check_bytes(buffer.bytes())
        }
        Ok(len) => Err(ProbeFailure {
            step: ProbeStep::ReadBuffer,
            detail: len,
        }),
        Err(error) => Err(failure(ProbeStep::ReadBuffer, error)),
    };
    let _ = buffer.release(sys);
    checked?;
    note(sys, ProbeStep::Truncate);
    entry
        .object
        .truncate(sys, STORAGE_PROBE_TRUNCATED_BYTES)
        .map_err(|error| failure(ProbeStep::Truncate, error))?;
    note(sys, ProbeStep::RecordLength);
    directory
        .set_len(sys, entry.slot, STORAGE_PROBE_TRUNCATED_BYTES)
        .map_err(|error| failure(ProbeStep::RecordLength, error))?;
    expect_len(sys, directory, Some(STORAGE_PROBE_TRUNCATED_BYTES), note)?;
    Ok(ProbeStage::Truncated)
}

/// Reads the truncated entry back, checks it ends at 4 KiB, then unlinks it.
fn remove_stage<S: Syscalls>(
    sys: &mut S,
    directory: Directory,
    entry: Entry,
    note: &mut impl FnMut(&mut S, ProbeStep),
) -> Result<ProbeStage, ProbeFailure> {
    note(sys, ProbeStep::ReadTruncated);
    // A read past the new end shows the cut: only 4 KiB come back.
    let mut bytes = [0u8; TRUNCATED_BYTES + 512];
    match entry.object.read_at(sys, 0, &mut bytes) {
        Ok(TRUNCATED_BYTES) => {}
        Ok(len) => {
            return Err(ProbeFailure {
                step: ProbeStep::ReadTruncated,
                detail: len as u64,
            })
        }
        Err(error) => return Err(failure(ProbeStep::ReadTruncated, error)),
    }
    note(sys, ProbeStep::CheckBytes);
    check_bytes(&bytes[..TRUNCATED_BYTES])?;
    note(sys, ProbeStep::Unlink);
    directory
        .unlink(sys, STORAGE_PROBE_FILE_NAME)
        .map_err(|error| failure(ProbeStep::Unlink, error))?;
    expect_len(sys, directory, None, note)?;
    Ok(ProbeStage::Removed)
}

fn allocate<S: Syscalls>(
    sys: &mut S,
    note: &mut impl FnMut(&mut S, ProbeStep),
) -> Result<SharedBuffer, ProbeFailure> {
    note(sys, ProbeStep::AllocateBuffer);
    SharedBuffer::allocate(sys, FILE_BYTES)
        .map_err(|error| failure(ProbeStep::AllocateBuffer, error))
}

/// Opens the entry again from the committed table: `len`, or no entry for `None`.
fn expect_len<S: Syscalls>(
    sys: &mut S,
    directory: Directory,
    len: Option<u64>,
    note: &mut impl FnMut(&mut S, ProbeStep),
) -> Result<(), ProbeFailure> {
    note(sys, ProbeStep::ReopenEntry);
    match (directory.open(sys, STORAGE_PROBE_FILE_NAME), len) {
        (Ok(entry), Some(len)) if entry.len == len => Ok(()),
        (Err(Error::Failed(STATUS_ENOENT)), None) => Ok(()),
        (Ok(entry), _) => Err(ProbeFailure {
            step: ProbeStep::ReopenEntry,
            detail: entry.len,
        }),
        (Err(error), _) => Err(failure(ProbeStep::ReopenEntry, error)),
    }
}

/// The first offset whose byte is not the probe pattern fails the check.
fn check_bytes(bytes: &[u8]) -> Result<(), ProbeFailure> {
    match bytes
        .iter()
        .enumerate()
        .position(|(offset, byte)| *byte != probe_byte(offset as u64))
    {
        None => Ok(()),
        Some(offset) => Err(ProbeFailure {
            step: ProbeStep::CheckBytes,
            detail: offset as u64,
        }),
    }
}

fn failure(step: ProbeStep, error: Error) -> ProbeFailure {
    ProbeFailure {
        step,
        detail: match error {
            Error::Gone => STATUS_ESTALE,
            Error::TimedOut => STATUS_ETIMEDOUT,
            Error::WouldBlock => STATUS_EAGAIN,
            Error::Failed(status) => status,
        },
    }
}

#[cfg(test)]
mod tests;
