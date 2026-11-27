//! The persisted name table of the Linux `/home` directory (#304): a native directory
//! (`clean_slate_native_abi::directory`, #312) whose table is the object
//! [`HOME_TABLE_OBJECT_ID`]. The broker is a client of the native directory model: the same
//! table format, the same entry object ids, and the same `DIRECTORY` capability rule.

use clean_slate_linux_abi::{LinuxErrno, EINVAL, ENAMETOOLONG, ENOSPC};
use clean_slate_native_abi::directory::{self, DirectoryError};

pub use clean_slate_native_abi::directory::{
    DirectoryTable as HomeTable, DIRECTORY_MAX_ENTRY_BYTES as HOME_MAX_FILE_BYTES,
    DIRECTORY_TABLE_BYTES as HOME_TABLE_BYTES,
};

/// The `/home` directory: its table object. Holding `READ`/`WRITE` with `DIRECTORY` on it is
/// holding them on every file in `/home`.
pub const HOME_TABLE_OBJECT_ID: u64 = 0x004D_0000;

pub const fn home_file_object_id(slot: usize) -> u64 {
    directory::entry_object_id(HOME_TABLE_OBJECT_ID, slot)
}

/// The errno a refused directory operation is in Linux.
pub fn errno(error: DirectoryError) -> LinuxErrno {
    match error {
        DirectoryError::NameTooLong => ENAMETOOLONG,
        DirectoryError::Full => ENOSPC,
        DirectoryError::InvalidName | DirectoryError::NoEntry | DirectoryError::SlotTaken => EINVAL,
    }
}

/// A name `/home` can hold: 1 to 27 bytes, no `/` or NUL, not `.` or `..`.
pub fn validate_name(name: &[u8]) -> Result<(), LinuxErrno> {
    directory::validate_name(name).map_err(errno)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::directory::DIRECTORY_MAX_ENTRIES as HOME_MAX_FILES;

    #[test]
    fn file_object_ids_follow_the_table_object() {
        assert_eq!(home_file_object_id(0), HOME_TABLE_OBJECT_ID + 1);
        assert_eq!(
            home_file_object_id(HOME_MAX_FILES - 1),
            HOME_TABLE_OBJECT_ID + HOME_MAX_FILES as u64
        );
    }

    #[test]
    fn refusals_keep_their_linux_errnos() {
        assert_eq!(validate_name(&[b'x'; 28]), Err(ENAMETOOLONG));
        assert_eq!(validate_name(b".."), Err(EINVAL));
        assert_eq!(HomeTable::empty().free_slot().map_err(errno), Ok(0));
        let mut full = HomeTable::empty();
        for index in 0..HOME_MAX_FILES {
            full.create_at(index, &[b'a' + index as u8]).unwrap();
        }
        assert_eq!(full.free_slot().map_err(errno), Err(ENOSPC));
    }
}
