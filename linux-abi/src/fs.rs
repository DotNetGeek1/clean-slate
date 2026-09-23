//! Linux filesystem syscall numbers and struct encoders (#101).

pub const SYS_READ: u64 = 0;
pub const SYS_OPEN: u64 = 2;
pub const SYS_STAT: u64 = 4;
pub const SYS_LSTAT: u64 = 6;
pub const SYS_LSEEK: u64 = 8;
pub const SYS_GETCWD: u64 = 79;
pub const SYS_MKDIR: u64 = 83;
pub const SYS_GETDENTS64: u64 = 217;

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_CREAT: u32 = 0o100;
pub const O_TRUNC: u32 = 0o1000;
pub const O_APPEND: u32 = 0o2000;
pub const O_DIRECTORY: u32 = 0o200000;
pub const O_LARGEFILE: u32 = 0o100000;
pub const O_CLOEXEC: u32 = 0o2000000;
pub const O_NONBLOCK: u32 = 0o4000;

pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

pub const DT_UNKNOWN: u8 = 0;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

use crate::LinuxErrno;

pub const EEXIST: LinuxErrno = LinuxErrno(17);
pub const ENOTDIR: LinuxErrno = LinuxErrno(20);
pub const EISDIR: LinuxErrno = LinuxErrno(21);
pub const ENOSPC: LinuxErrno = LinuxErrno(28);
pub const EROFS: LinuxErrno = LinuxErrno(30);
pub const ERANGE: LinuxErrno = LinuxErrno(34);
pub const ENAMETOOLONG: LinuxErrno = LinuxErrno(36);
pub const ELOOP: LinuxErrno = LinuxErrno(40);
pub const ESPIPE: LinuxErrno = LinuxErrno(29);
pub const EFBIG: LinuxErrno = LinuxErrno(27);
pub const EIO: LinuxErrno = LinuxErrno(5);

/// x86-64 `struct stat` — 144 bytes, field-by-field little-endian.
pub fn encode_stat144(out: &mut [u8], fields: &LinuxStatFields) -> bool {
    if out.len() < 144 {
        return false;
    }
    out.fill(0);
    write_u64(out, 0, fields.st_dev);
    write_u64(out, 8, fields.st_ino);
    write_u64(out, 16, fields.st_nlink);
    write_u32(out, 24, fields.st_mode);
    write_u32(out, 28, fields.st_uid);
    write_u32(out, 32, fields.st_gid);
    write_u64(out, 40, fields.st_rdev);
    write_i64(out, 48, fields.st_size);
    write_i32(out, 56, fields.st_blksize);
    write_i64(out, 60, fields.st_blocks);
    // timespec at 72, 88, 104 — left zero (no fake time)
    true
}

#[derive(Clone, Copy, Debug, Default)]
pub struct LinuxStatFields {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i32,
    pub st_blocks: i64,
}

fn write_u64(out: &mut [u8], off: usize, v: u64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn write_i64(out: &mut [u8], off: usize, v: i64) {
    out[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_i32(out: &mut [u8], off: usize, v: i32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Encode one `linux_dirent64` record; returns bytes written or 0 if buffer too small.
pub fn encode_dirent64(buf: &mut [u8], d_ino: u64, d_off: i64, d_type: u8, name: &[u8]) -> usize {
    let name_len = name.len() + 1;
    let reclen = align8(19 + name_len);
    if buf.len() < reclen {
        return 0;
    }
    buf[..reclen].fill(0);
    buf[0..8].copy_from_slice(&d_ino.to_le_bytes());
    buf[8..16].copy_from_slice(&d_off.to_le_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    buf[18] = d_type;
    buf[19..19 + name.len()].copy_from_slice(name);
    reclen
}

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat144_field_offsets() {
        let fields = LinuxStatFields {
            st_dev: 1,
            st_ino: 2,
            st_nlink: 3,
            st_mode: 4,
            st_uid: 5,
            st_gid: 6,
            st_rdev: 7,
            st_size: 8,
            st_blksize: 4096,
            st_blocks: 9,
        };
        let mut buf = [0u8; 144];
        assert!(encode_stat144(&mut buf, &fields));
        assert_eq!(u64::from_le_bytes(buf[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(buf[8..16].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(buf[16..24].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(buf[24..28].try_into().unwrap()), 4);
        assert_eq!(u32::from_le_bytes(buf[28..32].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(buf[32..36].try_into().unwrap()), 6);
        assert_eq!(u64::from_le_bytes(buf[40..48].try_into().unwrap()), 7);
        assert_eq!(i64::from_le_bytes(buf[48..56].try_into().unwrap()), 8);
        assert_eq!(i32::from_le_bytes(buf[56..60].try_into().unwrap()), 4096);
        assert_eq!(i64::from_le_bytes(buf[60..68].try_into().unwrap()), 9);
        assert_eq!(buf.len(), 144);
    }

    #[test]
    fn dirent64_layout() {
        let mut buf = [0u8; 32];
        let n = encode_dirent64(&mut buf, 9, 10, DT_REG, b"busybox");
        assert_eq!(n, 32);
        assert_eq!(u16::from_le_bytes(buf[16..18].try_into().unwrap()), 32);
        assert_eq!(buf[18], DT_REG);
    }
}
