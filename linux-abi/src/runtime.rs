//! M9 #103 Linux runtime/memory/time/poll ABI constants and struct codecs.

use crate::errno::{LinuxErrno, EINVAL};

pub const SYS_MMAP: u64 = 9;
pub const SYS_MUNMAP: u64 = 11;
pub const SYS_BRK: u64 = 12;
pub const SYS_RT_SIGACTION: u64 = 13;
pub const SYS_RT_SIGPROCMASK: u64 = 14;
pub const SYS_IOCTL: u64 = 16;
pub const SYS_POLL: u64 = 7;
pub const SYS_ARCH_PRCTL: u64 = 158;
pub const SYS_GETPID: u64 = 39;
pub const SYS_NANOSLEEP: u64 = 35;
pub const SYS_UNAME: u64 = 63;
pub const SYS_SET_TID_ADDRESS: u64 = 218;

pub const PROT_READ: u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC: u64 = 0x4;
pub const PROT_NONE: u64 = 0x0;

pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_ANONYMOUS: u64 = 0x20;
pub const MAP_FIXED: u64 = 0x10;

pub const ARCH_SET_FS: u64 = 0x1002;
pub const ARCH_GET_FS: u64 = 0x1003;

pub const TCGETS: u64 = 0x5401;

pub const TIOCGWINSZ: u64 = 0x5413;

pub const POLLIN: i16 = 0x0001;
pub const POLLOUT: i16 = 0x0004;
pub const POLLERR: i16 = 0x0008;
pub const POLLHUP: i16 = 0x0010;
pub const POLLNVAL: i16 = 0x0020;

pub const SIG_BLOCK: i32 = 0;
pub const SIG_UNBLOCK: i32 = 1;
pub const SIG_SETMASK: i32 = 2;

pub const _NSIG: usize = 64;

pub const EINTR: LinuxErrno = LinuxErrno(4);
pub const EAGAIN: LinuxErrno = LinuxErrno(11);
pub const ENOTTY: LinuxErrno = LinuxErrno(25);
pub const ETIMEDOUT: LinuxErrno = LinuxErrno(110);

pub const UTSNAME_FIELD_LEN: usize = 65;
pub const UTSNAME_SIZE: usize = UTSNAME_FIELD_LEN * 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Sigaction {
    pub sa_handler: u64,
    pub sa_flags: u64,
    pub sa_restorer: u64,
    pub sa_mask: u64,
}

pub const SIGACTION_SIZE: usize = 32;

pub fn decode_timespec(bytes: &[u8]) -> Result<Timespec, LinuxErrno> {
    if bytes.len() < 16 {
        return Err(EINVAL);
    }
    let tv_sec = i64::from_le_bytes(bytes[0..8].try_into().expect("slice"));
    let tv_nsec = i64::from_le_bytes(bytes[8..16].try_into().expect("slice"));
    if !(0..1_000_000_000).contains(&tv_nsec) {
        return Err(EINVAL);
    }
    if tv_sec < 0 {
        return Err(EINVAL);
    }
    Ok(Timespec { tv_sec, tv_nsec })
}

pub fn encode_pollfd(pollfd: PollFd) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&pollfd.fd.to_le_bytes());
    out[4..6].copy_from_slice(&pollfd.events.to_le_bytes());
    out[6..8].copy_from_slice(&pollfd.revents.to_le_bytes());
    out
}

pub fn decode_pollfd(bytes: &[u8]) -> Result<PollFd, LinuxErrno> {
    if bytes.len() < 8 {
        return Err(EINVAL);
    }
    Ok(PollFd {
        fd: i32::from_le_bytes(bytes[0..4].try_into().expect("slice")),
        events: i16::from_le_bytes(bytes[4..6].try_into().expect("slice")),
        revents: i16::from_le_bytes(bytes[6..8].try_into().expect("slice")),
    })
}

pub fn decode_sigaction(bytes: &[u8]) -> Result<Sigaction, LinuxErrno> {
    if bytes.len() < SIGACTION_SIZE {
        return Err(EINVAL);
    }
    Ok(Sigaction {
        sa_handler: u64::from_le_bytes(bytes[0..8].try_into().expect("slice")),
        sa_flags: u64::from_le_bytes(bytes[8..16].try_into().expect("slice")),
        sa_restorer: u64::from_le_bytes(bytes[16..24].try_into().expect("slice")),
        sa_mask: u64::from_le_bytes(bytes[24..32].try_into().expect("slice")),
    })
}

pub fn encode_sigaction(action: Sigaction) -> [u8; SIGACTION_SIZE] {
    let mut out = [0u8; SIGACTION_SIZE];
    out[0..8].copy_from_slice(&action.sa_handler.to_le_bytes());
    out[8..16].copy_from_slice(&action.sa_flags.to_le_bytes());
    out[16..24].copy_from_slice(&action.sa_restorer.to_le_bytes());
    out[24..32].copy_from_slice(&action.sa_mask.to_le_bytes());
    out
}

pub fn encode_utsname_fields(
    sysname: &[u8],
    nodename: &[u8],
    release: &[u8],
    version: &[u8],
    machine: &[u8],
    domainname: &[u8],
) -> [u8; UTSNAME_SIZE] {
    let mut out = [0u8; UTSNAME_SIZE];
    let fields = [sysname, nodename, release, version, machine, domainname];
    for (index, field) in fields.iter().enumerate() {
        let start = index * UTSNAME_FIELD_LEN;
        let limit = UTSNAME_FIELD_LEN - 1;
        let copy_len = field.len().min(limit);
        out[start..start + copy_len].copy_from_slice(&field[..copy_len]);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timespec_round_trip_and_invalid() {
        let ts = Timespec {
            tv_sec: 1,
            tv_nsec: 500_000_000,
        };
        let bytes = {
            let mut b = [0u8; 16];
            b[0..8].copy_from_slice(&ts.tv_sec.to_le_bytes());
            b[8..16].copy_from_slice(&ts.tv_nsec.to_le_bytes());
            b
        };
        assert_eq!(decode_timespec(&bytes), Ok(ts));
        assert_eq!(decode_timespec(&bytes[..15]), Err(EINVAL));
        let bad_ns = {
            let mut b = bytes;
            b[8..16].copy_from_slice(&1_000_000_000i64.to_le_bytes());
            b
        };
        assert_eq!(decode_timespec(&bad_ns), Err(EINVAL));
    }

    #[test]
    fn pollfd_offsets_pinned() {
        let p = PollFd {
            fd: 7,
            events: POLLIN | POLLOUT,
            revents: 0,
        };
        let enc = encode_pollfd(p);
        assert_eq!(decode_pollfd(&enc), Ok(p));
        assert_eq!(enc[0], 7);
        assert_eq!(enc[4], (POLLIN | POLLOUT) as u8);
    }

    #[test]
    fn sigaction_layout_32_bytes() {
        let sa = Sigaction {
            sa_handler: 0x1000,
            sa_flags: 0x04,
            sa_restorer: 0,
            sa_mask: 0x08,
        };
        let enc = encode_sigaction(sa);
        assert_eq!(enc.len(), 32);
        assert_eq!(decode_sigaction(&enc), Ok(sa));
    }

    #[test]
    fn utsname_six_65_byte_fields() {
        let out = encode_utsname_fields(
            b"Linux",
            b"m9-fixture",
            b"6.1.0-clean-slate",
            b"#1 M9",
            b"x86_64",
            b"",
        );
        assert_eq!(out.len(), 390);
        assert_eq!(&out[0..5], b"Linux");
        assert_eq!(out[64], 0);
        assert_eq!(&out[65..75], b"m9-fixture");
    }
}
