//! Linux socket ABI constants and `sockaddr_in` codec (M9 #105).

/// `socket(2)` — `socket(domain, type, protocol)`.
pub const SYS_SOCKET: u64 = 41;
/// `connect(2)`.
pub const SYS_CONNECT: u64 = 42;
/// `sendto(2)`.
pub const SYS_SENDTO: u64 = 44;
/// `bind(2)`.
pub const SYS_BIND: u64 = 49;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;

pub const SOCK_STREAM: u32 = 1;
pub const SOCK_DGRAM: u32 = 2;
pub const SOCK_CLOEXEC: u32 = 0x80000;
pub const SOCK_NONBLOCK: u32 = 0x800;

pub const IPPROTO_IP: u32 = 0;
pub const IPPROTO_TCP: u32 = 6;
pub const IPPROTO_UDP: u32 = 17;

pub const MSG_NOSIGNAL: u32 = 0x4000;

pub const SOCKADDR_IN_LEN: usize = 16;

pub const EAFNOSUPPORT: crate::LinuxErrno = crate::LinuxErrno(97);
pub const EPROTONOSUPPORT: crate::LinuxErrno = crate::LinuxErrno(93);
pub const ECONNREFUSED: crate::LinuxErrno = crate::LinuxErrno(111);
pub const ETIMEDOUT: crate::LinuxErrno = crate::LinuxErrno(110);
pub const ENOTCONN: crate::LinuxErrno = crate::LinuxErrno(107);
pub const EISCONN: crate::LinuxErrno = crate::LinuxErrno(106);
pub const EADDRINUSE: crate::LinuxErrno = crate::LinuxErrno(98);
pub const ENETUNREACH: crate::LinuxErrno = crate::LinuxErrno(101);
pub const ENOBUFS: crate::LinuxErrno = crate::LinuxErrno(105);
pub const EMSGSIZE: crate::LinuxErrno = crate::LinuxErrno(90);
pub const EDESTADDRREQ: crate::LinuxErrno = crate::LinuxErrno(89);
pub const EAGAIN: crate::LinuxErrno = crate::LinuxErrno(11);
pub const ECONNRESET: crate::LinuxErrno = crate::LinuxErrno(104);
pub const EIO: crate::LinuxErrno = crate::LinuxErrno(5);

/// IPv4 `sockaddr_in` (Linux UAPI layout, no transmute).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockaddrIn {
    pub port: u16,
    pub addr: [u8; 4],
}

impl SockaddrIn {
    pub const fn any_ephemeral() -> Self {
        Self {
            port: 0,
            addr: [0, 0, 0, 0],
        }
    }

    pub fn encode(&self) -> [u8; SOCKADDR_IN_LEN] {
        let mut out = [0u8; SOCKADDR_IN_LEN];
        out[0..2].copy_from_slice(&AF_INET.to_le_bytes());
        out[2..4].copy_from_slice(&self.port.to_be_bytes());
        out[4..8].copy_from_slice(&self.addr);
        out
    }

    pub fn decode(bytes: &[u8], socklen: u32) -> Result<Self, crate::LinuxErrno> {
        if socklen != SOCKADDR_IN_LEN as u32 || bytes.len() < SOCKADDR_IN_LEN {
            return Err(crate::EINVAL);
        }
        let family = u16::from_le_bytes([bytes[0], bytes[1]]);
        if family != AF_INET {
            return Err(EAFNOSUPPORT);
        }
        let port = u16::from_be_bytes([bytes[2], bytes[3]]);
        let addr = [bytes[4], bytes[5], bytes[6], bytes[7]];
        Ok(Self { port, addr })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sockaddr_in_roundtrip_and_endianness() {
        let sa = SockaddrIn {
            port: 53,
            addr: [10, 77, 0, 1],
        };
        let wire = sa.encode();
        assert_eq!(wire[0..2], AF_INET.to_le_bytes());
        assert_eq!(wire[2..4], 53u16.to_be_bytes());
        assert_eq!(wire[4..8], [10, 77, 0, 1]);
        let back = SockaddrIn::decode(&wire, SOCKADDR_IN_LEN as u32).expect("decode");
        assert_eq!(back, sa);
    }

    #[test]
    fn sockaddr_in_wrong_family_or_len() {
        let sa = SockaddrIn::any_ephemeral().encode();
        assert_eq!(SockaddrIn::decode(&sa, 15), Err(crate::EINVAL));
        let mut bad = sa;
        bad[0] = AF_INET6.to_le_bytes()[0];
        bad[1] = AF_INET6.to_le_bytes()[1];
        assert_eq!(
            SockaddrIn::decode(&bad, SOCKADDR_IN_LEN as u32),
            Err(EAFNOSUPPORT)
        );
    }
}
