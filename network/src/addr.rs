//! Address and protocol identifier newtypes (no `std::net`).

use core::fmt;

use crate::limits::MAX_REQUEST_HOSTNAME_LEN;

/// Ethernet MAC address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    pub const fn new(octets: [u8; 6]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }

    pub fn write_to(self, f: &mut impl fmt::Write) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AddrParseError> {
        if bytes.len() != 6 {
            return Err(AddrParseError::BadLength);
        }
        let mut octets = [0u8; 6];
        octets.copy_from_slice(bytes);
        Ok(Self(octets))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

/// IPv4 address stored in network byte order inside the array as written (big-endian octets).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Addr(pub [u8; 4]);

impl Ipv4Addr {
    pub const fn new(octets: [u8; 4]) -> Self {
        Self(octets)
    }

    pub const fn octets(self) -> [u8; 4] {
        self.0
    }

    pub fn write_to(self, f: &mut impl fmt::Write) -> fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, AddrParseError> {
        if bytes.len() != 4 {
            return Err(AddrParseError::BadLength);
        }
        let mut octets = [0u8; 4];
        octets.copy_from_slice(bytes);
        Ok(Self(octets))
    }
}

impl fmt::Display for Ipv4Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

/// IPv4 socket endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SocketAddrV4 {
    pub addr: Ipv4Addr,
    pub port: u16,
}

impl SocketAddrV4 {
    pub const fn new(addr: Ipv4Addr, port: u16) -> Self {
        Self { addr, port }
    }

    pub fn write_to(self, f: &mut impl fmt::Write) -> fmt::Result {
        self.addr.write_to(f)?;
        write!(f, ":{}", self.port)
    }

    pub fn encode(self) -> [u8; 6] {
        let mut out = [0u8; 6];
        out[0..4].copy_from_slice(&self.addr.octets());
        out[4..6].copy_from_slice(&self.port.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8; 6]) -> Result<Self, AddrParseError> {
        let mut octets = [0u8; 4];
        octets.copy_from_slice(&bytes[0..4]);
        let port = u16::from_le_bytes([bytes[4], bytes[5]]);
        Ok(Self {
            addr: Ipv4Addr(octets),
            port,
        })
    }
}

impl fmt::Display for SocketAddrV4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_to(f)
    }
}

/// IEEE 802.3 EtherType.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EtherType(pub u16);

impl EtherType {
    pub const IPV4: Self = Self(0x0800);
    pub const ARP: Self = Self(0x0806);

    pub const fn new(raw: u16) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u16 {
        self.0
    }
}

/// IANA IP protocol number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IpProtocol(pub u8);

impl IpProtocol {
    pub const ICMP: Self = Self(1);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);

    pub const fn new(raw: u8) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

/// Bounded host name bytes for resolver *requests* crossing the client/service IPC.
///
/// Capacity is [`MAX_REQUEST_HOSTNAME_LEN`] so a `Resolve` request always fits one
/// fixed-size IPC frame. DNS wire-format names (up to `MAX_DNS_NAME_LEN`) are the
/// resolver lane's concern and are never carried in this type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BoundedHostname {
    len: u8,
    bytes: [u8; MAX_REQUEST_HOSTNAME_LEN],
}

impl BoundedHostname {
    pub const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_REQUEST_HOSTNAME_LEN],
        }
    }

    pub fn try_from_str(name: &str) -> Result<Self, HostnameError> {
        if name.is_empty() {
            return Err(HostnameError::Empty);
        }
        if name.len() > MAX_REQUEST_HOSTNAME_LEN {
            return Err(HostnameError::TooLong);
        }
        if !name.is_ascii() {
            return Err(HostnameError::NotAscii);
        }
        let mut bytes = [0u8; MAX_REQUEST_HOSTNAME_LEN];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            len: u8::try_from(name.len()).map_err(|_| HostnameError::TooLong)?,
            bytes,
        })
    }

    pub const fn len(self) -> usize {
        self.len as usize
    }

    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    pub fn as_str(&self) -> Result<&str, HostnameError> {
        core::str::from_utf8(&self.bytes[..self.len()]).map_err(|_| HostnameError::NotAscii)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len()]
    }

    pub fn from_encoded(len: u8, src: &[u8]) -> Result<Self, HostnameError> {
        let len_usize = len as usize;
        if len_usize == 0 {
            return Err(HostnameError::Empty);
        }
        if len_usize > MAX_REQUEST_HOSTNAME_LEN || src.len() < len_usize {
            return Err(HostnameError::TooLong);
        }
        let mut bytes = [0u8; MAX_REQUEST_HOSTNAME_LEN];
        bytes[..len_usize].copy_from_slice(&src[..len_usize]);
        if !bytes[..len_usize].is_ascii() {
            return Err(HostnameError::NotAscii);
        }
        Ok(Self { len, bytes })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrParseError {
    BadLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostnameError {
    Empty,
    TooLong,
    NotAscii,
}
