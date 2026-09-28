//! Compositor protocol errors and disconnect reasons (wire u16 / u32).

/// Recoverable or fatal compositor protocol failure (§1.6).
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolError {
    UnsupportedVersion = 1,
    UnknownOpcode = 2,
    MalformedFrame = 3,
    ReservedBitsSet = 4,
    InvalidObject = 10,
    StaleObject = 11,
    WrongObjectKind = 12,
    LimitExceeded = 13,
    RoleForbidden = 20,
    RoleAlreadyAssigned = 21,
    InvalidParent = 22,
    InvalidFormat = 30,
    InvalidScale = 31,
    InvalidLayout = 32,
    BufferTooSmall = 33,
    BufferBusy = 34,
    TransferMissing = 35,
    TransferWrongClass = 36,
    InvalidDamage = 40,
    InvalidRegion = 41,
    NotConfigured = 42,
    SerialMismatch = 43,
    UnsupportedFeature = 50,
    NotPermitted = 51,
}

impl ProtocolError {
    pub const fn code(self) -> u16 {
        self as u16
    }

    pub fn from_u16(raw: u16) -> Option<Self> {
        match raw {
            1 => Some(Self::UnsupportedVersion),
            2 => Some(Self::UnknownOpcode),
            3 => Some(Self::MalformedFrame),
            4 => Some(Self::ReservedBitsSet),
            10 => Some(Self::InvalidObject),
            11 => Some(Self::StaleObject),
            12 => Some(Self::WrongObjectKind),
            13 => Some(Self::LimitExceeded),
            20 => Some(Self::RoleForbidden),
            21 => Some(Self::RoleAlreadyAssigned),
            22 => Some(Self::InvalidParent),
            30 => Some(Self::InvalidFormat),
            31 => Some(Self::InvalidScale),
            32 => Some(Self::InvalidLayout),
            33 => Some(Self::BufferTooSmall),
            34 => Some(Self::BufferBusy),
            35 => Some(Self::TransferMissing),
            36 => Some(Self::TransferWrongClass),
            40 => Some(Self::InvalidDamage),
            41 => Some(Self::InvalidRegion),
            42 => Some(Self::NotConfigured),
            43 => Some(Self::SerialMismatch),
            50 => Some(Self::UnsupportedFeature),
            51 => Some(Self::NotPermitted),
            _ => None,
        }
    }

    /// `UnsupportedVersion`, `MalformedFrame`, or `ReservedBitsSet`.
    pub const fn is_fatal(self) -> bool {
        matches!(
            self,
            Self::UnsupportedVersion | Self::MalformedFrame | Self::ReservedBitsSet
        )
    }
}

/// Port disconnect reason (opaque u32 on the wire).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    ClientExit,
    ServerExit,
    QueueOverflow,
    Revoked,
    ProtocolViolation(ProtocolError),
}

impl DisconnectReason {
    pub fn encode(self) -> u32 {
        match self {
            Self::ClientExit => 1,
            Self::ServerExit => 2,
            Self::QueueOverflow => 3,
            Self::Revoked => 4,
            Self::ProtocolViolation(code) => {
                if !code.is_fatal() {
                    return 0;
                }
                0x0001_0000 | u32::from(code.code())
            }
        }
    }

    pub fn decode(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::ClientExit),
            2 => Some(Self::ServerExit),
            3 => Some(Self::QueueOverflow),
            4 => Some(Self::Revoked),
            v if v & 0xFFFF_0000 == 0x0001_0000 => {
                let code = (v & 0xFFFF) as u16;
                ProtocolError::from_u16(code).and_then(|c| {
                    if c.is_fatal() {
                        Some(Self::ProtocolViolation(c))
                    } else {
                        None
                    }
                })
            }
            _ => None,
        }
    }
}
