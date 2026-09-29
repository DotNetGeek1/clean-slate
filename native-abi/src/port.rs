//! Bounded, class-agnostic service port ABI (syscall 17 `SERVICE_PORT`).
//!
//! Frames are opaque 64-byte values; no graphics types appear in this module.
//!
//! ```text
//! rax = 17, rdi = subop, rsi = capability handle (serve/connect subops) or flags (connection data path),
//! arguments in rdx, r10, r8, r9, result in rax. Deadlines are absolute monotonic ns (0 = none).
//! Nonzero unused registers return EINVAL.
//!
//! | # | Subop        | rsi               | rdx                 | r10                    | r8                 | r9       | Success       |
//! |---|--------------|-------------------|---------------------|------------------------|--------------------|----------|---------------|
//! | 1 | FIND_HANDLE  | 0                 | class (u8)          | resource id            | role (1 connect, 2 serve) | 0 | handle raw |
//! | 2 | CONNECT      | client cap        | class               | resource id            | 0                  | 0        | ConnectionId  |
//! | 3 | SEND         | flags (bit0 WAIT) | conn                | frame ptr (64 B)       | transfer handle/0  | deadline | 0             |
//! | 4 | RECV_EVENT   | flags (bit0 NONBLOCK) | conn            | out ptr                | out len (80)       | deadline | EventKind     |
//! | 5 | CLOSE        | 0                 | conn                | reason (u32)           | 0                  | 0        | 0             |
//! | 6 | RECV         | serve cap         | out ptr             | out len (152)          | flags (bit0 NONBLOCK) | deadline | RecvKind   |
//! | 7 | POST         | serve cap         | conn                | frame ptr              | 0                  | 0        | 0             |
//! | 8 | DISCONNECT   | serve cap         | conn                | reason (u32)           | 0                  | 0        | 0             |
//! | 9 | BIND_WAKE    | serve cap         | work-set id         | request bit (0..=31)   | notice bit (0..=31)| 0        | 0             |
//! ```

use clean_slate_capability::syscall_abi::SYSCALL_NR_SERVICE_PORT as CAPABILITY_SYSCALL_NR_SERVICE_PORT;
use clean_slate_capability::{ResourceClass, Rights};

pub const SYSCALL_NR_SERVICE_PORT: u64 = CAPABILITY_SYSCALL_NR_SERVICE_PORT;

macro_rules! slot_generation_id {
    ($name:ident, $error:ident) => {
        const HIGH_BITS_MASK: u64 = 0xffff_0000_0000_0000;
        const GENERATION_SHIFT: u32 = 16;

        /// Wire/decode failures for [`$name`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum $error {
            InvalidGeneration,
            ReservedBitsSet,
        }

        /// Kernel-minted identity: slot in bits 0..16, generation in 16..48 (0 invalid).
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub struct $name(u64);

        impl $name {
            pub const fn new(slot: u16, generation: u32) -> Result<Self, $error> {
                if generation == 0 {
                    return Err($error::InvalidGeneration);
                }
                Ok(Self(
                    slot as u64 | ((generation as u64) << GENERATION_SHIFT),
                ))
            }

            pub const fn encode(self) -> u64 {
                self.0
            }

            pub fn decode(raw: u64) -> Result<Self, $error> {
                if raw & HIGH_BITS_MASK != 0 {
                    return Err($error::ReservedBitsSet);
                }
                let generation = (raw >> GENERATION_SHIFT) as u32;
                if generation == 0 {
                    return Err($error::InvalidGeneration);
                }
                Ok(Self(raw))
            }

            pub fn slot(self) -> u16 {
                self.0 as u16
            }

            pub fn generation(self) -> u32 {
                (self.0 >> GENERATION_SHIFT) as u32
            }
        }
    };
}

slot_generation_id!(ConnectionId, ConnectionIdError);

pub const PORT_FRAME_BYTES: usize = 64;
pub const PORT_MAX_EVENT_QUEUE_DEPTH: usize = 64;
pub const PORT_MAX_REQUEST_QUEUE_DEPTH: usize = 64;
pub const PORT_MAX_CONNECTIONS: usize = 16;
pub const PORT_MAX_OUTSTANDING_PER_CONNECTION: usize = 16;

/// Transfers queued but not yet received, per connection and per port. They bound the
/// capability-table slots a port can hold on behalf of servers that have not read yet.
pub const PORT_MAX_TRANSFERS_IN_FLIGHT_PER_CONNECTION: usize = 1;
pub const PORT_MAX_TRANSFERS_IN_FLIGHT: usize = 4;

pub const PORT_OP_FIND_HANDLE: u64 = 1;
pub const PORT_OP_CONNECT: u64 = 2;
pub const PORT_OP_SEND: u64 = 3;
pub const PORT_OP_RECV_EVENT: u64 = 4;
pub const PORT_OP_CLOSE: u64 = 5;
pub const PORT_OP_RECV: u64 = 6;
pub const PORT_OP_POST: u64 = 7;
pub const PORT_OP_DISCONNECT: u64 = 8;
pub const PORT_OP_BIND_WAKE: u64 = 9;

pub const PORT_SEND_WAIT: u64 = 1;
pub const PORT_RECV_NONBLOCK: u64 = 1;
pub const PORT_ROLE_CONNECT: u64 = 1;
pub const PORT_ROLE_SERVE: u64 = 2;

/// Port queue and connection limits supplied at creation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortParams {
    pub event_depth: u16,
    pub request_depth: u16,
    pub max_connections: u16,
    pub max_outstanding: u16,
    pub max_connections_per_holder: u16,
}

/// Validation failure for [`PortParams`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortParamError {
    EventDepth,
    RequestDepth,
    Connections,
    Outstanding,
    PerHolder,
    Inconsistent,
}

impl PortParams {
    pub const fn validate(&self) -> Result<(), PortParamError> {
        if self.event_depth == 0 || self.event_depth as usize > PORT_MAX_EVENT_QUEUE_DEPTH {
            return Err(PortParamError::EventDepth);
        }
        if self.request_depth == 0 || self.request_depth as usize > PORT_MAX_REQUEST_QUEUE_DEPTH {
            return Err(PortParamError::RequestDepth);
        }
        if self.max_connections == 0 || self.max_connections as usize > PORT_MAX_CONNECTIONS {
            return Err(PortParamError::Connections);
        }
        if self.max_outstanding == 0
            || self.max_outstanding as usize > PORT_MAX_OUTSTANDING_PER_CONNECTION
        {
            return Err(PortParamError::Outstanding);
        }
        if self.max_connections_per_holder == 0
            || self.max_connections_per_holder as usize > PORT_MAX_CONNECTIONS
        {
            return Err(PortParamError::PerHolder);
        }
        if self.max_outstanding > self.request_depth
            || self.max_connections_per_holder > self.max_connections
        {
            return Err(PortParamError::Inconsistent);
        }
        Ok(())
    }
}

/// Rights required to connect vs serve on a class-specific port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRights {
    pub connect: Rights,
    pub serve: Rights,
}

pub const fn port_rights_for(class: ResourceClass) -> Option<PortRights> {
    match class {
        ResourceClass::Graphics => Some(PortRights {
            connect: Rights::GFX_CONNECT,
            serve: Rights::GFX_SERVE,
        }),
        _ => None,
    }
}

/// Server-side receive classification.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecvKind {
    Request = 1,
    /// Client invoked `CLOSE`; `reason` is the client's opaque `u32`.
    ClientClosed = 2,
    ClientExited = 3,
    /// Client's connect capability was found revoked.
    ClientRevoked = 4,
}

impl RecvKind {
    pub const fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Request),
            2 => Some(Self::ClientClosed),
            3 => Some(Self::ClientExited),
            4 => Some(Self::ClientRevoked),
            _ => None,
        }
    }
}

/// Client-side event classification.
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Frame = 1,
    /// Server invoked `DISCONNECT`; `reason` is the server's opaque `u32`.
    Disconnected = 2,
    /// Server instance exited.
    ServerGone = 3,
}

impl EventKind {
    pub const fn from_u32(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Frame),
            2 => Some(Self::Disconnected),
            3 => Some(Self::ServerGone),
            _ => None,
        }
    }
}

/// Fixed-layout wire decode failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordError {
    UnknownKind,
    UnknownFlags,
    ReservedNonZero,
    TransferMismatch,
    Connection(ConnectionIdError),
}

pub const ENVELOPE_TRANSFER_PRESENT: u32 = 1;

/// Capability transfer embedded in a trusted envelope when present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransferredCap {
    pub handle: u64,
    pub buffer_id: u64,
    pub byte_len: u64,
    pub rights: u32,
    pub class: u8,
}

/// Kernel-trusted metadata for an inbound port request.
///
/// | Off | Size | Field |
/// |---|---|---|
/// | 0 | 8 | connection (ConnectionId raw) |
/// | 8 | 8 | pid |
/// | 16 | 8 | domain |
/// | 24 | 8 | instance_generation |
/// | 32 | 8 | kernel_seq |
/// | 40 | 4 | rights (raw bits of the sender's re-authorised capability) |
/// | 44 | 4 | flags: bit 0 ENVELOPE_TRANSFER_PRESENT, other bits zero |
/// | 48 | 8 | transfer.handle |
/// | 56 | 8 | transfer.buffer_id |
/// | 64 | 8 | transfer.byte_len |
/// | 72 | 4 | transfer.rights |
/// | 76 | 1 | transfer.class |
/// | 77 | 3 | reserved, zero |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrustedEnvelope {
    pub connection: ConnectionId,
    pub pid: u64,
    pub domain: u64,
    pub instance_generation: u64,
    pub kernel_seq: u64,
    pub rights: u32,
    pub transfer: Option<TransferredCap>,
}

impl TrustedEnvelope {
    pub const BYTES: usize = 80;

    pub fn encode(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..8].copy_from_slice(&self.connection.encode().to_le_bytes());
        out[8..16].copy_from_slice(&self.pid.to_le_bytes());
        out[16..24].copy_from_slice(&self.domain.to_le_bytes());
        out[24..32].copy_from_slice(&self.instance_generation.to_le_bytes());
        out[32..40].copy_from_slice(&self.kernel_seq.to_le_bytes());
        out[40..44].copy_from_slice(&self.rights.to_le_bytes());
        let flags = if self.transfer.is_some() {
            ENVELOPE_TRANSFER_PRESENT
        } else {
            0
        };
        out[44..48].copy_from_slice(&flags.to_le_bytes());
        if let Some(transfer) = self.transfer {
            out[48..56].copy_from_slice(&transfer.handle.to_le_bytes());
            out[56..64].copy_from_slice(&transfer.buffer_id.to_le_bytes());
            out[64..72].copy_from_slice(&transfer.byte_len.to_le_bytes());
            out[72..76].copy_from_slice(&transfer.rights.to_le_bytes());
            out[76] = transfer.class;
        }
        out
    }

    pub fn decode(bytes: &[u8; Self::BYTES]) -> Result<Self, RecordError> {
        let connection_raw = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let connection = ConnectionId::decode(connection_raw).map_err(RecordError::Connection)?;
        let pid = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let domain = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let instance_generation = u64::from_le_bytes(bytes[24..32].try_into().unwrap());
        let kernel_seq = u64::from_le_bytes(bytes[32..40].try_into().unwrap());
        let rights = u32::from_le_bytes(bytes[40..44].try_into().unwrap());
        let flags = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
        if flags & !ENVELOPE_TRANSFER_PRESENT != 0 {
            return Err(RecordError::UnknownFlags);
        }
        if bytes[77..80] != [0, 0, 0] {
            return Err(RecordError::ReservedNonZero);
        }
        let transfer_slice = &bytes[48..77];
        let transfer_present = flags & ENVELOPE_TRANSFER_PRESENT != 0;
        let handle = u64::from_le_bytes(transfer_slice[0..8].try_into().unwrap());
        if transfer_present {
            if handle == 0 {
                return Err(RecordError::TransferMismatch);
            }
            let transfer = TransferredCap {
                handle,
                buffer_id: u64::from_le_bytes(transfer_slice[8..16].try_into().unwrap()),
                byte_len: u64::from_le_bytes(transfer_slice[16..24].try_into().unwrap()),
                rights: u32::from_le_bytes(transfer_slice[24..28].try_into().unwrap()),
                class: transfer_slice[28],
            };
            Ok(Self {
                connection,
                pid,
                domain,
                instance_generation,
                kernel_seq,
                rights,
                transfer: Some(transfer),
            })
        } else if transfer_slice.iter().any(|&b| b != 0) {
            Err(RecordError::TransferMismatch)
        } else {
            Ok(Self {
                connection,
                pid,
                domain,
                instance_generation,
                kernel_seq,
                rights,
                transfer: None,
            })
        }
    }
}

/// Server `RECV` out-record (152 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRecvRecord {
    pub kind: RecvKind,
    pub reason: u32,
    pub envelope: TrustedEnvelope,
    pub frame: [u8; PORT_FRAME_BYTES],
}

impl PortRecvRecord {
    pub const BYTES: usize = 152;

    pub fn encode(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..4].copy_from_slice(&(self.kind as u32).to_le_bytes());
        out[4..8].copy_from_slice(&self.reason.to_le_bytes());
        out[8..88].copy_from_slice(&self.envelope.encode());
        out[88..152].copy_from_slice(&self.frame);
        out
    }

    pub fn decode(bytes: &[u8; Self::BYTES]) -> Result<Self, RecordError> {
        let kind_raw = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let kind = RecvKind::from_u32(kind_raw).ok_or(RecordError::UnknownKind)?;
        let reason = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let envelope_bytes: &[u8; TrustedEnvelope::BYTES] = bytes[8..88]
            .try_into()
            .map_err(|_| RecordError::UnknownKind)?;
        let envelope = TrustedEnvelope::decode(envelope_bytes)?;
        let frame: [u8; PORT_FRAME_BYTES] = bytes[88..152].try_into().unwrap();
        Ok(Self {
            kind,
            reason,
            envelope,
            frame,
        })
    }
}

/// Client `RECV_EVENT` out-record (80 bytes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortEventRecord {
    pub kind: EventKind,
    pub reason: u32,
    pub kernel_seq: u64,
    pub frame: [u8; PORT_FRAME_BYTES],
}

impl PortEventRecord {
    pub const BYTES: usize = 80;

    pub fn encode(&self) -> [u8; Self::BYTES] {
        let mut out = [0u8; Self::BYTES];
        out[0..4].copy_from_slice(&(self.kind as u32).to_le_bytes());
        out[4..8].copy_from_slice(&self.reason.to_le_bytes());
        out[8..16].copy_from_slice(&self.kernel_seq.to_le_bytes());
        out[16..80].copy_from_slice(&self.frame);
        out
    }

    pub fn decode(bytes: &[u8; Self::BYTES]) -> Result<Self, RecordError> {
        let kind_raw = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let kind = EventKind::from_u32(kind_raw).ok_or(RecordError::UnknownKind)?;
        let reason = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let kernel_seq = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let frame: [u8; PORT_FRAME_BYTES] = bytes[16..80].try_into().unwrap();
        Ok(Self {
            kind,
            reason,
            kernel_seq,
            frame,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::{
        validate_delegation, CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityState,
        HolderId, Provenance, ResourceRef,
    };
    use clean_slate_graphics::{
        CLIENT_EVENT_QUEUE_DEPTH, MAX_CLIENTS, MAX_OUTSTANDING_REQUESTS_PER_CLIENT,
        SERVER_REQUEST_QUEUE_DEPTH,
    };

    const HIGH_BITS_MASK: u64 = 0xffff_0000_0000_0000;

    fn valid_port_params() -> PortParams {
        PortParams {
            event_depth: 64,
            request_depth: 64,
            max_connections: 8,
            max_outstanding: 16,
            max_connections_per_holder: 2,
        }
    }

    #[test]
    fn connection_id_round_trip_and_rejections() {
        let id = ConnectionId::new(3, 42).unwrap();
        assert_eq!(ConnectionId::decode(id.encode()), Ok(id));
        assert_eq!(id.slot(), 3);
        assert_eq!(id.generation(), 42);
        assert_eq!(
            ConnectionId::new(0, 0),
            Err(ConnectionIdError::InvalidGeneration)
        );
        assert_eq!(
            ConnectionId::decode(0),
            Err(ConnectionIdError::InvalidGeneration)
        );
        assert_eq!(
            ConnectionId::decode(1 | (1u64 << 48)),
            Err(ConnectionIdError::ReservedBitsSet)
        );
        assert_eq!(
            ConnectionId::decode(1 | HIGH_BITS_MASK),
            Err(ConnectionIdError::ReservedBitsSet)
        );
    }

    #[test]
    fn connection_id_max_slot_and_generation() {
        let id = ConnectionId::new(u16::MAX, u32::MAX).unwrap();
        assert_eq!(id.slot(), u16::MAX);
        assert_eq!(id.generation(), u32::MAX);
        assert_eq!(ConnectionId::decode(id.encode()), Ok(id));
    }

    fn sample_envelope_with_transfer() -> TrustedEnvelope {
        TrustedEnvelope {
            connection: ConnectionId::new(3, 7).unwrap(),
            pid: 0x1122,
            domain: 0x3344,
            instance_generation: 0x5566,
            kernel_seq: 0x7788,
            rights: 0x0001_4000,
            transfer: Some(TransferredCap {
                handle: 0x0000_0002_0005,
                buffer_id: 0x0009_0004,
                byte_len: 0x1000,
                rights: 1,
                class: 8,
            }),
        }
    }

    fn sample_envelope_without_transfer() -> TrustedEnvelope {
        TrustedEnvelope {
            connection: ConnectionId::new(1, 2).unwrap(),
            pid: 1,
            domain: 2,
            instance_generation: 3,
            kernel_seq: 4,
            rights: 5,
            transfer: None,
        }
    }

    #[test]
    fn trusted_envelope_golden_with_transfer() {
        let envelope = sample_envelope_with_transfer();
        let mut expected = [0u8; TrustedEnvelope::BYTES];
        expected[0..8].copy_from_slice(&ConnectionId::new(3, 7).unwrap().encode().to_le_bytes());
        expected[8..16].copy_from_slice(&0x1122u64.to_le_bytes());
        expected[16..24].copy_from_slice(&0x3344u64.to_le_bytes());
        expected[24..32].copy_from_slice(&0x5566u64.to_le_bytes());
        expected[32..40].copy_from_slice(&0x7788u64.to_le_bytes());
        expected[40..44].copy_from_slice(&0x0001_4000u32.to_le_bytes());
        expected[44..48].copy_from_slice(&ENVELOPE_TRANSFER_PRESENT.to_le_bytes());
        expected[48..56].copy_from_slice(&0x0000_0002_0005u64.to_le_bytes());
        expected[56..64].copy_from_slice(&0x0009_0004u64.to_le_bytes());
        expected[64..72].copy_from_slice(&0x1000u64.to_le_bytes());
        expected[72..76].copy_from_slice(&1u32.to_le_bytes());
        expected[76] = 8;
        assert_eq!(envelope.encode(), expected);
        assert_eq!(TrustedEnvelope::decode(&expected), Ok(envelope));
    }

    #[test]
    fn trusted_envelope_round_trip_without_transfer() {
        let envelope = sample_envelope_without_transfer();
        let encoded = envelope.encode();
        assert_eq!(TrustedEnvelope::decode(&encoded), Ok(envelope));
    }

    #[test]
    fn port_recv_record_golden_and_round_trip() {
        let envelope = sample_envelope_with_transfer();
        let mut frame = [0u8; PORT_FRAME_BYTES];
        frame[0] = 0xAB;
        frame[63] = 0xCD;
        let record = PortRecvRecord {
            kind: RecvKind::Request,
            reason: 0xDEAD_BEEF,
            envelope,
            frame,
        };
        let mut expected = [0u8; PortRecvRecord::BYTES];
        expected[0..4].copy_from_slice(&(RecvKind::Request as u32).to_le_bytes());
        expected[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        expected[8..88].copy_from_slice(&envelope.encode());
        expected[88..152].copy_from_slice(&frame);
        assert_eq!(record.encode(), expected);
        assert_eq!(PortRecvRecord::decode(&expected), Ok(record));
    }

    #[test]
    fn port_event_record_golden_and_round_trip() {
        let mut frame = [0u8; PORT_FRAME_BYTES];
        frame[1] = 0x42;
        let record = PortEventRecord {
            kind: EventKind::Frame,
            reason: 9,
            kernel_seq: 0xAABB_CCDD_EEFF_0011,
            frame,
        };
        let mut expected = [0u8; PortEventRecord::BYTES];
        expected[0..4].copy_from_slice(&(EventKind::Frame as u32).to_le_bytes());
        expected[4..8].copy_from_slice(&9u32.to_le_bytes());
        expected[8..16].copy_from_slice(&0xAABB_CCDD_EEFF_0011u64.to_le_bytes());
        expected[16..80].copy_from_slice(&frame);
        assert_eq!(record.encode(), expected);
        assert_eq!(PortEventRecord::decode(&expected), Ok(record));
    }

    #[test]
    fn trusted_envelope_decode_rejections() {
        let good = sample_envelope_without_transfer().encode();
        let mut bad_conn = good;
        bad_conn[0..8].copy_from_slice(&0u64.to_le_bytes());
        assert_eq!(
            TrustedEnvelope::decode(&bad_conn),
            Err(RecordError::Connection(
                ConnectionIdError::InvalidGeneration
            ))
        );

        let mut unknown_flags = good;
        unknown_flags[44] = 2;
        assert_eq!(
            TrustedEnvelope::decode(&unknown_flags),
            Err(RecordError::UnknownFlags)
        );

        let mut reserved = good;
        reserved[79] = 1;
        assert_eq!(
            TrustedEnvelope::decode(&reserved),
            Err(RecordError::ReservedNonZero)
        );

        let mut flag_no_handle = good;
        flag_no_handle[44..48].copy_from_slice(&ENVELOPE_TRANSFER_PRESENT.to_le_bytes());
        assert_eq!(
            TrustedEnvelope::decode(&flag_no_handle),
            Err(RecordError::TransferMismatch)
        );

        let mut clear_with_transfer_bytes = good;
        clear_with_transfer_bytes[72] = 1;
        assert_eq!(
            TrustedEnvelope::decode(&clear_with_transfer_bytes),
            Err(RecordError::TransferMismatch)
        );
    }

    #[test]
    fn port_recv_record_unknown_kind() {
        let base = PortRecvRecord {
            kind: RecvKind::Request,
            reason: 0,
            envelope: sample_envelope_without_transfer(),
            frame: [0; PORT_FRAME_BYTES],
        }
        .encode();
        for raw in [0u32, 5u32] {
            let mut bytes = base;
            bytes[0..4].copy_from_slice(&raw.to_le_bytes());
            assert_eq!(
                PortRecvRecord::decode(&bytes),
                Err(RecordError::UnknownKind)
            );
        }
    }

    #[test]
    fn port_event_record_unknown_kind() {
        let base = PortEventRecord {
            kind: EventKind::Frame,
            reason: 0,
            kernel_seq: 0,
            frame: [0; PORT_FRAME_BYTES],
        }
        .encode();
        for raw in [0u32, 4u32] {
            let mut bytes = base;
            bytes[0..4].copy_from_slice(&raw.to_le_bytes());
            assert_eq!(
                PortEventRecord::decode(&bytes),
                Err(RecordError::UnknownKind)
            );
        }
    }

    #[test]
    fn port_params_validate_fields() {
        let base = valid_port_params();
        assert_eq!(base.validate(), Ok(()));

        let mut p = base;
        p.event_depth = 0;
        assert_eq!(p.validate(), Err(PortParamError::EventDepth));
        p.event_depth = PORT_MAX_EVENT_QUEUE_DEPTH as u16;
        assert_eq!(p.validate(), Ok(()));
        p.event_depth = PORT_MAX_EVENT_QUEUE_DEPTH as u16 + 1;
        assert_eq!(p.validate(), Err(PortParamError::EventDepth));

        p = base;
        p.request_depth = 0;
        assert_eq!(p.validate(), Err(PortParamError::RequestDepth));
        p.request_depth = PORT_MAX_REQUEST_QUEUE_DEPTH as u16;
        assert_eq!(p.validate(), Ok(()));
        p.request_depth = PORT_MAX_REQUEST_QUEUE_DEPTH as u16 + 1;
        assert_eq!(p.validate(), Err(PortParamError::RequestDepth));

        p = base;
        p.max_connections = 0;
        assert_eq!(p.validate(), Err(PortParamError::Connections));
        p.max_connections = PORT_MAX_CONNECTIONS as u16;
        assert_eq!(p.validate(), Ok(()));
        p.max_connections = PORT_MAX_CONNECTIONS as u16 + 1;
        assert_eq!(p.validate(), Err(PortParamError::Connections));

        p = base;
        p.max_outstanding = 0;
        assert_eq!(p.validate(), Err(PortParamError::Outstanding));
        p.max_outstanding = PORT_MAX_OUTSTANDING_PER_CONNECTION as u16;
        assert_eq!(p.validate(), Ok(()));
        p.max_outstanding = PORT_MAX_OUTSTANDING_PER_CONNECTION as u16 + 1;
        assert_eq!(p.validate(), Err(PortParamError::Outstanding));

        p = base;
        p.max_connections_per_holder = 0;
        assert_eq!(p.validate(), Err(PortParamError::PerHolder));
        p.max_connections = PORT_MAX_CONNECTIONS as u16;
        p.max_connections_per_holder = PORT_MAX_CONNECTIONS as u16;
        assert_eq!(p.validate(), Ok(()));
        p.max_connections_per_holder = PORT_MAX_CONNECTIONS as u16 + 1;
        assert_eq!(p.validate(), Err(PortParamError::PerHolder));

        p = base;
        p.request_depth = 10;
        p.max_outstanding = 11;
        assert_eq!(p.validate(), Err(PortParamError::Inconsistent));

        p = base;
        p.max_connections_per_holder = p.max_connections + 1;
        assert_eq!(p.validate(), Err(PortParamError::Inconsistent));
    }

    #[test]
    fn port_rights_for_all_classes() {
        for raw in 1u8..=11 {
            let class = ResourceClass::from_u8(raw).unwrap();
            let rights = port_rights_for(class);
            if class == ResourceClass::Graphics {
                let pr = rights.unwrap();
                assert!(pr.serve.is_subset_of(Rights::root_only_for(class)));
                assert!(!pr.connect.intersects(pr.serve));
                assert!(pr.connect.is_subset_of(Rights::valid_for(class)));
                assert!(pr.serve.is_subset_of(Rights::valid_for(class)));
                assert_ne!(pr.connect, Rights::empty());
                assert_ne!(pr.serve, Rights::empty());
            } else {
                assert!(rights.is_none());
            }
        }
    }

    #[test]
    fn gfx_serve_not_delegable_even_when_parent_holds_it() {
        let rights = Rights::GFX_SERVE.union(Rights::DELEGATE);
        let parent = CapabilityRecord {
            state: CapabilityState::Live,
            holder: HolderId(1),
            resource: ResourceRef::graphics(1, 1),
            rights,
            provenance: Provenance::root(HolderId(1)),
            generation: 1,
        };
        let handle = CapabilityHandle::new(0, 1);
        assert_eq!(
            validate_delegation(&parent, handle, HolderId(1), Rights::GFX_SERVE),
            Err(CapabilityError::NotDelegable)
        );
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn graphics_limits_within_port_bounds() {
        assert!(MAX_CLIENTS <= PORT_MAX_CONNECTIONS);
        assert!(CLIENT_EVENT_QUEUE_DEPTH <= PORT_MAX_EVENT_QUEUE_DEPTH);
        assert!(SERVER_REQUEST_QUEUE_DEPTH <= PORT_MAX_REQUEST_QUEUE_DEPTH);
        assert!(MAX_OUTSTANDING_REQUESTS_PER_CLIENT <= PORT_MAX_OUTSTANDING_PER_CONNECTION);
        assert_eq!(
            PortParams {
                event_depth: CLIENT_EVENT_QUEUE_DEPTH as u16,
                request_depth: SERVER_REQUEST_QUEUE_DEPTH as u16,
                max_connections: MAX_CLIENTS as u16,
                max_outstanding: MAX_OUTSTANDING_REQUESTS_PER_CLIENT as u16,
                max_connections_per_holder: 2,
            }
            .validate(),
            Ok(())
        );
    }

    #[test]
    fn port_module_has_no_graphics_dependency_in_sources() {
        let manifest = include_str!("../Cargo.toml");
        let deps_start = manifest.find("[dependencies]").unwrap();
        let after_deps = &manifest[deps_start..];
        let deps_end = after_deps[1..]
            .find("\n[")
            .map(|i| deps_start + 1 + i)
            .unwrap_or(manifest.len());
        let deps_section = &manifest[deps_start..deps_end];
        assert!(!deps_section.contains("clean-slate-graphics"));

        for source in [
            include_str!("port.rs"),
            include_str!("work_set.rs"),
            include_str!("status.rs"),
        ] {
            let pre_test = source.split("#[cfg(test)]").next().unwrap();
            assert!(!pre_test.contains("clean-slate-graphics"));
        }
    }
}
