//! Bounded, versioned wire messages aligned with M3 IPC limits.

use crate::control::{ControlRequest, ControlRequestKind};
use crate::dependency::{DependencyEdge, DependencyMetadata, MAX_INLINE_DEPENDENCIES};
use crate::health::{HealthReport, HealthStatus};
use crate::identity::{DomainId, InstanceGeneration, ProcessId, ServiceId, ServiceInstanceId};
use crate::state::{LifecycleEvent, LifecycleEventKind};

pub const LIFECYCLE_PROTOCOL_VERSION: u8 = 1;
pub const LIFECYCLE_WIRE_MAX_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleMessageKind {
    ControlRequest = 1,
    LifecycleEvent = 2,
    HealthReport = 3,
    DependencyMetadata = 4,
}

impl LifecycleMessageKind {
    const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::ControlRequest),
            2 => Some(Self::LifecycleEvent),
            3 => Some(Self::HealthReport),
            4 => Some(Self::DependencyMetadata),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleMessage {
    ControlRequest(ControlRequest),
    LifecycleEvent(LifecycleEvent),
    HealthReport(HealthReport),
    DependencyMetadata(DependencyMetadata),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodeError {
    BufferTooShort { actual: usize, required: usize },
    TrailingBytes { length: usize },
    UnknownProtocolVersion(u8),
    UnknownMessageKind(u8),
    InvalidEnumDiscriminant,
    InvalidDependencyCount(u8),
}

impl LifecycleMessage {
    pub fn encode(self) -> [u8; LIFECYCLE_WIRE_MAX_BYTES] {
        let mut buf = [0u8; LIFECYCLE_WIRE_MAX_BYTES];
        buf[0] = LIFECYCLE_PROTOCOL_VERSION;
        match self {
            LifecycleMessage::ControlRequest(request) => {
                buf[1] = LifecycleMessageKind::ControlRequest as u8;
                write_u32(&mut buf[4..8], request.service.0);
                buf[8] = request.kind as u8;
            }
            LifecycleMessage::LifecycleEvent(event) => {
                buf[1] = LifecycleMessageKind::LifecycleEvent as u8;
                write_u32(&mut buf[4..8], event.instance.service.0);
                write_u32(&mut buf[8..12], event.instance.generation.0);
                write_u64(&mut buf[12..20], event.instance.pid.0);
                write_u64(&mut buf[20..28], event.instance.domain.0);
                buf[28] = event.kind as u8;
                write_u32(&mut buf[29..33], event.status_code);
            }
            LifecycleMessage::HealthReport(report) => {
                buf[1] = LifecycleMessageKind::HealthReport as u8;
                write_u32(&mut buf[4..8], report.service.0);
                write_u32(&mut buf[8..12], report.generation.0);
                buf[12] = report.status as u8;
                write_u32(&mut buf[13..17], report.detail_reserved);
            }
            LifecycleMessage::DependencyMetadata(metadata) => {
                buf[1] = LifecycleMessageKind::DependencyMetadata as u8;
                write_u32(&mut buf[4..8], metadata.service.0);
                buf[8] = metadata.edge_count;
                for index in 0..MAX_INLINE_DEPENDENCIES {
                    let offset = 12 + index * 8;
                    let edge = metadata.edges[index];
                    write_u32(&mut buf[offset..offset + 4], edge.depends_on.0);
                    buf[offset + 4] = edge.required_state as u8;
                }
            }
        }
        buf
    }

    pub fn decode(buffer: &[u8]) -> Result<(Self, usize), DecodeError> {
        if buffer.is_empty() {
            return Err(DecodeError::BufferTooShort {
                actual: 0,
                required: 4,
            });
        }
        if buffer[0] != LIFECYCLE_PROTOCOL_VERSION {
            return Err(DecodeError::UnknownProtocolVersion(buffer[0]));
        }
        if buffer.len() < 4 {
            return Err(DecodeError::BufferTooShort {
                actual: buffer.len(),
                required: 4,
            });
        }
        let kind = LifecycleMessageKind::from_repr(buffer[1])
            .ok_or(DecodeError::UnknownMessageKind(buffer[1]))?;
        let message = match kind {
            LifecycleMessageKind::ControlRequest => {
                require_len(buffer, 9)?;
                let service = ServiceId(read_u32(&buffer[4..8]));
                let control_kind = ControlRequestKind::from_repr(buffer[8])
                    .ok_or(DecodeError::InvalidEnumDiscriminant)?;
                LifecycleMessage::ControlRequest(ControlRequest {
                    service,
                    kind: control_kind,
                })
            }
            LifecycleMessageKind::LifecycleEvent => {
                require_len(buffer, 33)?;
                let instance = ServiceInstanceId::new(
                    ServiceId(read_u32(&buffer[4..8])),
                    InstanceGeneration(read_u32(&buffer[8..12])),
                    ProcessId(read_u64(&buffer[12..20])),
                    DomainId(read_u64(&buffer[20..28])),
                );
                let event_kind = LifecycleEventKind::from_repr(buffer[28])
                    .ok_or(DecodeError::InvalidEnumDiscriminant)?;
                LifecycleMessage::LifecycleEvent(LifecycleEvent {
                    instance,
                    kind: event_kind,
                    status_code: read_u32(&buffer[29..33]),
                })
            }
            LifecycleMessageKind::HealthReport => {
                require_len(buffer, 17)?;
                let status = HealthStatus::from_repr(buffer[12])
                    .ok_or(DecodeError::InvalidEnumDiscriminant)?;
                LifecycleMessage::HealthReport(HealthReport {
                    service: ServiceId(read_u32(&buffer[4..8])),
                    generation: InstanceGeneration(read_u32(&buffer[8..12])),
                    status,
                    detail_reserved: read_u32(&buffer[13..17]),
                })
            }
            LifecycleMessageKind::DependencyMetadata => {
                require_len(buffer, 12 + MAX_INLINE_DEPENDENCIES * 8)?;
                let edge_count = buffer[8];
                if edge_count as usize > MAX_INLINE_DEPENDENCIES {
                    return Err(DecodeError::InvalidDependencyCount(edge_count));
                }
                let mut edges = DependencyMetadata::empty(ServiceId(read_u32(&buffer[4..8]))).edges;
                for (index, edge) in edges.iter_mut().enumerate() {
                    let offset = 12 + index * 8;
                    let depends_on = ServiceId(read_u32(&buffer[offset..offset + 4]));
                    let required_state =
                        crate::state::ServiceLifecycleState::from_repr(buffer[offset + 4])
                            .ok_or(DecodeError::InvalidEnumDiscriminant)?;
                    *edge = DependencyEdge {
                        depends_on,
                        required_state,
                    };
                }
                LifecycleMessage::DependencyMetadata(DependencyMetadata {
                    service: ServiceId(read_u32(&buffer[4..8])),
                    edges,
                    edge_count,
                })
            }
        };
        let consumed = encoded_length(&message);
        if buffer.len() > consumed && buffer[consumed..].iter().any(|byte| *byte != 0) {
            return Err(DecodeError::TrailingBytes {
                length: buffer.len(),
            });
        }
        Ok((message, consumed))
    }
}

fn encoded_length(message: &LifecycleMessage) -> usize {
    match message {
        LifecycleMessage::ControlRequest(_) => 9,
        LifecycleMessage::LifecycleEvent(_) => 33,
        LifecycleMessage::HealthReport(_) => 17,
        LifecycleMessage::DependencyMetadata(_) => 12 + MAX_INLINE_DEPENDENCIES * 8,
    }
}

fn require_len(buffer: &[u8], required: usize) -> Result<(), DecodeError> {
    if buffer.len() < required {
        Err(DecodeError::BufferTooShort {
            actual: buffer.len(),
            required,
        })
    } else {
        Ok(())
    }
}

fn write_u32(dst: &mut [u8], value: u32) {
    dst[0] = (value & 0xff) as u8;
    dst[1] = ((value >> 8) & 0xff) as u8;
    dst[2] = ((value >> 16) & 0xff) as u8;
    dst[3] = ((value >> 24) & 0xff) as u8;
}

fn read_u32(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

fn write_u64(dst: &mut [u8], value: u64) {
    for (index, byte) in dst.iter_mut().enumerate().take(8) {
        *byte = ((value >> (index * 8)) & 0xff) as u8;
    }
}

fn read_u64(src: &[u8]) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(src);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn round_trip_control_request() {
        let message = LifecycleMessage::ControlRequest(ControlRequest::new(
            ServiceId(3),
            ControlRequestKind::Restart,
        ));
        let encoded = message.encode();
        assert!(encoded.len() <= LIFECYCLE_WIRE_MAX_BYTES);
        let (decoded, _) = LifecycleMessage::decode(&encoded).expect("decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn unknown_version_fails_deterministically() {
        let err = LifecycleMessage::decode(&[99, 1, 0, 0]).unwrap_err();
        assert_eq!(err, DecodeError::UnknownProtocolVersion(99));
    }

    #[test]
    fn unknown_kind_fails_deterministically() {
        let err = LifecycleMessage::decode(&[1, 250, 0, 0, 0, 0, 0, 0, 0]).unwrap_err();
        assert_eq!(err, DecodeError::UnknownMessageKind(250));
    }

    #[test]
    fn stale_instance_event_round_trip_preserves_generation() {
        let event = LifecycleEvent::new(
            ServiceInstanceId::new(
                ServiceId(1),
                InstanceGeneration(4),
                ProcessId(99),
                DomainId(99),
            ),
            LifecycleEventKind::Exited,
        );
        let encoded = LifecycleMessage::LifecycleEvent(event).encode();
        let decoded = LifecycleMessage::decode(&encoded)
            .expect("decode")
            .0;
        let LifecycleMessage::LifecycleEvent(decoded) = decoded else {
            panic!("expected lifecycle event");
        };
        assert_eq!(decoded.instance.generation, InstanceGeneration(4));
        assert_eq!(decoded.instance.pid, ProcessId(99));
    }

    #[test]
    fn dependency_metadata_respects_inline_limit_on_decode() {
        let mut metadata = DependencyMetadata::empty(ServiceId(2));
        metadata.edge_count = (MAX_INLINE_DEPENDENCIES + 1) as u8;
        let encoded = LifecycleMessage::DependencyMetadata(metadata).encode();
        let err = LifecycleMessage::decode(&encoded).unwrap_err();
        assert_eq!(
            err,
            DecodeError::InvalidDependencyCount((MAX_INLINE_DEPENDENCIES + 1) as u8)
        );
    }

    #[test]
    fn health_and_dependency_extension_fields_default_to_zero() {
        let health = HealthReport::new(ServiceId(5), InstanceGeneration(1), HealthStatus::Ok);
        assert_eq!(health.detail_reserved, 0);
        let dep = DependencyMetadata::empty(ServiceId(5));
        assert_eq!(dep.edge_count, 0);
    }
}
