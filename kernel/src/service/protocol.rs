//! M4.1 shared service lifecycle protocol and state model.

#[cfg(test)]
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
use core::mem::size_of;

pub(crate) const SERVICE_PROTOCOL_VERSION: u8 = 1;
pub(crate) const SERVICE_PROTOCOL_MESSAGE_BYTES: usize = size_of::<ServiceWireMessage>();
const SERVICE_PROTOCOL_EXTENSION_BYTES: usize = size_of::<u64>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceId(u64);

impl ServiceId {
    pub(crate) fn new(raw: u64) -> Result<Self, ProtocolError> {
        if raw == 0 {
            return Err(ProtocolError::InvalidServiceId);
        }
        Ok(Self(raw))
    }

    pub(crate) const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceInstance {
    pub(crate) pid: u64,
    pub(crate) generation: u32,
}

impl ServiceInstance {
    pub(crate) fn new(pid: u64, generation: u32) -> Result<Self, ProtocolError> {
        if pid == 0 {
            return Err(ProtocolError::InvalidInstancePid);
        }
        if generation == 0 {
            return Err(ProtocolError::InvalidInstanceGeneration);
        }
        Ok(Self { pid, generation })
    }

    fn succeeds(self, previous: Self) -> bool {
        self.generation > previous.generation && self.pid != previous.pid
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ServiceLifecycleState {
    Declared = 1,
    Starting = 2,
    Running = 3,
    Stopping = 4,
    Exited = 5,
    Faulted = 6,
    RestartPending = 7,
}

impl ServiceLifecycleState {
    fn decode(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            1 => Ok(Self::Declared),
            2 => Ok(Self::Starting),
            3 => Ok(Self::Running),
            4 => Ok(Self::Stopping),
            5 => Ok(Self::Exited),
            6 => Ok(Self::Faulted),
            7 => Ok(Self::RestartPending),
            _ => Err(ProtocolError::UnknownLifecycleState(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum LifecycleEventKind {
    Started = 1,
    Ready = 2,
    StopRequested = 3,
    Exited = 4,
    Faulted = 5,
}

impl LifecycleEventKind {
    fn decode(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            1 => Ok(Self::Started),
            2 => Ok(Self::Ready),
            3 => Ok(Self::StopRequested),
            4 => Ok(Self::Exited),
            5 => Ok(Self::Faulted),
            _ => Err(ProtocolError::UnknownLifecycleEvent(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum LifecycleControlAction {
    Start = 1,
    Stop = 2,
    Restart = 3,
}

impl LifecycleControlAction {
    fn decode(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            1 => Ok(Self::Start),
            2 => Ok(Self::Stop),
            3 => Ok(Self::Restart),
            _ => Err(ProtocolError::UnknownControlAction(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ServiceHealth {
    Unknown = 1,
    Healthy = 2,
    Degraded = 3,
    Unhealthy = 4,
}

impl ServiceHealth {
    fn decode(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            1 => Ok(Self::Unknown),
            2 => Ok(Self::Healthy),
            3 => Ok(Self::Degraded),
            4 => Ok(Self::Unhealthy),
            _ => Err(ProtocolError::UnknownHealthState(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum DependencyRequirement {
    Running = 1,
    Ready = 2,
}

impl DependencyRequirement {
    fn decode(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            1 => Ok(Self::Running),
            2 => Ok(Self::Ready),
            _ => Err(ProtocolError::UnknownDependencyRequirement(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum ServiceMessageKind {
    ControlRequest = 1,
    LifecycleEvent = 2,
    HealthReport = 3,
    DependencyMetadata = 4,
}

impl ServiceMessageKind {
    fn decode(raw: u8) -> Result<Self, ProtocolError> {
        match raw {
            1 => Ok(Self::ControlRequest),
            2 => Ok(Self::LifecycleEvent),
            3 => Ok(Self::HealthReport),
            4 => Ok(Self::DependencyMetadata),
            _ => Err(ProtocolError::UnknownMessageKind(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExtensionEnvelope {
    pub(crate) kind: u8,
    pub(crate) length: u16,
    pub(crate) payload: u64,
}

impl ExtensionEnvelope {
    pub(crate) const NONE: Self = Self {
        kind: 0,
        length: 0,
        payload: 0,
    };

    pub(crate) fn validate(self) -> Result<(), ProtocolError> {
        if usize::from(self.length) > SERVICE_PROTOCOL_EXTENSION_BYTES {
            return Err(ProtocolError::ExtensionTooLarge(self.length));
        }
        if self.length == 0 && self.payload != 0 {
            return Err(ProtocolError::ExtensionPayloadWithoutLength);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TargetInstance {
    pub(crate) pid: u64,
    pub(crate) generation: u32,
}

impl TargetInstance {
    pub(crate) const NONE: Self = Self {
        pid: 0,
        generation: 0,
    };

    pub(crate) fn for_instance(instance: ServiceInstance) -> Self {
        Self {
            pid: instance.pid,
            generation: instance.generation,
        }
    }

    fn validate(self, action: LifecycleControlAction) -> Result<(), ProtocolError> {
        match action {
            LifecycleControlAction::Start => {
                if self != Self::NONE {
                    return Err(ProtocolError::UnexpectedTargetInstance);
                }
            }
            LifecycleControlAction::Stop | LifecycleControlAction::Restart => {
                if self.pid == 0 {
                    return Err(ProtocolError::InvalidInstancePid);
                }
                if self.generation == 0 {
                    return Err(ProtocolError::InvalidInstanceGeneration);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleControlRequest {
    pub(crate) service_id: ServiceId,
    pub(crate) action: LifecycleControlAction,
    pub(crate) target: TargetInstance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LifecycleEvent {
    pub(crate) service_id: ServiceId,
    pub(crate) event: LifecycleEventKind,
    pub(crate) state: ServiceLifecycleState,
    pub(crate) instance: ServiceInstance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HealthReport {
    pub(crate) service_id: ServiceId,
    pub(crate) instance: ServiceInstance,
    pub(crate) health: ServiceHealth,
    pub(crate) extension: ExtensionEnvelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DependencyMetadata {
    pub(crate) service_id: ServiceId,
    pub(crate) dependency_id: ServiceId,
    pub(crate) requirement: DependencyRequirement,
    pub(crate) extension: ExtensionEnvelope,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ServiceProtocolMessage {
    ControlRequest(LifecycleControlRequest),
    LifecycleEvent(LifecycleEvent),
    HealthReport(HealthReport),
    DependencyMetadata(DependencyMetadata),
}

impl ServiceProtocolMessage {
    pub(crate) fn encode(self) -> Result<ServiceWireMessage, ProtocolError> {
        match self {
            Self::ControlRequest(message) => {
                message.target.validate(message.action)?;
                Ok(ServiceWireMessage::new(
                    ServiceMessageKind::ControlRequest,
                    message.action as u8,
                    ExtensionEnvelope::NONE,
                    [
                        message.service_id.raw(),
                        message.target.pid,
                        u64::from(message.target.generation),
                        0,
                    ],
                ))
            }
            Self::LifecycleEvent(message) => Ok(ServiceWireMessage::new(
                ServiceMessageKind::LifecycleEvent,
                message.event as u8,
                ExtensionEnvelope {
                    kind: message.state as u8,
                    length: 0,
                    payload: 0,
                },
                [
                    message.service_id.raw(),
                    message.instance.pid,
                    u64::from(message.instance.generation),
                    0,
                ],
            )),
            Self::HealthReport(message) => {
                message.extension.validate()?;
                Ok(ServiceWireMessage::new(
                    ServiceMessageKind::HealthReport,
                    message.health as u8,
                    message.extension,
                    [
                        message.service_id.raw(),
                        message.instance.pid,
                        u64::from(message.instance.generation),
                        message.extension.payload,
                    ],
                ))
            }
            Self::DependencyMetadata(message) => {
                message.extension.validate()?;
                Ok(ServiceWireMessage::new(
                    ServiceMessageKind::DependencyMetadata,
                    message.requirement as u8,
                    message.extension,
                    [
                        message.service_id.raw(),
                        message.dependency_id.raw(),
                        0,
                        message.extension.payload,
                    ],
                ))
            }
        }
    }

    pub(crate) fn decode(wire: ServiceWireMessage) -> Result<Self, ProtocolError> {
        match ServiceMessageKind::decode(wire.kind)? {
            ServiceMessageKind::ControlRequest => {
                wire.validate(ServiceMessageKind::ControlRequest)?;
                let action = LifecycleControlAction::decode(wire.discriminant)?;
                let service_id = ServiceId::new(wire.word0)?;
                let generation = u32::try_from(wire.word2)
                    .map_err(|_| ProtocolError::InvalidInstanceGeneration)?;
                let target = TargetInstance {
                    pid: wire.word1,
                    generation,
                };
                target.validate(action)?;
                Ok(Self::ControlRequest(LifecycleControlRequest {
                    service_id,
                    action,
                    target,
                }))
            }
            ServiceMessageKind::LifecycleEvent => {
                wire.validate(ServiceMessageKind::LifecycleEvent)?;
                let event = LifecycleEventKind::decode(wire.discriminant)?;
                let state = ServiceLifecycleState::decode(wire.extension_kind)?;
                let service_id = ServiceId::new(wire.word0)?;
                let generation = u32::try_from(wire.word2)
                    .map_err(|_| ProtocolError::InvalidInstanceGeneration)?;
                Ok(Self::LifecycleEvent(LifecycleEvent {
                    service_id,
                    event,
                    state,
                    instance: ServiceInstance::new(wire.word1, generation)?,
                }))
            }
            ServiceMessageKind::HealthReport => {
                wire.validate(ServiceMessageKind::HealthReport)?;
                let health = ServiceHealth::decode(wire.discriminant)?;
                let service_id = ServiceId::new(wire.word0)?;
                let generation = u32::try_from(wire.word2)
                    .map_err(|_| ProtocolError::InvalidInstanceGeneration)?;
                let extension = ExtensionEnvelope {
                    kind: wire.extension_kind,
                    length: wire.extension_length,
                    payload: wire.word3,
                };
                extension.validate()?;
                Ok(Self::HealthReport(HealthReport {
                    service_id,
                    instance: ServiceInstance::new(wire.word1, generation)?,
                    health,
                    extension,
                }))
            }
            ServiceMessageKind::DependencyMetadata => {
                wire.validate(ServiceMessageKind::DependencyMetadata)?;
                let requirement = DependencyRequirement::decode(wire.discriminant)?;
                let extension = ExtensionEnvelope {
                    kind: wire.extension_kind,
                    length: wire.extension_length,
                    payload: wire.word3,
                };
                extension.validate()?;
                Ok(Self::DependencyMetadata(DependencyMetadata {
                    service_id: ServiceId::new(wire.word0)?,
                    dependency_id: ServiceId::new(wire.word1)?,
                    requirement,
                    extension,
                }))
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct ServiceWireMessage {
    version: u8,
    kind: u8,
    length: u16,
    discriminant: u8,
    extension_kind: u8,
    extension_length: u16,
    word0: u64,
    word1: u64,
    word2: u64,
    word3: u64,
}

impl ServiceWireMessage {
    const fn new(
        kind: ServiceMessageKind,
        discriminant: u8,
        extension: ExtensionEnvelope,
        words: [u64; 4],
    ) -> Self {
        Self {
            version: SERVICE_PROTOCOL_VERSION,
            kind: kind as u8,
            length: SERVICE_PROTOCOL_MESSAGE_BYTES as u16,
            discriminant,
            extension_kind: extension.kind,
            extension_length: extension.length,
            word0: words[0],
            word1: words[1],
            word2: words[2],
            word3: words[3],
        }
    }

    fn validate(self, expected_kind: ServiceMessageKind) -> Result<(), ProtocolError> {
        if self.version != SERVICE_PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.version));
        }
        if usize::from(self.length) != SERVICE_PROTOCOL_MESSAGE_BYTES {
            return Err(ProtocolError::InvalidWireLength(self.length));
        }
        if self.kind != expected_kind as u8 {
            return Err(ProtocolError::UnexpectedMessageKind {
                expected: expected_kind,
                actual: self.kind,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ServiceStateModel {
    pub(crate) service_id: ServiceId,
    pub(crate) state: ServiceLifecycleState,
    pub(crate) instance: Option<ServiceInstance>,
}

impl ServiceStateModel {
    pub(crate) const fn declared(service_id: ServiceId) -> Self {
        Self {
            service_id,
            state: ServiceLifecycleState::Declared,
            instance: None,
        }
    }

    pub(crate) fn apply_control(
        &mut self,
        request: LifecycleControlRequest,
    ) -> Result<(), ProtocolError> {
        self.validate_service_id(request.service_id)?;
        request.target.validate(request.action)?;
        match request.action {
            LifecycleControlAction::Start => {
                if !matches!(
                    self.state,
                    ServiceLifecycleState::Declared | ServiceLifecycleState::Exited
                ) {
                    return Err(ProtocolError::InvalidTransition {
                        from: self.state,
                        step: TransitionStep::Control(request.action),
                    });
                }
                self.state = ServiceLifecycleState::Starting;
                self.instance = None;
            }
            LifecycleControlAction::Stop => {
                let current = self.current_instance()?;
                if !matches!(
                    self.state,
                    ServiceLifecycleState::Starting | ServiceLifecycleState::Running
                ) {
                    return Err(ProtocolError::InvalidTransition {
                        from: self.state,
                        step: TransitionStep::Control(request.action),
                    });
                }
                self.require_target(current, request.target)?;
                self.state = ServiceLifecycleState::Stopping;
            }
            LifecycleControlAction::Restart => {
                let current = self.current_instance()?;
                if !matches!(
                    self.state,
                    ServiceLifecycleState::Faulted | ServiceLifecycleState::Exited
                ) {
                    return Err(ProtocolError::InvalidTransition {
                        from: self.state,
                        step: TransitionStep::Control(request.action),
                    });
                }
                self.require_target(current, request.target)?;
                self.state = ServiceLifecycleState::RestartPending;
            }
        }
        Ok(())
    }

    pub(crate) fn apply_event(&mut self, event: LifecycleEvent) -> Result<(), ProtocolError> {
        self.validate_service_id(event.service_id)?;
        match event.event {
            LifecycleEventKind::Started => self.apply_started(event),
            LifecycleEventKind::Ready => {
                self.require_state(ServiceLifecycleState::Starting, event.event)?;
                self.require_current_instance(event.instance)?;
                if event.state != ServiceLifecycleState::Running {
                    return Err(ProtocolError::EventStateMismatch {
                        event: event.event,
                        state: event.state,
                    });
                }
                self.state = ServiceLifecycleState::Running;
                Ok(())
            }
            LifecycleEventKind::StopRequested => {
                if !matches!(
                    self.state,
                    ServiceLifecycleState::Starting | ServiceLifecycleState::Running
                ) {
                    return Err(ProtocolError::InvalidTransition {
                        from: self.state,
                        step: TransitionStep::Event(event.event),
                    });
                }
                self.require_current_instance(event.instance)?;
                if event.state != ServiceLifecycleState::Stopping {
                    return Err(ProtocolError::EventStateMismatch {
                        event: event.event,
                        state: event.state,
                    });
                }
                self.state = ServiceLifecycleState::Stopping;
                Ok(())
            }
            LifecycleEventKind::Exited => {
                if !matches!(
                    self.state,
                    ServiceLifecycleState::Starting
                        | ServiceLifecycleState::Running
                        | ServiceLifecycleState::Stopping
                ) {
                    return Err(ProtocolError::InvalidTransition {
                        from: self.state,
                        step: TransitionStep::Event(event.event),
                    });
                }
                self.require_current_instance(event.instance)?;
                if event.state != ServiceLifecycleState::Exited {
                    return Err(ProtocolError::EventStateMismatch {
                        event: event.event,
                        state: event.state,
                    });
                }
                self.state = ServiceLifecycleState::Exited;
                Ok(())
            }
            LifecycleEventKind::Faulted => {
                if !matches!(
                    self.state,
                    ServiceLifecycleState::Starting
                        | ServiceLifecycleState::Running
                        | ServiceLifecycleState::Stopping
                ) {
                    return Err(ProtocolError::InvalidTransition {
                        from: self.state,
                        step: TransitionStep::Event(event.event),
                    });
                }
                self.require_current_instance(event.instance)?;
                if event.state != ServiceLifecycleState::Faulted {
                    return Err(ProtocolError::EventStateMismatch {
                        event: event.event,
                        state: event.state,
                    });
                }
                self.state = ServiceLifecycleState::Faulted;
                Ok(())
            }
        }
    }

    fn apply_started(&mut self, event: LifecycleEvent) -> Result<(), ProtocolError> {
        match self.state {
            ServiceLifecycleState::Starting => {
                if let Some(current) = self.instance {
                    if event.instance != current {
                        return Err(ProtocolError::StaleInstanceEvent {
                            current,
                            observed: event.instance,
                        });
                    }
                }
            }
            ServiceLifecycleState::RestartPending => {
                let previous = self.current_instance()?;
                if !event.instance.succeeds(previous) {
                    return Err(ProtocolError::ReplacementInstanceNotNewer {
                        previous,
                        replacement: event.instance,
                    });
                }
            }
            _ => {
                return Err(ProtocolError::InvalidTransition {
                    from: self.state,
                    step: TransitionStep::Event(event.event),
                });
            }
        }
        if event.state != ServiceLifecycleState::Starting {
            return Err(ProtocolError::EventStateMismatch {
                event: event.event,
                state: event.state,
            });
        }
        self.instance = Some(event.instance);
        self.state = ServiceLifecycleState::Starting;
        Ok(())
    }

    fn current_instance(self) -> Result<ServiceInstance, ProtocolError> {
        self.instance.ok_or(ProtocolError::MissingCurrentInstance)
    }

    fn require_current_instance(self, observed: ServiceInstance) -> Result<(), ProtocolError> {
        let current = self.current_instance()?;
        if observed != current {
            return Err(ProtocolError::StaleInstanceEvent { current, observed });
        }
        Ok(())
    }

    fn require_state(
        self,
        expected: ServiceLifecycleState,
        event: LifecycleEventKind,
    ) -> Result<(), ProtocolError> {
        if self.state != expected {
            return Err(ProtocolError::InvalidTransition {
                from: self.state,
                step: TransitionStep::Event(event),
            });
        }
        Ok(())
    }

    fn require_target(
        self,
        current: ServiceInstance,
        target: TargetInstance,
    ) -> Result<(), ProtocolError> {
        let observed = ServiceInstance::new(target.pid, target.generation)?;
        if observed != current {
            return Err(ProtocolError::StaleInstanceEvent { current, observed });
        }
        Ok(())
    }

    fn validate_service_id(self, observed: ServiceId) -> Result<(), ProtocolError> {
        if self.service_id != observed {
            return Err(ProtocolError::ServiceIdMismatch {
                expected: self.service_id,
                observed,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TransitionStep {
    Control(LifecycleControlAction),
    Event(LifecycleEventKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProtocolError {
    InvalidServiceId,
    InvalidInstancePid,
    InvalidInstanceGeneration,
    UnsupportedVersion(u8),
    InvalidWireLength(u16),
    UnknownMessageKind(u8),
    UnexpectedMessageKind {
        expected: ServiceMessageKind,
        actual: u8,
    },
    UnknownLifecycleState(u8),
    UnknownLifecycleEvent(u8),
    UnknownControlAction(u8),
    UnknownHealthState(u8),
    UnknownDependencyRequirement(u8),
    ExtensionTooLarge(u16),
    ExtensionPayloadWithoutLength,
    UnexpectedTargetInstance,
    MissingCurrentInstance,
    InvalidTransition {
        from: ServiceLifecycleState,
        step: TransitionStep,
    },
    EventStateMismatch {
        event: LifecycleEventKind,
        state: ServiceLifecycleState,
    },
    StaleInstanceEvent {
        current: ServiceInstance,
        observed: ServiceInstance,
    },
    ReplacementInstanceNotNewer {
        previous: ServiceInstance,
        replacement: ServiceInstance,
    },
    ServiceIdMismatch {
        expected: ServiceId,
        observed: ServiceId,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_protocol_messages_stay_within_ipc_bound() {
        let wire = ServiceProtocolMessage::ControlRequest(LifecycleControlRequest {
            service_id: ServiceId::new(1).expect("service"),
            action: LifecycleControlAction::Start,
            target: TargetInstance::NONE,
        })
        .encode()
        .expect("encode");
        assert!(size_of_val(&wire) <= IPC_MAX_MESSAGE_BYTES);
    }

    #[test]
    fn decode_rejects_unknown_protocol_version() {
        let mut wire = ServiceProtocolMessage::ControlRequest(LifecycleControlRequest {
            service_id: ServiceId::new(1).expect("service"),
            action: LifecycleControlAction::Start,
            target: TargetInstance::NONE,
        })
        .encode()
        .expect("encode");
        wire.version = SERVICE_PROTOCOL_VERSION + 1;

        assert_eq!(
            ServiceProtocolMessage::decode(wire),
            Err(ProtocolError::UnsupportedVersion(
                SERVICE_PROTOCOL_VERSION + 1
            ))
        );
    }

    #[test]
    fn decode_rejects_unknown_message_kind() {
        let mut wire = ServiceProtocolMessage::ControlRequest(LifecycleControlRequest {
            service_id: ServiceId::new(7).expect("service"),
            action: LifecycleControlAction::Start,
            target: TargetInstance::NONE,
        })
        .encode()
        .expect("encode");
        wire.kind = 99;

        assert_eq!(
            ServiceProtocolMessage::decode(wire),
            Err(ProtocolError::UnknownMessageKind(99))
        );
    }

    #[test]
    fn decode_rejects_wrong_message_length() {
        let mut wire = ServiceProtocolMessage::HealthReport(HealthReport {
            service_id: ServiceId::new(9).expect("service"),
            instance: ServiceInstance::new(11, 3).expect("instance"),
            health: ServiceHealth::Healthy,
            extension: ExtensionEnvelope::NONE,
        })
        .encode()
        .expect("encode");
        wire.length -= 8;

        assert_eq!(
            ServiceProtocolMessage::decode(wire),
            Err(ProtocolError::InvalidWireLength(
                (SERVICE_PROTOCOL_MESSAGE_BYTES as u16) - 8
            ))
        );
    }

    #[test]
    fn lifecycle_state_model_enforces_declared_start_run_fault_restart_flow() {
        let service_id = ServiceId::new(1).expect("service");
        let instance = ServiceInstance::new(41, 1).expect("instance");
        let replacement = ServiceInstance::new(42, 2).expect("replacement");
        let mut model = ServiceStateModel::declared(service_id);

        model
            .apply_control(LifecycleControlRequest {
                service_id,
                action: LifecycleControlAction::Start,
                target: TargetInstance::NONE,
            })
            .expect("start");
        assert_eq!(model.state, ServiceLifecycleState::Starting);
        assert_eq!(model.instance, None);

        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Started,
                state: ServiceLifecycleState::Starting,
                instance,
            })
            .expect("started");
        assert_eq!(model.instance, Some(instance));

        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Ready,
                state: ServiceLifecycleState::Running,
                instance,
            })
            .expect("ready");
        assert_eq!(model.state, ServiceLifecycleState::Running);

        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Faulted,
                state: ServiceLifecycleState::Faulted,
                instance,
            })
            .expect("fault");
        assert_eq!(model.state, ServiceLifecycleState::Faulted);

        model
            .apply_control(LifecycleControlRequest {
                service_id,
                action: LifecycleControlAction::Restart,
                target: TargetInstance::for_instance(instance),
            })
            .expect("restart");
        assert_eq!(model.state, ServiceLifecycleState::RestartPending);

        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Started,
                state: ServiceLifecycleState::Starting,
                instance: replacement,
            })
            .expect("replacement started");
        assert_eq!(model.instance, Some(replacement));
        assert_eq!(model.state, ServiceLifecycleState::Starting);
    }

    #[test]
    fn stale_instance_events_cannot_overwrite_newer_replacement_state() {
        let service_id = ServiceId::new(1).expect("service");
        let instance = ServiceInstance::new(41, 1).expect("instance");
        let replacement = ServiceInstance::new(42, 2).expect("replacement");
        let mut model = ServiceStateModel {
            service_id,
            state: ServiceLifecycleState::Running,
            instance: Some(instance),
        };

        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Faulted,
                state: ServiceLifecycleState::Faulted,
                instance,
            })
            .expect("fault");
        model
            .apply_control(LifecycleControlRequest {
                service_id,
                action: LifecycleControlAction::Restart,
                target: TargetInstance::for_instance(instance),
            })
            .expect("restart");
        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Started,
                state: ServiceLifecycleState::Starting,
                instance: replacement,
            })
            .expect("replacement");
        model
            .apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Ready,
                state: ServiceLifecycleState::Running,
                instance: replacement,
            })
            .expect("running");

        assert_eq!(
            model.apply_event(LifecycleEvent {
                service_id,
                event: LifecycleEventKind::Exited,
                state: ServiceLifecycleState::Exited,
                instance,
            }),
            Err(ProtocolError::StaleInstanceEvent {
                current: replacement,
                observed: instance,
            })
        );
        assert_eq!(model.state, ServiceLifecycleState::Running);
        assert_eq!(model.instance, Some(replacement));
    }

    #[test]
    fn extension_envelopes_validate_stably_for_health_and_dependencies() {
        let service_id = ServiceId::new(5).expect("service");
        let instance = ServiceInstance::new(8, 2).expect("instance");
        let extension = ExtensionEnvelope {
            kind: 7,
            length: 8,
            payload: 0xfeed_face_dead_beef,
        };

        let health = ServiceProtocolMessage::HealthReport(HealthReport {
            service_id,
            instance,
            health: ServiceHealth::Degraded,
            extension,
        })
        .encode()
        .expect("encode health");
        assert_eq!(
            ServiceProtocolMessage::decode(health),
            Ok(ServiceProtocolMessage::HealthReport(HealthReport {
                service_id,
                instance,
                health: ServiceHealth::Degraded,
                extension,
            }))
        );

        let dependency = ServiceProtocolMessage::DependencyMetadata(DependencyMetadata {
            service_id,
            dependency_id: ServiceId::new(6).expect("dependency"),
            requirement: DependencyRequirement::Ready,
            extension,
        })
        .encode()
        .expect("encode dependency");
        assert_eq!(
            ServiceProtocolMessage::decode(dependency),
            Ok(ServiceProtocolMessage::DependencyMetadata(
                DependencyMetadata {
                    service_id,
                    dependency_id: ServiceId::new(6).expect("dependency"),
                    requirement: DependencyRequirement::Ready,
                    extension,
                }
            ))
        );
    }
}
