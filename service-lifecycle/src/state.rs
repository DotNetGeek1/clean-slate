//! Lifecycle states, events, and explicit transition rules.

use crate::control::ControlRequestKind;
use crate::identity::{InstanceGeneration, ServiceInstanceId};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ServiceLifecycleState {
    Declared = 0,
    Starting = 1,
    Running = 2,
    Stopping = 3,
    Exited = 4,
    Faulted = 5,
    RestartPending = 6,
}

impl ServiceLifecycleState {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Declared),
            1 => Some(Self::Starting),
            2 => Some(Self::Running),
            3 => Some(Self::Stopping),
            4 => Some(Self::Exited),
            5 => Some(Self::Faulted),
            6 => Some(Self::RestartPending),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LifecycleEventKind {
    InstanceSpawned = 1,
    Started = 2,
    Ready = 3,
    StopAcknowledged = 4,
    Exited = 5,
    Faulted = 6,
}

impl LifecycleEventKind {
    pub const fn from_repr(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::InstanceSpawned),
            2 => Some(Self::Started),
            3 => Some(Self::Ready),
            4 => Some(Self::StopAcknowledged),
            5 => Some(Self::Exited),
            6 => Some(Self::Faulted),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LifecycleEvent {
    pub instance: ServiceInstanceId,
    pub kind: LifecycleEventKind,
    pub status_code: u32,
}

impl LifecycleEvent {
    pub const fn new(instance: ServiceInstanceId, kind: LifecycleEventKind) -> Self {
        Self {
            instance,
            kind,
            status_code: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition {
        from: ServiceLifecycleState,
        input: TransitionInput,
    },
    StaleInstance {
        observed: InstanceGeneration,
        authoritative: InstanceGeneration,
    },
    InstanceMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionInput {
    Control(ControlRequestKind),
    Event(LifecycleEventKind),
}

/// Applies a control request or lifecycle event to `state`, updating `authoritative_generation`
/// when a new instance is spawned.
pub fn apply_transition(
    state: ServiceLifecycleState,
    authoritative_generation: InstanceGeneration,
    input: TransitionInput,
    event_instance: Option<ServiceInstanceId>,
) -> Result<(ServiceLifecycleState, InstanceGeneration), TransitionError> {
    match input {
        TransitionInput::Control(kind) => apply_control(state, authoritative_generation, kind),
        TransitionInput::Event(event_kind) => {
            let instance = event_instance.ok_or(TransitionError::InstanceMismatch)?;
            apply_event(state, authoritative_generation, instance, event_kind)
        }
    }
}

fn apply_control(
    state: ServiceLifecycleState,
    generation: InstanceGeneration,
    kind: ControlRequestKind,
) -> Result<(ServiceLifecycleState, InstanceGeneration), TransitionError> {
    let input = TransitionInput::Control(kind);
    match (state, kind) {
        (ServiceLifecycleState::Declared, ControlRequestKind::Start) => {
            Ok((ServiceLifecycleState::Starting, bump_generation(generation)))
        }
        (
            ServiceLifecycleState::Exited | ServiceLifecycleState::Faulted,
            ControlRequestKind::Start,
        ) => Ok((ServiceLifecycleState::Starting, bump_generation(generation))),
        (ServiceLifecycleState::RestartPending, ControlRequestKind::Start) => {
            Ok((ServiceLifecycleState::Starting, bump_generation(generation)))
        }
        (
            ServiceLifecycleState::Running,
            ControlRequestKind::Stop | ControlRequestKind::Terminate,
        ) => Ok((ServiceLifecycleState::Stopping, generation)),
        (ServiceLifecycleState::Starting, ControlRequestKind::Terminate) => {
            Ok((ServiceLifecycleState::Stopping, generation))
        }
        (
            ServiceLifecycleState::Faulted | ServiceLifecycleState::Exited,
            ControlRequestKind::Restart,
        ) => Ok((ServiceLifecycleState::RestartPending, generation)),
        (ServiceLifecycleState::Running, ControlRequestKind::Restart) => {
            Ok((ServiceLifecycleState::RestartPending, generation))
        }
        _ => Err(TransitionError::InvalidTransition { from: state, input }),
    }
}

fn apply_event(
    state: ServiceLifecycleState,
    authoritative_generation: InstanceGeneration,
    instance: ServiceInstanceId,
    kind: LifecycleEventKind,
) -> Result<(ServiceLifecycleState, InstanceGeneration), TransitionError> {
    let input = TransitionInput::Event(kind);
    if instance.generation < authoritative_generation {
        return Err(TransitionError::StaleInstance {
            observed: instance.generation,
            authoritative: authoritative_generation,
        });
    }
    if instance.generation > authoritative_generation {
        return Err(TransitionError::StaleInstance {
            observed: instance.generation,
            authoritative: authoritative_generation,
        });
    }

    match (state, kind) {
        (ServiceLifecycleState::Starting, LifecycleEventKind::InstanceSpawned) => {
            Ok((ServiceLifecycleState::Starting, authoritative_generation))
        }
        (ServiceLifecycleState::Starting, LifecycleEventKind::Started) => {
            Ok((ServiceLifecycleState::Starting, authoritative_generation))
        }
        (ServiceLifecycleState::Starting, LifecycleEventKind::Ready) => {
            Ok((ServiceLifecycleState::Running, authoritative_generation))
        }
        (ServiceLifecycleState::Running, LifecycleEventKind::Faulted) => {
            Ok((ServiceLifecycleState::Faulted, authoritative_generation))
        }
        (ServiceLifecycleState::Running, LifecycleEventKind::Exited) => {
            Ok((ServiceLifecycleState::Exited, authoritative_generation))
        }
        (ServiceLifecycleState::Stopping, LifecycleEventKind::StopAcknowledged) => {
            Ok((ServiceLifecycleState::Stopping, authoritative_generation))
        }
        (ServiceLifecycleState::Stopping, LifecycleEventKind::Exited) => {
            Ok((ServiceLifecycleState::Exited, authoritative_generation))
        }
        (ServiceLifecycleState::Starting, LifecycleEventKind::Faulted) => {
            Ok((ServiceLifecycleState::Faulted, authoritative_generation))
        }
        (ServiceLifecycleState::Starting, LifecycleEventKind::Exited) => {
            Ok((ServiceLifecycleState::Exited, authoritative_generation))
        }
        _ => Err(TransitionError::InvalidTransition { from: state, input }),
    }
}

fn bump_generation(generation: InstanceGeneration) -> InstanceGeneration {
    InstanceGeneration(generation.0.saturating_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{DomainId, ProcessId, ServiceId};

    fn instance(gen: u32, pid: u64) -> ServiceInstanceId {
        ServiceInstanceId::new(
            ServiceId(7),
            InstanceGeneration(gen),
            ProcessId(pid),
            DomainId(pid),
        )
    }

    #[test]
    fn declared_start_bumps_generation_and_enters_starting() {
        let (next, gen) = apply_transition(
            ServiceLifecycleState::Declared,
            InstanceGeneration(0),
            TransitionInput::Control(ControlRequestKind::Start),
            None,
        )
        .expect("start from declared");
        assert_eq!(next, ServiceLifecycleState::Starting);
        assert_eq!(gen, InstanceGeneration(1));
    }

    #[test]
    fn ready_promotes_starting_to_running() {
        let (next, _) = apply_transition(
            ServiceLifecycleState::Starting,
            InstanceGeneration(1),
            TransitionInput::Event(LifecycleEventKind::Ready),
            Some(instance(1, 42)),
        )
        .expect("ready");
        assert_eq!(next, ServiceLifecycleState::Running);
    }

    #[test]
    fn stale_instance_event_is_rejected() {
        let err = apply_transition(
            ServiceLifecycleState::Running,
            InstanceGeneration(2),
            TransitionInput::Event(LifecycleEventKind::Exited),
            Some(instance(1, 10)),
        )
        .unwrap_err();
        assert_eq!(
            err,
            TransitionError::StaleInstance {
                observed: InstanceGeneration(1),
                authoritative: InstanceGeneration(2),
            }
        );
    }

    #[test]
    fn invalid_transition_is_explicit() {
        let err = apply_transition(
            ServiceLifecycleState::Declared,
            InstanceGeneration(0),
            TransitionInput::Event(LifecycleEventKind::Ready),
            Some(instance(0, 1)),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            TransitionError::InvalidTransition {
                from: ServiceLifecycleState::Declared,
                ..
            }
        ));
    }
}
