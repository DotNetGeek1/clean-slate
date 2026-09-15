//! Supervisor-owned dependency graph storage and deterministic readiness evaluation (M4.5).

use crate::dependency::{DependencyEdge, DependencyMetadata, MAX_INLINE_DEPENDENCIES};
use crate::health::HealthStatus;
use crate::identity::ServiceId;
use crate::state::ServiceLifecycleState;
use crate::tracker::{ServiceLifecycleRecord, ServiceLifecycleTracker};

/// Default minimum lifecycle state for a dependency edge.
pub const DEFAULT_REQUIRED_DEPENDENCY_STATE: ServiceLifecycleState = ServiceLifecycleState::Running;

/// Outcome of evaluating whether a service may receive a start attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartReadiness {
    Ready,
    Blocked(StartBlockReason),
}

/// Deterministic reason a start is blocked (first failing edge in declaration order).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartBlockReason {
    DependencyNotReady {
        dependency: ServiceId,
        observed: ServiceLifecycleState,
        required: ServiceLifecycleState,
    },
    DependencyFailed {
        dependency: ServiceId,
        observed: ServiceLifecycleState,
    },
    DependencyUnhealthy {
        dependency: ServiceId,
        observed: HealthStatus,
    },
}

/// Errors while registering dependency metadata (graph must stay well-formed).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DependencyGraphError {
    UnknownService,
    DuplicateService,
    CapacityExceeded,
    UnknownDependency {
        service: ServiceId,
        depends_on: ServiceId,
    },
    SelfDependency {
        service: ServiceId,
    },
    DuplicateDependencyEdge {
        service: ServiceId,
        depends_on: ServiceId,
    },
    CycleDetected {
        service: ServiceId,
    },
    EdgeCapacityExceeded {
        service: ServiceId,
    },
}

/// Fixed-capacity in-memory dependency graph keyed by logical `ServiceId`.
pub struct DependencyGraph<const N: usize> {
    metadata: [Option<DependencyMetadata>; N],
}

impl<const N: usize> Default for DependencyGraph<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DependencyGraph<N> {
    pub const fn new() -> Self {
        Self {
            metadata: [None; N],
        }
    }

    /// Registers a service with empty dependency metadata.
    pub fn declare(&mut self, service: ServiceId) -> Result<(), DependencyGraphError> {
        if self.find_index(service).is_some() {
            return Err(DependencyGraphError::DuplicateService);
        }
        let slot = self
            .metadata
            .iter()
            .position(|entry| entry.is_none())
            .ok_or(DependencyGraphError::CapacityExceeded)?;
        self.metadata[slot] = Some(DependencyMetadata::empty(service));
        Ok(())
    }

    /// Replaces dependency metadata for a declared service after validation.
    pub fn set_dependencies(
        &mut self,
        metadata: DependencyMetadata,
    ) -> Result<(), DependencyGraphError> {
        let index = self
            .find_index(metadata.service)
            .ok_or(DependencyGraphError::UnknownService)?;
        validate_metadata_shape(&metadata)?;
        for edge in metadata_edges(&metadata) {
            if self.find_index(edge.depends_on).is_none() {
                return Err(DependencyGraphError::UnknownDependency {
                    service: metadata.service,
                    depends_on: edge.depends_on,
                });
            }
        }
        let previous = self.metadata[index];
        self.metadata[index] = Some(metadata);
        if detect_cycle_involving(metadata.service, &self.metadata) {
            self.metadata[index] = previous;
            return Err(DependencyGraphError::CycleDetected {
                service: metadata.service,
            });
        }
        Ok(())
    }

    pub fn metadata(&self, service: ServiceId) -> Option<&DependencyMetadata> {
        self.find_index(service)
            .and_then(|index| self.metadata[index].as_ref())
    }

    /// Evaluates start eligibility from current lifecycle (and optional health) snapshots.
    ///
    /// Does not mutate metadata; dependency recovery only requires upstream state to change.
    pub fn evaluate_start_readiness(
        &self,
        service: ServiceId,
        lifecycle: &ServiceLifecycleTracker<N>,
        health: Option<&DependencyHealthSnapshot<N>>,
    ) -> Result<StartReadiness, DependencyGraphError> {
        let metadata = self
            .metadata(service)
            .ok_or(DependencyGraphError::UnknownService)?;
        for edge in metadata_edges(metadata) {
            let record = lifecycle.record(edge.depends_on).ok_or(
                DependencyGraphError::UnknownDependency {
                    service,
                    depends_on: edge.depends_on,
                },
            )?;
            if let Some(reason) = edge_blocks_start(edge, record, health) {
                return Ok(StartReadiness::Blocked(reason));
            }
        }
        Ok(StartReadiness::Ready)
    }

    fn find_index(&self, service: ServiceId) -> Option<usize> {
        self.metadata
            .iter()
            .position(|entry| matches!(entry, Some(meta) if meta.service == service))
    }
}

/// Optional parallel health view for readiness (no timeout policy).
#[derive(Clone, Copy, Debug)]
pub struct DependencyHealthSnapshot<const N: usize> {
    entries: [(ServiceId, HealthStatus); N],
    count: usize,
}

impl<const N: usize> DependencyHealthSnapshot<N> {
    pub const fn empty() -> Self {
        Self {
            entries: [(ServiceId(0), HealthStatus::Unknown); N],
            count: 0,
        }
    }

    pub fn set(
        &mut self,
        service: ServiceId,
        status: HealthStatus,
    ) -> Result<(), DependencyGraphError> {
        if let Some(index) = self.entries.iter().position(|(id, _)| *id == service) {
            self.entries[index].1 = status;
            return Ok(());
        }
        if self.count >= N {
            return Err(DependencyGraphError::CapacityExceeded);
        }
        self.entries[self.count] = (service, status);
        self.count += 1;
        Ok(())
    }

    pub fn status(&self, service: ServiceId) -> Option<HealthStatus> {
        self.entries
            .iter()
            .take(self.count)
            .find(|(id, _)| *id == service)
            .map(|(_, status)| *status)
    }
}

fn validate_metadata_shape(metadata: &DependencyMetadata) -> Result<(), DependencyGraphError> {
    if metadata.edge_count as usize > MAX_INLINE_DEPENDENCIES {
        return Err(DependencyGraphError::EdgeCapacityExceeded {
            service: metadata.service,
        });
    }
    if metadata_edges(metadata).any(|edge| edge.depends_on == metadata.service) {
        return Err(DependencyGraphError::SelfDependency {
            service: metadata.service,
        });
    }
    let mut seen = [ServiceId(0); MAX_INLINE_DEPENDENCIES];
    for (seen_count, edge) in metadata_edges(metadata).enumerate() {
        if seen[..seen_count].contains(&edge.depends_on) {
            return Err(DependencyGraphError::DuplicateDependencyEdge {
                service: metadata.service,
                depends_on: edge.depends_on,
            });
        }
        seen[seen_count] = edge.depends_on;
    }
    Ok(())
}

fn metadata_edges(metadata: &DependencyMetadata) -> impl Iterator<Item = &DependencyEdge> {
    metadata.edges.iter().take(metadata.edge_count as usize)
}

fn edge_blocks_start<const N: usize>(
    edge: &DependencyEdge,
    record: &ServiceLifecycleRecord,
    health: Option<&DependencyHealthSnapshot<N>>,
) -> Option<StartBlockReason> {
    let dependency = edge.depends_on;
    let observed = record.state;
    if matches!(
        observed,
        ServiceLifecycleState::Exited | ServiceLifecycleState::Faulted
    ) {
        return Some(StartBlockReason::DependencyFailed {
            dependency,
            observed,
        });
    }
    if !lifecycle_state_satisfies(observed, edge.required_state) {
        return Some(StartBlockReason::DependencyNotReady {
            dependency,
            observed,
            required: edge.required_state,
        });
    }
    if let Some(snapshot) = health {
        if matches!(snapshot.status(dependency), Some(HealthStatus::Unhealthy)) {
            return Some(StartBlockReason::DependencyUnhealthy {
                dependency,
                observed: HealthStatus::Unhealthy,
            });
        }
    }
    None
}

/// Returns true when `actual` meets or exceeds `required` for dependency gating.
pub fn lifecycle_state_satisfies(
    actual: ServiceLifecycleState,
    required: ServiceLifecycleState,
) -> bool {
    match required {
        ServiceLifecycleState::Declared => true,
        ServiceLifecycleState::Starting => matches!(
            actual,
            ServiceLifecycleState::Starting
                | ServiceLifecycleState::Running
                | ServiceLifecycleState::Stopping
        ),
        ServiceLifecycleState::Running => actual == ServiceLifecycleState::Running,
        ServiceLifecycleState::Stopping => matches!(
            actual,
            ServiceLifecycleState::Stopping | ServiceLifecycleState::Running
        ),
        ServiceLifecycleState::Exited | ServiceLifecycleState::Faulted => false,
        ServiceLifecycleState::RestartPending => matches!(
            actual,
            ServiceLifecycleState::RestartPending
                | ServiceLifecycleState::Starting
                | ServiceLifecycleState::Running
        ),
    }
}

fn detect_cycle_involving(service: ServiceId, metadata: &[Option<DependencyMetadata>]) -> bool {
    let Some(meta) = find_metadata(service, metadata) else {
        return false;
    };
    for edge in metadata_edges(meta) {
        if dependency_path_reaches(edge.depends_on, service, metadata, 0) {
            return true;
        }
    }
    false
}

fn dependency_path_reaches(
    current: ServiceId,
    target: ServiceId,
    metadata: &[Option<DependencyMetadata>],
    depth: usize,
) -> bool {
    if current == target {
        return true;
    }
    if depth >= MAX_DEPENDENCY_WALK_DEPTH {
        return false;
    }
    let Some(meta) = find_metadata(current, metadata) else {
        return false;
    };
    for edge in metadata_edges(meta) {
        if dependency_path_reaches(edge.depends_on, target, metadata, depth + 1) {
            return true;
        }
    }
    false
}

const MAX_DEPENDENCY_WALK_DEPTH: usize = 32;

fn find_metadata(
    service: ServiceId,
    metadata: &[Option<DependencyMetadata>],
) -> Option<&DependencyMetadata> {
    metadata
        .iter()
        .find_map(|entry| entry.as_ref().filter(|meta| meta.service == service))
}

/// Builds metadata with a single dependency edge (common supervisor helper).
pub fn single_dependency(
    service: ServiceId,
    depends_on: ServiceId,
    required_state: ServiceLifecycleState,
) -> DependencyMetadata {
    let mut metadata = DependencyMetadata::empty(service);
    metadata.push_edge(DependencyEdge {
        depends_on,
        required_state,
    });
    metadata
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ControlRequest, ControlRequestKind};
    use crate::health::HealthReport;
    use crate::identity::{DomainId, InstanceGeneration, ProcessId, ServiceInstanceId};
    use crate::state::LifecycleEventKind;

    fn running_tracker(service: ServiceId) -> ServiceLifecycleTracker<4> {
        let mut tracker = ServiceLifecycleTracker::<4>::new();
        tracker.declare(service).expect("declare");
        let record = tracker.record_mut(service).expect("record");
        record
            .apply_control(ControlRequest::new(service, ControlRequestKind::Start))
            .expect("start");
        let instance =
            ServiceInstanceId::new(service, InstanceGeneration(1), ProcessId(100), DomainId(1));
        record
            .apply_event(crate::state::LifecycleEvent::new(
                instance,
                LifecycleEventKind::InstanceSpawned,
            ))
            .expect("spawned");
        record
            .apply_event(crate::state::LifecycleEvent::new(
                instance,
                LifecycleEventKind::Ready,
            ))
            .expect("ready");
        tracker
    }

    #[test]
    fn independent_services_are_ready_without_dependencies() {
        let mut graph = DependencyGraph::<4>::new();
        let service = ServiceId(1);
        graph.declare(service).expect("declare");
        let mut tracker = ServiceLifecycleTracker::<4>::new();
        tracker.declare(service).expect("declare");
        assert_eq!(
            graph
                .evaluate_start_readiness(service, &tracker, None)
                .expect("eval"),
            StartReadiness::Ready
        );
    }

    #[test]
    fn linear_dependency_blocks_until_upstream_running() {
        let mut graph = DependencyGraph::<4>::new();
        let upstream = ServiceId(1);
        let downstream = ServiceId(2);
        graph.declare(upstream).expect("declare upstream");
        graph.declare(downstream).expect("declare downstream");
        graph
            .set_dependencies(single_dependency(
                downstream,
                upstream,
                ServiceLifecycleState::Running,
            ))
            .expect("deps");

        let mut tracker = ServiceLifecycleTracker::<4>::new();
        tracker.declare(upstream).expect("declare upstream");
        tracker.declare(downstream).expect("declare downstream");

        let blocked = graph
            .evaluate_start_readiness(downstream, &tracker, None)
            .expect("eval");
        assert_eq!(
            blocked,
            StartReadiness::Blocked(StartBlockReason::DependencyNotReady {
                dependency: upstream,
                observed: ServiceLifecycleState::Declared,
                required: ServiceLifecycleState::Running,
            })
        );

        let upstream_record = tracker.record_mut(upstream).expect("upstream");
        upstream_record
            .apply_control(ControlRequest::new(upstream, ControlRequestKind::Start))
            .expect("start");
        upstream_record
            .apply_event(crate::state::LifecycleEvent::new(
                ServiceInstanceId::new(upstream, InstanceGeneration(1), ProcessId(10), DomainId(1)),
                LifecycleEventKind::Ready,
            ))
            .expect("ready");

        assert_eq!(
            graph
                .evaluate_start_readiness(downstream, &tracker, None)
                .expect("eval"),
            StartReadiness::Ready
        );
    }

    #[test]
    fn unknown_dependency_is_rejected_at_registration() {
        let mut graph = DependencyGraph::<4>::new();
        graph.declare(ServiceId(1)).expect("declare");
        let err = graph
            .set_dependencies(single_dependency(
                ServiceId(1),
                ServiceId(99),
                ServiceLifecycleState::Running,
            ))
            .unwrap_err();
        assert_eq!(
            err,
            DependencyGraphError::UnknownDependency {
                service: ServiceId(1),
                depends_on: ServiceId(99),
            }
        );
    }

    #[test]
    fn self_dependency_is_rejected() {
        let mut graph = DependencyGraph::<4>::new();
        let service = ServiceId(3);
        graph.declare(service).expect("declare");
        let err = graph
            .set_dependencies(single_dependency(
                service,
                service,
                ServiceLifecycleState::Running,
            ))
            .unwrap_err();
        assert_eq!(err, DependencyGraphError::SelfDependency { service });
    }

    #[test]
    fn cycle_is_rejected_deterministically() {
        let mut graph = DependencyGraph::<4>::new();
        let a = ServiceId(10);
        let b = ServiceId(11);
        graph.declare(a).expect("declare a");
        graph.declare(b).expect("declare b");
        graph
            .set_dependencies(single_dependency(a, b, ServiceLifecycleState::Running))
            .expect("a depends on b");
        let err = graph
            .set_dependencies(single_dependency(b, a, ServiceLifecycleState::Running))
            .unwrap_err();
        assert_eq!(err, DependencyGraphError::CycleDetected { service: b });
    }

    #[test]
    fn failed_dependency_blocks_with_explicit_reason() {
        let mut graph = DependencyGraph::<4>::new();
        let upstream = ServiceId(5);
        let downstream = ServiceId(6);
        graph.declare(upstream).expect("declare");
        graph.declare(downstream).expect("declare");
        graph
            .set_dependencies(single_dependency(
                downstream,
                upstream,
                ServiceLifecycleState::Running,
            ))
            .expect("deps");

        let mut tracker = ServiceLifecycleTracker::<4>::new();
        tracker.declare(upstream).expect("declare");
        tracker.declare(downstream).expect("declare");
        let upstream_record = tracker.record_mut(upstream).expect("upstream");
        upstream_record
            .apply_control(ControlRequest::new(upstream, ControlRequestKind::Start))
            .expect("start");
        upstream_record
            .apply_event(crate::state::LifecycleEvent::new(
                ServiceInstanceId::new(upstream, InstanceGeneration(1), ProcessId(50), DomainId(1)),
                LifecycleEventKind::Faulted,
            ))
            .expect("fault");

        assert_eq!(
            graph
                .evaluate_start_readiness(downstream, &tracker, None)
                .expect("eval"),
            StartReadiness::Blocked(StartBlockReason::DependencyFailed {
                dependency: upstream,
                observed: ServiceLifecycleState::Faulted,
            })
        );
    }

    #[test]
    fn unhealthy_dependency_blocks_even_when_running() {
        let mut graph = DependencyGraph::<4>::new();
        let upstream = ServiceId(20);
        let downstream = ServiceId(21);
        graph.declare(upstream).expect("declare");
        graph.declare(downstream).expect("declare");
        graph
            .set_dependencies(single_dependency(
                downstream,
                upstream,
                ServiceLifecycleState::Running,
            ))
            .expect("deps");

        let mut tracker = running_tracker(upstream);
        tracker.declare(downstream).expect("declare downstream");

        let mut health = DependencyHealthSnapshot::<4>::empty();
        health
            .set(upstream, HealthStatus::Unhealthy)
            .expect("health");

        assert_eq!(
            graph
                .evaluate_start_readiness(downstream, &tracker, Some(&health))
                .expect("eval"),
            StartReadiness::Blocked(StartBlockReason::DependencyUnhealthy {
                dependency: upstream,
                observed: HealthStatus::Unhealthy,
            })
        );
    }

    #[test]
    fn dependency_identity_uses_logical_service_id_not_pid() {
        let mut graph = DependencyGraph::<4>::new();
        let upstream = ServiceId(30);
        let downstream = ServiceId(31);
        graph.declare(upstream).expect("declare");
        graph.declare(downstream).expect("declare");
        graph
            .set_dependencies(single_dependency(
                downstream,
                upstream,
                ServiceLifecycleState::Running,
            ))
            .expect("deps");
        let mut tracker = running_tracker(upstream);
        tracker.declare(downstream).expect("declare");
        let active = tracker.record(upstream).expect("upstream").active_instance;
        assert!(active.is_some());
        assert_ne!(active.unwrap().pid.0, upstream.0 as u64);
        assert_eq!(
            graph
                .evaluate_start_readiness(downstream, &tracker, None)
                .expect("eval"),
            StartReadiness::Ready
        );
    }

    #[test]
    fn health_report_generation_does_not_affect_dependency_keys() {
        let report = HealthReport::new(ServiceId(40), InstanceGeneration(9), HealthStatus::Ok);
        assert_eq!(report.service, ServiceId(40));
        let _ = report.generation;
    }
}
