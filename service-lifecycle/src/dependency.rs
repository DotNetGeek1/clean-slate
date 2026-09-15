//! Dependency metadata envelope (evaluation lives in `dependency_graph`).

use crate::identity::ServiceId;
use crate::state::ServiceLifecycleState;

pub const MAX_INLINE_DEPENDENCIES: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyEdge {
    pub depends_on: ServiceId,
    /// Minimum lifecycle state required before the dependent may start.
    pub required_state: ServiceLifecycleState,
}

/// Inline dependency list for a service (bounded; larger graphs use future storage).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DependencyMetadata {
    pub service: ServiceId,
    pub edges: [DependencyEdge; MAX_INLINE_DEPENDENCIES],
    pub edge_count: u8,
}

impl DependencyMetadata {
    pub const fn empty(service: ServiceId) -> Self {
        Self {
            service,
            edges: [DependencyEdge {
                depends_on: ServiceId(0),
                required_state: ServiceLifecycleState::Declared,
            }; MAX_INLINE_DEPENDENCIES],
            edge_count: 0,
        }
    }

    pub fn push_edge(&mut self, edge: DependencyEdge) -> bool {
        if self.edge_count as usize >= MAX_INLINE_DEPENDENCIES {
            return false;
        }
        self.edges[self.edge_count as usize] = edge;
        self.edge_count += 1;
        true
    }
}
