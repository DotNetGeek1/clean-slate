//! Readiness contract for #103 poll/select (implemented by resource backends).

use super::open_description::OpenDescriptionId;

/// Edge-triggered readiness bits for an open description.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub hangup: bool,
    pub error: bool,
}

/// Backends implement readiness for their open descriptions.
pub(crate) trait ReadinessSource {
    fn readiness(&self, id: OpenDescriptionId) -> Readiness;
}
