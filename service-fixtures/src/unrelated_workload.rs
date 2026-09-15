//! Continuing workload fixture that survives an injected crash-service fault.

use crate::config::UnrelatedWorkloadLaunchConfig;
use clean_slate_service_lifecycle::ServiceId;

/// Logical identity for the unrelated progress workload (not the crash target).
pub const UNRELATED_WORKLOAD_SERVICE_ID: ServiceId = ServiceId(0x0000_4101);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnrelatedWorkloadFixture {
    progress: u32,
    token: u64,
}

impl UnrelatedWorkloadFixture {
    pub const fn from_launch(config: UnrelatedWorkloadLaunchConfig) -> Self {
        Self {
            progress: 0,
            token: config.progress_token,
        }
    }

    pub const fn progress(&self) -> u32 {
        self.progress
    }

    pub const fn token(&self) -> u64 {
        self.token
    }

    /// One scheduler heartbeat / voluntary userspace exit.
    pub fn tick(&mut self) -> u32 {
        self.progress = self.progress.saturating_add(1);
        self.progress
    }
}
