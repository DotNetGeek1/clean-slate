//! Host-side crash-service fixture harness (lifecycle protocol, no restart policy).

use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, DomainId, HealthReport, HealthStatus, InstanceGeneration,
    LifecycleEvent, LifecycleEventKind, ProcessId, ServiceInstanceId, ServiceLifecycleState,
    ServiceLifecycleTracker,
};

use crate::config::{CrashServiceLaunchConfig, CrashServiceMode};
use crate::CRASH_SERVICE_ID;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashServiceFixtureRole {
    Primary,
    Replacement,
}

/// Scripted supervisor adapter for host tests — applies #35 transitions only.
pub struct CrashServiceFixtureHarness {
    tracker: ServiceLifecycleTracker<4>,
    inject_requested: bool,
    last_health: Option<HealthReport>,
    cached_state: ServiceLifecycleState,
    cached_generation: InstanceGeneration,
}

impl CrashServiceFixtureHarness {
    pub fn new() -> Self {
        let mut tracker = ServiceLifecycleTracker::new();
        tracker.declare(CRASH_SERVICE_ID).expect("declare once");
        Self {
            tracker,
            inject_requested: false,
            last_health: None,
            cached_state: ServiceLifecycleState::Declared,
            cached_generation: InstanceGeneration(0),
        }
    }

    fn refresh_cache(&mut self) {
        let record = self
            .tracker
            .record_mut(CRASH_SERVICE_ID)
            .expect("crash service declared");
        self.cached_state = record.state;
        self.cached_generation = record.authoritative_generation;
    }

    pub fn request_inject_fault(&mut self) {
        self.inject_requested = true;
    }

    pub fn start_launch(
        &mut self,
        config: &CrashServiceLaunchConfig,
        pid: u64,
        role: CrashServiceFixtureRole,
    ) -> ServiceInstanceId {
        let record = self.tracker.record_mut(CRASH_SERVICE_ID).expect("record");
        if role == CrashServiceFixtureRole::Primary {
            record
                .apply_control(ControlRequest::new(
                    CRASH_SERVICE_ID,
                    ControlRequestKind::Start,
                ))
                .expect("primary start");
        } else {
            record
                .apply_control(ControlRequest::new(
                    CRASH_SERVICE_ID,
                    ControlRequestKind::Restart,
                ))
                .expect("restart request");
            record
                .apply_control(ControlRequest::new(
                    CRASH_SERVICE_ID,
                    ControlRequestKind::Start,
                ))
                .expect("replacement start");
        }
        assert_eq!(record.authoritative_generation, config.generation);
        self.refresh_cache();
        ServiceInstanceId::new(
            config.service,
            config.generation,
            ProcessId(pid),
            DomainId(pid),
        )
    }

    pub fn on_instance_spawned(&mut self, instance: ServiceInstanceId) {
        self.tracker
            .record_mut(CRASH_SERVICE_ID)
            .expect("record")
            .apply_event(LifecycleEvent::new(
                instance,
                LifecycleEventKind::InstanceSpawned,
            ))
            .expect("spawned");
        self.refresh_cache();
    }

    pub fn on_ready(&mut self, instance: ServiceInstanceId) {
        self.tracker
            .record_mut(CRASH_SERVICE_ID)
            .expect("record")
            .apply_event(LifecycleEvent::new(instance, LifecycleEventKind::Ready))
            .expect("ready");
        self.refresh_cache();
    }

    pub fn report_health(&mut self, generation: InstanceGeneration) -> HealthReport {
        let report = HealthReport::new(CRASH_SERVICE_ID, generation, HealthStatus::Ok);
        self.last_health = Some(report);
        report
    }

    pub fn last_health(&self) -> Option<HealthReport> {
        self.last_health
    }

    pub fn should_inject_fault(&self, config: &CrashServiceLaunchConfig, heartbeat: u32) -> bool {
        if self.inject_requested {
            return true;
        }
        match config.mode {
            CrashServiceMode::HealthyUntilInject => false,
            CrashServiceMode::CrashAtHeartbeat => heartbeat >= config.crash_at_heartbeat,
        }
    }

    pub fn on_faulted(&mut self, instance: ServiceInstanceId) {
        self.tracker
            .record_mut(CRASH_SERVICE_ID)
            .expect("record")
            .apply_event(LifecycleEvent::new(instance, LifecycleEventKind::Faulted))
            .expect("faulted");
        self.inject_requested = false;
        self.refresh_cache();
    }

    pub fn state(&self) -> ServiceLifecycleState {
        self.cached_state
    }

    pub fn generation(&self) -> InstanceGeneration {
        self.cached_generation
    }
}

impl Default for CrashServiceFixtureHarness {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CrashServiceLaunchConfig;

    #[test]
    fn harness_models_crash_and_replacement_without_resume() {
        let mut harness = CrashServiceFixtureHarness::new();
        let probe = 0x4000_0000_1000;
        let gen1 = CrashServiceLaunchConfig::crash_after_heartbeats(
            InstanceGeneration(1),
            1,
            0x1111,
            probe,
        );
        let inst1 = harness.start_launch(&gen1, 10, CrashServiceFixtureRole::Primary);
        harness.on_instance_spawned(inst1);
        harness.on_ready(inst1);
        assert_eq!(harness.state(), ServiceLifecycleState::Running);
        assert!(harness.should_inject_fault(&gen1, 1));
        harness.on_faulted(inst1);
        assert_eq!(harness.state(), ServiceLifecycleState::Faulted);

        let gen2 = CrashServiceLaunchConfig::healthy_instance(InstanceGeneration(2), 0x2222, probe);
        let inst2 = harness.start_launch(&gen2, 11, CrashServiceFixtureRole::Replacement);
        assert_ne!(inst1.pid, inst2.pid);
        assert_eq!(inst2.generation, InstanceGeneration(2));
        harness.on_ready(inst2);
        assert_eq!(harness.state(), ServiceLifecycleState::Running);
        let health = harness.report_health(InstanceGeneration(2));
        assert_eq!(health.status, HealthStatus::Ok);
    }
}
