//! Milestone self-tests. Each submodule is compiled only under its feature
//! (except `m2_timer`, which owns an unconditionally referenced symbol) and
//! is reached from the three production hook sites (`boot::run_inner`,
//! `interrupt::clean_slate_interrupt_dispatch`/`handle_exception` and the
//! `syscall` handlers). Items shared by more than one milestone live here.

#[cfg(feature = "m1-self-test")]
pub(crate) mod m1_memory;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m3-entry-self-test"
))]
pub(crate) mod m2_double_fault;
// Always compiled: it owns the `no_mangle` `clean_slate_timer_self_test_task`
// symbol that `arch::x86_64::asm` references unconditionally.
pub(crate) mod m2_timer;
#[cfg(feature = "m3-address-space-self-test")]
pub(crate) mod m3_address_space;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test",
    feature = "m7-net-caps-self-test"
))]
pub(crate) mod m3_entry;
#[cfg(feature = "m3-ipc-self-test")]
pub(crate) mod m3_ipc;
#[cfg(feature = "m3-resources-self-test")]
pub(crate) mod m3_resources;
#[cfg(feature = "m3-syscall-self-test")]
pub(crate) mod m3_syscall;
#[cfg(feature = "m4-crash-service-self-test")]
pub(crate) mod m4_crash_service;
#[cfg(feature = "m4-recovery-self-test")]
pub(crate) mod m4_recovery;
#[cfg(feature = "m4-service-lifecycle-self-test")]
pub(crate) mod m4_service_lifecycle;
#[cfg(feature = "m4-supervisor-self-test")]
pub(crate) mod m4_supervisor;
#[cfg(feature = "m5-block-self-test")]
pub(crate) mod m5_block;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test",
    feature = "m7-net-caps-self-test"
))]
pub(crate) mod m5_storage;
#[cfg(feature = "m6-audit-self-test")]
pub(crate) mod m6_audit;
#[cfg(feature = "m6-capabilities-self-test")]
pub(crate) mod m6_capabilities;
#[cfg(feature = "m6-delegation-self-test")]
pub(crate) mod m6_delegation;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test",
    feature = "m7-net-caps-self-test"
))]
pub(crate) mod m6_fixture;
#[cfg(feature = "m6-fixture-smoke-self-test")]
pub(crate) mod m6_fixture_smoke;
#[cfg(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test"))]
pub(crate) mod m6_object;
#[cfg(feature = "m6-process-control-self-test")]
pub(crate) mod m6_process_control;
#[cfg(feature = "m6-revocation-self-test")]
pub(crate) mod m6_revocation;
#[cfg(feature = "m7-dns-self-test")]
pub(crate) mod m7_dns;
#[cfg(feature = "m7-net-caps-self-test")]
pub(crate) mod m7_net_caps;
#[cfg(feature = "m7-net-device-self-test")]
pub(crate) mod m7_net_device;
#[cfg(any(feature = "m7-net-service-self-test", feature = "m7-network-self-test"))]
pub(crate) mod m7_net_service;
#[cfg(any(feature = "m7-tls-self-test", feature = "m7-tls-fail-closed-self-test"))]
pub(crate) mod m7_tls;
#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) mod m8_linux_dispatch;
#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) mod m8_linux_hello;
#[cfg(feature = "m8-linux-image-self-test")]
pub(crate) mod m8_linux_image;
#[cfg(feature = "m9-block-wake-self-test")]
pub(crate) mod m9_block_wake;
#[cfg(feature = "m9-fd-core-self-test")]
pub(crate) mod m9_fd_core;
#[cfg(feature = "m9-linux-exec-self-test")]
pub(crate) mod m9_linux_exec;
#[cfg(feature = "m9-low-va-self-test")]
pub(crate) mod m9_low_va;
#[cfg(feature = "m9-rootfs-self-test")]
pub(crate) mod m9_rootfs;
#[cfg(feature = "m9-linux-fs-self-test")]
pub(crate) mod m9_linux_fs;
#[cfg(feature = "m9-syscall-fail-closed-self-test")]
pub(crate) mod m9_syscall_fail_closed;
#[cfg(any(
    feature = "m3-syscall-self-test",
    feature = "m9-syscall-fail-closed-self-test",
    feature = "m9-block-wake-self-test",
    feature = "m9-fd-core-self-test"
))]
pub(crate) mod userspace_process;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test",
    feature = "m8-linux-dispatch-self-test",
    feature = "m8-linux-hello-self-test",
    feature = "m9-syscall-fail-closed-self-test",
    feature = "m9-block-wake-self-test"
))]
use crate::mm::PAGE_SIZE;

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test",
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m8-linux-dispatch-self-test",
    feature = "m8-linux-hello-self-test",
    feature = "m9-syscall-fail-closed-self-test",
    feature = "m9-linux-exec-self-test",
    feature = "m9-fd-core-self-test"
))]
pub(super) const USER_TEST_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m4-service-lifecycle-self-test",
    feature = "m3-entry-self-test",
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test"
))]
pub(super) const USER_TEST_DATA_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m3-entry-self-test",
    feature = "m8-linux-hello-self-test",
    feature = "m9-linux-exec-self-test"
))]
pub(super) const USER_TEST_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m3-ipc-self-test",
    feature = "m4-service-lifecycle-self-test",
    feature = "m4-supervisor-self-test",
    feature = "m4-recovery-self-test",
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m8-linux-dispatch-self-test",
    feature = "m9-syscall-fail-closed-self-test",
    feature = "m9-block-wake-self-test",
    feature = "m9-fd-core-self-test"
))]
pub(super) const USER_TEST_PROCESS_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 2);
#[cfg(feature = "m4-recovery-self-test")]
pub(super) const RECOVERY_SUPERVISOR_MAX_CODE_PAGES: u64 = 12;
#[cfg(feature = "m4-recovery-self-test")]
pub(super) const RECOVERY_SUPERVISOR_BOOTSTRAP_ADDRESS: u64 =
    USER_TEST_CODE_ADDRESS + RECOVERY_SUPERVISOR_MAX_CODE_PAGES * PAGE_SIZE;
#[cfg(feature = "m4-recovery-self-test")]
pub(super) const RECOVERY_SUPERVISOR_STACK_ADDRESS: u64 =
    RECOVERY_SUPERVISOR_BOOTSTRAP_ADDRESS + PAGE_SIZE;
#[cfg(feature = "m4-recovery-self-test")]
pub(super) const RECOVERY_SUPERVISOR_STACK_PAGES: u64 = 4;
