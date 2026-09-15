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
    feature = "m3-entry-self-test"
))]
pub(crate) mod m3_entry;
#[cfg(feature = "m3-ipc-self-test")]
pub(crate) mod m3_ipc;
#[cfg(feature = "m3-resources-self-test")]
pub(crate) mod m3_resources;
#[cfg(feature = "m3-syscall-self-test")]
pub(crate) mod m3_syscall;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
use crate::mm::PAGE_SIZE;

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
pub(super) const USER_TEST_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
const USER_TEST_DATA_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
pub(super) const USER_TEST_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-ipc-self-test"
))]
const USER_TEST_PROCESS_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 2);
