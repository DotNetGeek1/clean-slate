//! Syscall 18 (display) wiring: the read-only subops (#111 D1).
//!
//! `MAP_SCANOUT` and `PRESENT` return `ENOSYS` until #195's kernel-owned scanout buffers land (W7,
//! R2); `BIND_WAKE` returns `ENOSYS` until the work-set signal API lands (W2). Every status is the
//! frozen `docs/GRAPHICS.md` mapping; checks run in its order: length/pointer → capability → backend.

use core::ptr;

use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSYS};
use clean_slate_capability::{CapabilityError, HolderId};
use clean_slate_graphics::display::{
    DisplayError, DISPLAY_ABI_VERSION, DISPLAY_MODE_INFO_BYTES, DISPLAY_SUBOP_BIND_WAKE,
    DISPLAY_SUBOP_FIND_HANDLE, DISPLAY_SUBOP_MAP_SCANOUT, DISPLAY_SUBOP_PRESENT,
    DISPLAY_SUBOP_PRESENT_STATUS, DISPLAY_SUBOP_QUERY_MODE, PRESENT_STATUS_BYTES,
};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::display::{authorize_display_query, find_display_handle};
use crate::device::display::engine::DisplayState;
use crate::device::display::{with_active_display, PRIMARY_OUTPUT_INDEX};
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::syscall::current_syscall_caller_pid;

fn current_holder() -> Result<HolderId, u64> {
    current_syscall_caller_pid()
        .map(HolderId)
        .map_err(|_| SYSCALL_EACCES)
}

fn backend_present() -> bool {
    with_active_display(|display| display.is_some())
}

pub(crate) fn handle_syscall_display(frame: &mut SyscallContext) {
    frame.rax = match frame.rdi {
        DISPLAY_SUBOP_FIND_HANDLE => find_handle(
            frame.rdx,
            current_holder,
            |holder| find_display_handle(holder, PRIMARY_OUTPUT_INDEX),
            backend_present,
        ),
        DISPLAY_SUBOP_QUERY_MODE => {
            copy_out::<DISPLAY_MODE_INFO_BYTES>(frame.rsi, frame.rdx, frame.r10, |state| {
                state.mode_info().encode()
            })
        }
        DISPLAY_SUBOP_PRESENT_STATUS => {
            copy_out::<PRESENT_STATUS_BYTES>(frame.rsi, frame.rdx, frame.r10, |state| {
                state.status().encode()
            })
        }
        other => unrouted_subop(other),
    };
}

fn unrouted_subop(subop: u64) -> u64 {
    match subop {
        DISPLAY_SUBOP_MAP_SCANOUT | DISPLAY_SUBOP_PRESENT | DISPLAY_SUBOP_BIND_WAKE => {
            SYSCALL_ENOSYS
        }
        _ => SYSCALL_EINVAL,
    }
}

fn copy_out<const N: usize>(
    raw_handle: u64,
    out_ptr: u64,
    out_len: u64,
    encode: impl FnOnce(&DisplayState) -> [u8; N],
) -> u64 {
    let bytes = query(
        out_len,
        || validate_user_writable_pointer_range(out_ptr, out_len).is_ok(),
        current_holder,
        |holder| authorize_display_query(holder, raw_handle, PRIMARY_OUTPUT_INDEX).map(|_| ()),
        || with_active_display(|display| display.map(|display| encode(display.state()))),
    );
    match bytes {
        Ok(bytes) => {
            unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, N) };
            0
        }
        Err(status) => status,
    }
}

/// `FIND_HANDLE`: version → caller → a live `Display` capability → backend.
fn find_handle(
    version: u64,
    holder: impl FnOnce() -> Result<HolderId, u64>,
    lookup: impl FnOnce(HolderId) -> Option<u64>,
    backend_present: impl FnOnce() -> bool,
) -> u64 {
    if version != DISPLAY_ABI_VERSION {
        return SYSCALL_EINVAL;
    }
    let holder = match holder() {
        Ok(holder) => holder,
        Err(status) => return status,
    };
    let Some(handle) = lookup(holder) else {
        return SYSCALL_EACCES;
    };
    if !backend_present() {
        return DisplayError::ModeUnavailable.status();
    }
    handle
}

/// `QUERY_MODE` / `PRESENT_STATUS`: exact length, then pointer → caller → capability → backend.
/// The pointer range is only walked once `out_len` is the exact struct length. `snapshot` returns
/// `None` when boot found no backend. A poisoned backend still answers.
fn query<const N: usize>(
    out_len: u64,
    pointer_valid: impl FnOnce() -> bool,
    holder: impl FnOnce() -> Result<HolderId, u64>,
    authorize: impl FnOnce(HolderId) -> Result<(), CapabilityError>,
    snapshot: impl FnOnce() -> Option<[u8; N]>,
) -> Result<[u8; N], u64> {
    if out_len != N as u64 || !pointer_valid() {
        return Err(SYSCALL_EINVAL);
    }
    let holder = holder()?;
    authorize(holder).map_err(CapabilityError::syscall_status)?;
    snapshot().ok_or(DisplayError::ModeUnavailable.status())
}

#[cfg(test)]
mod tests {
    use clean_slate_capability::syscall_abi::{
        SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSYS, SYSCALL_ESTALE,
    };
    use clean_slate_capability::{
        CapabilityTable, HolderId, Provenance, ResourceClass, ResourceRef, Rights,
    };
    use clean_slate_graphics::abi_status::STATUS_ENODEV;
    use clean_slate_graphics::display::{
        DisplayModeInfo, PresentState, PresentStatus, DISPLAY_MODE_INFO_BYTES, PRESENT_STATUS_BYTES,
    };
    use clean_slate_graphics::REFERENCE_MODE;

    use super::{find_handle, query, unrouted_subop};
    use crate::capability::display::{authorize_display_query_in, find_display_handle_in};
    use crate::device::display::engine::DisplayState;

    const CALLER: HolderId = HolderId(11);

    fn table_with(rights: Option<Rights>) -> (CapabilityTable<8>, u64) {
        let mut table = CapabilityTable::<8>::new();
        let handle = rights.map_or(u64::MAX, |rights| {
            table
                .grant(
                    CALLER,
                    ResourceRef::display(0),
                    rights,
                    Provenance::root(CALLER),
                )
                .expect("grant")
                .encode()
        });
        (table, handle)
    }

    fn caller() -> Result<HolderId, u64> {
        Ok(CALLER)
    }

    fn no_caller() -> Result<HolderId, u64> {
        Err(SYSCALL_EACCES)
    }

    fn unreachable_caller() -> Result<HolderId, u64> {
        panic!("caller resolved before the length/version check")
    }

    fn find(table: &CapabilityTable<8>, version: u64, backend: bool) -> u64 {
        find_handle(
            version,
            caller,
            |holder| find_display_handle_in(table, holder, 0),
            || backend,
        )
    }

    fn query_mode(
        table: &CapabilityTable<8>,
        handle: u64,
        out_len: u64,
        state: Option<&DisplayState>,
    ) -> Result<[u8; DISPLAY_MODE_INFO_BYTES], u64> {
        query(
            out_len,
            || true,
            caller,
            |holder| authorize_display_query_in(table, holder, handle, 0).map(|_| ()),
            || state.map(|state| state.mode_info().encode()),
        )
    }

    #[test]
    fn find_handle_checks_version_then_capability_then_backend() {
        let (table, handle) = table_with(Some(Rights::INSPECT));
        assert_eq!(
            find_handle(2, unreachable_caller, |_| unreachable!(), || unreachable!()),
            SYSCALL_EINVAL
        );
        assert_eq!(
            find_handle(1, no_caller, |_| unreachable!(), || unreachable!()),
            SYSCALL_EACCES
        );
        let (empty, _) = table_with(None);
        assert_eq!(
            find(&empty, 1, false),
            SYSCALL_EACCES,
            "capability before backend"
        );
        assert_eq!(find(&table, 1, false), STATUS_ENODEV);
        assert_eq!(find(&table, 1, true), handle);
    }

    #[test]
    fn query_rejects_wrong_length_or_pointer_before_anything_else() {
        for out_len in [
            0,
            DISPLAY_MODE_INFO_BYTES as u64 - 1,
            DISPLAY_MODE_INFO_BYTES as u64 + 1,
            u64::MAX,
        ] {
            let result = query::<DISPLAY_MODE_INFO_BYTES>(
                out_len,
                || unreachable!("pointer walked before the length check"),
                unreachable_caller,
                |_| unreachable!(),
                || unreachable!(),
            );
            assert_eq!(result, Err(SYSCALL_EINVAL), "len {out_len}");
        }
        let result = query::<PRESENT_STATUS_BYTES>(
            PRESENT_STATUS_BYTES as u64,
            || false,
            unreachable_caller,
            |_| unreachable!(),
            || unreachable!(),
        );
        assert_eq!(result, Err(SYSCALL_EINVAL));
    }

    #[test]
    fn query_maps_capability_failures_before_the_backend_check() {
        let state = DisplayState::new(REFERENCE_MODE).expect("reference mode");
        let (table, handle) = table_with(Some(Rights::INSPECT));
        let len = DISPLAY_MODE_INFO_BYTES as u64;

        let result = query::<DISPLAY_MODE_INFO_BYTES>(
            len,
            || true,
            no_caller,
            |_| unreachable!(),
            || unreachable!(),
        );
        assert_eq!(result, Err(SYSCALL_EACCES), "no trusted caller");
        assert_eq!(query_mode(&table, u64::MAX, len, None), Err(SYSCALL_EINVAL));

        let mut other = CapabilityTable::<8>::new();
        let network = other
            .grant(
                CALLER,
                ResourceRef::network(3, 1),
                Rights::valid_for(ResourceClass::Network),
                Provenance::root(CALLER),
            )
            .expect("grant")
            .encode();
        assert_eq!(
            query_mode(&other, network, len, None),
            Err(SYSCALL_EACCES),
            "wrong class"
        );

        let mut revoked = CapabilityTable::<8>::new();
        let stale = revoked
            .grant(
                CALLER,
                ResourceRef::display(0),
                Rights::INSPECT,
                Provenance::root(CALLER),
            )
            .expect("grant");
        revoked.revoke(stale).expect("revoke");
        assert_eq!(
            query_mode(&revoked, stale.encode(), len, None),
            Err(SYSCALL_ESTALE)
        );

        assert_eq!(query_mode(&table, handle, len, None), Err(STATUS_ENODEV));
        let bytes = query_mode(&table, handle, len, Some(&state)).expect("mode");
        assert_eq!(DisplayModeInfo::decode(&bytes), Ok(state.mode_info()));
    }

    #[test]
    fn query_mode_and_status_answer_with_either_right() {
        let state = DisplayState::new(REFERENCE_MODE).expect("reference mode");
        for rights in [Rights::INSPECT, Rights::DISPLAY_PRESENT] {
            let (table, handle) = table_with(Some(rights));
            let mode = query_mode(&table, handle, DISPLAY_MODE_INFO_BYTES as u64, Some(&state))
                .expect("mode");
            let info = DisplayModeInfo::decode(&mode).expect("decode");
            assert_eq!((info.output.index(), info.output.backend_epoch()), (0, 1));
            assert_eq!(info.mode, REFERENCE_MODE);

            let status = query::<PRESENT_STATUS_BYTES>(
                PRESENT_STATUS_BYTES as u64,
                || true,
                caller,
                |holder| authorize_display_query_in(&table, holder, handle, 0).map(|_| ()),
                || Some(state.status().encode()),
            )
            .expect("status");
            let status = PresentStatus::decode(&status).expect("decode");
            assert_eq!(status.state, PresentState::Idle);
            assert_eq!(status.output, info.output);
        }
    }

    #[test]
    fn gated_subops_are_enosys_and_unknown_subops_einval() {
        for subop in [3, 4, 6] {
            assert_eq!(unrouted_subop(subop), SYSCALL_ENOSYS, "subop {subop}");
        }
        for subop in [0, 7, u64::MAX] {
            assert_eq!(unrouted_subop(subop), SYSCALL_EINVAL, "subop {subop}");
        }
    }
}
