//! Syscall 18 (display) wiring (#111).
//!
//! Every status is the frozen `docs/GRAPHICS.md` mapping; checks run in its order: argument
//! length/pointer → caller → capability → backend → presenter → the subop's own validation.

use core::ptr;

use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL};
use clean_slate_capability::{CapabilityError, HolderId};
use clean_slate_graphics::display::{
    DisplayError, PresentRequest, ScanoutMapping, DISPLAY_ABI_VERSION, DISPLAY_MODE_INFO_BYTES,
    DISPLAY_SUBOP_BIND_WAKE, DISPLAY_SUBOP_FIND_HANDLE, DISPLAY_SUBOP_MAP_SCANOUT,
    DISPLAY_SUBOP_PRESENT, DISPLAY_SUBOP_PRESENT_STATUS, DISPLAY_SUBOP_QUERY_MODE,
    PRESENT_REQUEST_BYTES, PRESENT_STATUS_BYTES, SCANOUT_MAPPING_BYTES,
};
use clean_slate_native_abi::SharedBufferAccess;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::display::{
    authorize_display_present, authorize_display_query, find_display_handle,
};
use crate::device::display::engine::DisplayState;
use crate::device::display::{with_active_display, ActiveDisplay, PRIMARY_OUTPUT_INDEX};
use crate::mm::shared_buffer::kernel_owned::map_kernel_owned_into;
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::sched::work_set;
use crate::syscall::{current_syscall_caller_pid, service_lifecycle_syscall_allocator_mut};
use crate::time::monotonic_ns;

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
        DISPLAY_SUBOP_MAP_SCANOUT => handle_map_scanout(frame.rsi, frame.rdx, frame.r10, frame.r8),
        DISPLAY_SUBOP_PRESENT => handle_present(frame.rsi, frame.rdx, frame.r10),
        DISPLAY_SUBOP_BIND_WAKE => handle_bind_wake(frame.rsi, frame.rdx, frame.r10),
        _ => SYSCALL_EINVAL,
    };
}

fn authorize_present(holder: HolderId, raw_handle: u64) -> Result<(), CapabilityError> {
    authorize_display_present(holder, raw_handle, PRIMARY_OUTPUT_INDEX).map(|_| ())
}

fn handle_map_scanout(raw_handle: u64, buffer_index: u64, out_ptr: u64, out_len: u64) -> u64 {
    let index = u8::try_from(buffer_index).unwrap_or(u8::MAX);
    let mapping = map_scanout(
        out_len,
        || validate_user_writable_pointer_range(out_ptr, out_len).is_ok(),
        current_holder,
        |holder| authorize_present(holder, raw_handle),
        |holder| {
            with_active_display(|display| {
                display.map(|display| map_into_caller(display, holder, index))
            })
        },
    );
    match mapping {
        Ok(bytes) => {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), out_ptr as *mut u8, SCANOUT_MAPPING_BYTES)
            };
            0
        }
        Err(status) => status,
    }
}

fn map_into_caller(
    display: &mut ActiveDisplay,
    holder: HolderId,
    index: u8,
) -> Result<ScanoutMapping, u64> {
    let frames = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or(DisplayError::ModeUnavailable.status())?;
    display.map_scanout(holder, index, frames, |id, frames| {
        map_kernel_owned_into(id, holder.0, SharedBufferAccess::ReadWrite, frames)
    })
}

fn handle_present(raw_handle: u64, in_ptr: u64, in_len: u64) -> u64 {
    present(
        in_len,
        || {
            validate_user_pointer_range(in_ptr, in_len).ok()?;
            let mut bytes = [0u8; PRESENT_REQUEST_BYTES];
            unsafe {
                ptr::copy_nonoverlapping(in_ptr as *const u8, bytes.as_mut_ptr(), bytes.len())
            };
            Some(bytes)
        },
        current_holder,
        |holder| authorize_present(holder, raw_handle),
        |holder, request| {
            with_active_display(|display| {
                display.map(|display| display.present_scanout(holder, request, monotonic_ns()))
            })
        },
    )
}

fn handle_bind_wake(raw_handle: u64, raw_work_set: u64, raw_bit: u64) -> u64 {
    bind_wake(
        raw_bit,
        current_holder,
        |holder| authorize_present(holder, raw_handle),
        |holder, bit| {
            with_active_display(|display| {
                display.map(|display| {
                    display.bind_wake(holder, || {
                        work_set::bind(holder, raw_work_set)
                            .map(|binding| (binding, bit))
                            .map_err(work_set::WorkSetError::status)
                    })
                })
            })
        },
    )
}

/// `MAP_SCANOUT`: exact length and pointer → caller → `DISPLAY_PRESENT` → backend → presenter →
/// index (`EBADF`) → allocate, pin and bind on first use → map read-write into the caller.
fn map_scanout(
    out_len: u64,
    pointer_valid: impl FnOnce() -> bool,
    holder: impl FnOnce() -> Result<HolderId, u64>,
    authorize: impl FnOnce(HolderId) -> Result<(), CapabilityError>,
    map: impl FnOnce(HolderId) -> Option<Result<ScanoutMapping, u64>>,
) -> Result<[u8; SCANOUT_MAPPING_BYTES], u64> {
    if out_len != SCANOUT_MAPPING_BYTES as u64 || !pointer_valid() {
        return Err(SYSCALL_EINVAL);
    }
    let holder = holder()?;
    authorize(holder).map_err(CapabilityError::syscall_status)?;
    let mapping = map(holder).ok_or(DisplayError::ModeUnavailable.status())??;
    Ok(mapping.encode())
}

/// `PRESENT`: exact length and readable pointer → caller → `DISPLAY_PRESENT` → decode → the
/// engine's backend → presenter → validate → mapped → in-flight order.
fn present(
    in_len: u64,
    read: impl FnOnce() -> Option<[u8; PRESENT_REQUEST_BYTES]>,
    holder: impl FnOnce() -> Result<HolderId, u64>,
    authorize: impl FnOnce(HolderId) -> Result<(), CapabilityError>,
    submit: impl FnOnce(HolderId, &PresentRequest) -> Option<Result<u64, DisplayError>>,
) -> u64 {
    let status = (|| {
        if in_len != PRESENT_REQUEST_BYTES as u64 {
            return Err(SYSCALL_EINVAL);
        }
        let bytes = read().ok_or(SYSCALL_EINVAL)?;
        let holder = holder()?;
        authorize(holder).map_err(CapabilityError::syscall_status)?;
        let request = PresentRequest::decode(&bytes).map_err(|_| SYSCALL_EINVAL)?;
        submit(holder, &request)
            .ok_or(DisplayError::ModeUnavailable.status())?
            .map_err(DisplayError::status)
    })();
    status.unwrap_or_else(|status| status)
}

/// `BIND_WAKE`: bit 0..=31 → caller → `DISPLAY_PRESENT` → backend → presenter → work-set handle.
fn bind_wake(
    raw_bit: u64,
    holder: impl FnOnce() -> Result<HolderId, u64>,
    authorize: impl FnOnce(HolderId) -> Result<(), CapabilityError>,
    bind: impl FnOnce(HolderId, u32) -> Option<Result<(), u64>>,
) -> u64 {
    let status = (|| {
        let bit = work_set::bind_bit(raw_bit).map_err(work_set::WorkSetError::status)?;
        let holder = holder()?;
        authorize(holder).map_err(CapabilityError::syscall_status)?;
        bind(holder, bit).ok_or(DisplayError::ModeUnavailable.status())?
    })();
    match status {
        Ok(()) => 0,
        Err(status) => status,
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
    use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ESTALE};
    use clean_slate_capability::{
        CapabilityError, CapabilityTable, HolderId, Provenance, ResourceClass, ResourceRef, Rights,
    };
    use clean_slate_graphics::abi_status::STATUS_ENODEV;
    use clean_slate_graphics::display::{
        DisplayError, DisplayModeInfo, PresentRequest, PresentState, PresentStatus, ScanoutMapping,
        DISPLAY_MODE_INFO_BYTES, PRESENT_REQUEST_BYTES, PRESENT_STATUS_BYTES,
        SCANOUT_MAPPING_BYTES,
    };
    use clean_slate_graphics::{
        BufferRect, OutputId, MAX_PRESENT_DAMAGE_RECTS, REFERENCE_FRAME_BYTES, REFERENCE_MODE,
    };

    use super::{bind_wake, find_handle, map_scanout, present, query};
    use crate::capability::display::{
        authorize_display_present_in, authorize_display_query_in, find_display_handle_in,
    };
    use crate::device::display::engine::DisplayState;

    type AuthResult = Result<(), CapabilityError>;

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

    fn present_auth(
        table: &CapabilityTable<8>,
        handle: u64,
    ) -> impl FnOnce(HolderId) -> AuthResult + '_ {
        move |holder| authorize_display_present_in(table, holder, handle, 0).map(|_| ())
    }

    fn valid_request() -> [u8; PRESENT_REQUEST_BYTES] {
        let damage = BufferRect {
            x: 0,
            y: 0,
            width: 1,
            height: 1,
        };
        PresentRequest {
            output: OutputId::new(0, 1).expect("output"),
            buffer_index: 0,
            damage_count: 1,
            rects: [damage; MAX_PRESENT_DAMAGE_RECTS],
        }
        .encode()
    }

    #[test]
    fn map_scanout_checks_length_caller_capability_then_backend() {
        let (table, handle) = table_with(Some(Rights::DISPLAY_PRESENT));
        let (inspect, inspect_handle) = table_with(Some(Rights::INSPECT));
        let len = SCANOUT_MAPPING_BYTES as u64;
        for out_len in [0, len - 1, len + 1] {
            assert_eq!(
                map_scanout(
                    out_len,
                    || unreachable!(),
                    unreachable_caller,
                    |_| unreachable!(),
                    |_| unreachable!()
                ),
                Err(SYSCALL_EINVAL)
            );
        }
        assert_eq!(
            map_scanout(
                len,
                || false,
                unreachable_caller,
                |_| unreachable!(),
                |_| unreachable!()
            ),
            Err(SYSCALL_EINVAL)
        );
        assert_eq!(
            map_scanout(
                len,
                || true,
                no_caller,
                |_| unreachable!(),
                |_| unreachable!()
            ),
            Err(SYSCALL_EACCES)
        );
        assert_eq!(
            map_scanout(
                len,
                || true,
                caller,
                present_auth(&inspect, inspect_handle),
                |_| unreachable!()
            ),
            Err(SYSCALL_EACCES),
            "INSPECT cannot map scanout"
        );
        assert_eq!(
            map_scanout(len, || true, caller, present_auth(&table, handle), |_| None),
            Err(STATUS_ENODEV)
        );
        assert_eq!(
            map_scanout(
                len,
                || true,
                caller,
                present_auth(&table, handle),
                |_| Some(Err(DisplayError::NotPresenter.status()))
            ),
            Err(SYSCALL_EACCES)
        );
        let mapping = ScanoutMapping {
            output: OutputId::new(0, 1).expect("output"),
            buffer_index: 1,
            user_va: 0x4000_0000,
            byte_len: REFERENCE_FRAME_BYTES as u64,
            stride_bytes: REFERENCE_MODE.stride_bytes,
        };
        let bytes = map_scanout(
            len,
            || true,
            caller,
            present_auth(&table, handle),
            |holder| {
                assert_eq!(holder, CALLER);
                Some(Ok(mapping))
            },
        )
        .expect("mapped");
        assert_eq!(ScanoutMapping::decode(&bytes), Ok(mapping));
    }

    #[test]
    fn present_checks_length_pointer_capability_decode_then_backend() {
        let (table, handle) = table_with(Some(Rights::DISPLAY_PRESENT));
        let (inspect, inspect_handle) = table_with(Some(Rights::INSPECT));
        let len = PRESENT_REQUEST_BYTES as u64;
        assert_eq!(
            present(
                len - 1,
                || unreachable!(),
                unreachable_caller,
                |_| unreachable!(),
                |_, _| unreachable!()
            ),
            SYSCALL_EINVAL
        );
        assert_eq!(
            present(
                len,
                || None,
                unreachable_caller,
                |_| unreachable!(),
                |_, _| unreachable!()
            ),
            SYSCALL_EINVAL
        );
        let mut malformed = valid_request();
        malformed[6] = 1;
        assert_eq!(
            present(
                len,
                || Some(malformed),
                caller,
                present_auth(&inspect, inspect_handle),
                |_, _| unreachable!()
            ),
            SYSCALL_EACCES,
            "capability before decode"
        );
        assert_eq!(
            present(
                len,
                || Some(malformed),
                caller,
                present_auth(&table, handle),
                |_, _| unreachable!()
            ),
            SYSCALL_EINVAL
        );
        assert_eq!(
            present(
                len,
                || Some(valid_request()),
                caller,
                present_auth(&table, handle),
                |_, _| None
            ),
            STATUS_ENODEV
        );
        assert_eq!(
            present(
                len,
                || Some(valid_request()),
                caller,
                present_auth(&table, handle),
                |_, _| Some(Err(DisplayError::BufferBusy))
            ),
            DisplayError::BufferBusy.status()
        );
        assert_eq!(
            present(
                len,
                || Some(valid_request()),
                caller,
                present_auth(&table, handle),
                |holder, request| {
                    assert_eq!(
                        (holder, request.buffer_index, request.damage_count),
                        (CALLER, 0, 1)
                    );
                    Some(Ok(7))
                }
            ),
            7
        );
    }

    #[test]
    fn bind_wake_checks_bit_caller_capability_then_backend() {
        let (table, handle) = table_with(Some(Rights::DISPLAY_PRESENT));
        let (inspect, inspect_handle) = table_with(Some(Rights::INSPECT));
        assert_eq!(
            bind_wake(
                32,
                unreachable_caller,
                |_| unreachable!(),
                |_, _| unreachable!()
            ),
            SYSCALL_EINVAL
        );
        assert_eq!(
            bind_wake(
                3,
                caller,
                present_auth(&inspect, inspect_handle),
                |_, _| unreachable!()
            ),
            SYSCALL_EACCES
        );
        assert_eq!(
            bind_wake(3, caller, present_auth(&table, handle), |_, _| None),
            STATUS_ENODEV
        );
        assert_eq!(
            bind_wake(3, caller, present_auth(&table, handle), |_, bit| {
                assert_eq!(bit, 3);
                Some(Err(SYSCALL_ESTALE))
            }),
            SYSCALL_ESTALE
        );
        assert_eq!(
            bind_wake(31, caller, present_auth(&table, handle), |_, _| Some(
                Ok(())
            )),
            0
        );
    }
}
