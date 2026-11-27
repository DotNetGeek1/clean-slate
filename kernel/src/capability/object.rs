//! M6.3 persistent object/file capability surface (kernel side of SYSCALL_NR_CAP_OBJECT).

use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ENOSYS, SYSCALL_NR_CAP_OBJECT,
};
use clean_slate_capability::{
    CapabilityError, CapabilityHandle, CapabilityState, HolderId, ResourceClass, ResourceRef,
    Rights,
};
use clean_slate_native_abi::status::STATUS_ETIMEDOUT;
use clean_slate_service_fixtures::{
    object_status_to_native, ObjectServiceRequest, ObjectSubmitAt, OBJECT_MAX_PAYLOAD_BYTES,
    OBJECT_OP_COMMIT, OBJECT_OP_DELETE, OBJECT_OP_READ, OBJECT_OP_READ_AT, OBJECT_OP_TRUNCATE,
    OBJECT_OP_WRITE, OBJECT_OP_WRITE_AT, OBJECT_POLL_NO_DEADLINE, OBJECT_REQUEST_SLOTS,
    OBJECT_SERVICE_REQUEST_BYTES, OBJECT_SERVICE_ROLE_ID, OBJECT_STATUS_PENDING,
    OBJECT_SUBMIT_AT_BYTES, OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, OBJECT_SUBOP_POLL,
    OBJECT_SUBOP_SERVICE_COMPLETE, OBJECT_SUBOP_SERVICE_NEXT, OBJECT_SUBOP_SUBMIT,
    OBJECT_SUBOP_SUBMIT_AT,
};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::user_access::{copy_from_user, copy_to_user};
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::sched::wait::{
    block_current_thread_with_resume, wake_all_registered, BlockedResume, Deadline, WaitKey,
};
use crate::sync::global_cell::GlobalCell;
use crate::time::{monotonic_ns, tsc_hz};

use super::{
    authorize_current, authorize_current_class, capability_space_mut, current_holder, grant_root,
    with_capability_space,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotState {
    Free,
    Pending,
    InService,
    Done,
}

#[derive(Clone, Copy, Debug)]
struct ObjectRequestSlot {
    state: SlotState,
    client: HolderId,
    request_id: u64,
    op: u64,
    object_id: u64,
    /// The authorizing capability's object epoch, passed to the storage service.
    epoch: u64,
    /// Offset of an offset op (`READ_AT`, `WRITE_AT`), or `TRUNCATE`'s new length.
    offset: u64,
    len: usize,
    payload: [u8; OBJECT_MAX_PAYLOAD_BYTES],
    status: u64,
    /// Submitted through `OBJECT_SUBOP_SUBMIT_AT`: a failure polls as a native status
    /// ([`object_status_to_native`]), never as a small number a read length could be.
    native_statuses: bool,
}

impl ObjectRequestSlot {
    const fn free() -> Self {
        Self {
            state: SlotState::Free,
            client: HolderId(0),
            request_id: 0,
            op: 0,
            object_id: 0,
            epoch: 0,
            offset: 0,
            len: 0,
            payload: [0; OBJECT_MAX_PAYLOAD_BYTES],
            status: 0,
            native_statuses: false,
        }
    }
}

pub(crate) struct ObjectRequestQueue {
    slots: [ObjectRequestSlot; OBJECT_REQUEST_SLOTS],
    next_request_id: u64,
}

impl ObjectRequestQueue {
    pub const fn new() -> Self {
        Self {
            slots: [ObjectRequestSlot::free(); OBJECT_REQUEST_SLOTS],
            next_request_id: 1,
        }
    }

    fn alloc_request_id(&mut self) -> u64 {
        let id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        id
    }

    pub fn submit(
        &mut self,
        client: HolderId,
        op: u64,
        object_id: u64,
        epoch: u64,
        payload: &[u8],
    ) -> Result<u64, SyscallQueueError> {
        self.submit_at(client, op, object_id, epoch, 0, payload)
    }

    /// [`submit`](Self::submit) with an offset. A `READ_AT` asks for `payload.len()` bytes;
    /// its payload's bytes are not read.
    pub fn submit_at(
        &mut self,
        client: HolderId,
        op: u64,
        object_id: u64,
        epoch: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<u64, SyscallQueueError> {
        let slot_index = self
            .slots
            .iter()
            .position(|slot| slot.state == SlotState::Free)
            .ok_or(SyscallQueueError::QueueFull)?;
        let request_id = self.alloc_request_id();
        let len = payload.len();
        let mut slot = ObjectRequestSlot::free();
        slot.state = SlotState::Pending;
        slot.client = client;
        slot.request_id = request_id;
        slot.op = op;
        slot.object_id = object_id;
        slot.epoch = epoch;
        slot.offset = offset;
        slot.len = len;
        slot.payload[..len].copy_from_slice(payload);
        self.slots[slot_index] = slot;
        wake_all_registered(OBJECT_SERVICE_WORK_KEY);
        Ok(request_id)
    }

    /// [`submit_at`](Self::submit_at) for `OBJECT_SUBOP_SUBMIT_AT`: a failure polls as a
    /// native status.
    pub fn submit_native_at(
        &mut self,
        client: HolderId,
        op: u64,
        object_id: u64,
        epoch: u64,
        offset: u64,
        payload: &[u8],
    ) -> Result<u64, SyscallQueueError> {
        let request_id = self.submit_at(client, op, object_id, epoch, offset, payload)?;
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.request_id == request_id)
        {
            slot.native_statuses = true;
        }
        Ok(request_id)
    }

    pub fn poll(
        &mut self,
        client: HolderId,
        request_id: u64,
        out: &mut [u8],
    ) -> Result<u64, SyscallQueueError> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.request_id == request_id)
            .ok_or(SyscallQueueError::InvalidRequest)?;
        let slot = &self.slots[index];
        if slot.client != client {
            return Err(SyscallQueueError::UnauthorizedHolder);
        }
        match slot.state {
            SlotState::Pending | SlotState::InService => Ok(OBJECT_STATUS_PENDING),
            SlotState::Done => {
                let status = slot.status;
                if status != 0 {
                    // Error completions still consume the client's poll; free so ENOSPC cannot stick.
                    let status = if slot.native_statuses {
                        object_status_to_native(status)
                    } else {
                        status
                    };
                    self.slots[index] = ObjectRequestSlot::free();
                    return Err(SyscallQueueError::CompletionStatus(status));
                }
                let len = slot.len;
                if out.len() < len {
                    // Match success-path behavior: undersized buffer is EINVAL without freeing
                    // (client can poll again with a large enough buffer).
                    return Err(SyscallQueueError::BufferTooSmall);
                }
                out[..len].copy_from_slice(&slot.payload[..len]);
                self.slots[index] = ObjectRequestSlot::free();
                Ok(len as u64)
            }
            SlotState::Free => Err(SyscallQueueError::InvalidRequest),
        }
    }

    pub fn service_next(&mut self) -> Option<ObjectServiceRequest> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.state == SlotState::Pending)?;
        self.slots[index].state = SlotState::InService;
        let slot = &self.slots[index];
        let mut request =
            ObjectServiceRequest::new(slot.request_id, slot.op, slot.object_id, slot.len as u64);
        request.epoch = slot.epoch;
        request.offset = slot.offset;
        request.payload[..slot.len].copy_from_slice(&slot.payload[..slot.len]);
        Some(request)
    }

    /// Frees every queue slot owned by `holder` (any state).
    pub fn reclaim_for_holder(&mut self, holder: HolderId) -> usize {
        let mut reclaimed = 0usize;
        for slot in &mut self.slots {
            if slot.state != SlotState::Free && slot.client == holder {
                *slot = ObjectRequestSlot::free();
                reclaimed += 1;
            }
        }
        reclaimed
    }

    /// Returns in-flight work to the pending queue after the object service holder exits.
    pub fn requeue_in_service(&mut self) -> usize {
        let mut requeued = 0usize;
        for slot in &mut self.slots {
            if slot.state == SlotState::InService {
                slot.state = SlotState::Pending;
                requeued += 1;
            }
        }
        if requeued > 0 {
            wake_all_registered(OBJECT_SERVICE_WORK_KEY);
        }
        requeued
    }

    pub fn service_complete(
        &mut self,
        request_id: u64,
        status: u64,
        payload: &[u8],
    ) -> Result<(), SyscallQueueError> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.request_id == request_id && slot.state == SlotState::InService)
            .ok_or(SyscallQueueError::InvalidRequest)?;
        let len = payload.len();
        if len > OBJECT_MAX_PAYLOAD_BYTES {
            return Err(SyscallQueueError::PayloadTooLarge);
        }
        let slot = &mut self.slots[index];
        slot.state = SlotState::Done;
        slot.status = status;
        slot.len = len;
        slot.payload[..len].copy_from_slice(payload);
        wake_all_registered(object_request_wait_key(request_id));
        Ok(())
    }
}

/// Wait key the client of `request_id` blocks on until the object service completes
/// it (native `OBJECT_SUBOP_POLL` and the Linux `/tmp` projection).
///
/// Both object queue keys are woken with `wake_all_registered`: every consumer checks the
/// queue and registers its waiter within one syscall, with interrupts masked on the single
/// CPU, so a wake with no waiter has nothing to deliver. A recorded pending wake would never
/// be consumed once the client's poll finds the request done, and request ids are never
/// reused, so each completion would leak a slot of the bounded pending-wake table.
pub(crate) fn object_request_wait_key(request_id: u64) -> WaitKey {
    WaitKey(0x46_u64 << 56 | (request_id & 0x00FF_FFFF_FFFF_FFFF))
}

/// The right an object op needs. Deleting, truncating or committing an object needs
/// `WRITE`, like changing its bytes.
fn required_rights(op: u64) -> Option<Rights> {
    match op {
        OBJECT_OP_READ | OBJECT_OP_READ_AT => Some(Rights::READ),
        OBJECT_OP_WRITE | OBJECT_OP_DELETE | OBJECT_OP_WRITE_AT | OBJECT_OP_TRUNCATE
        | OBJECT_OP_COMMIT => Some(Rights::WRITE),
        _ => None,
    }
}

/// Ops a native client may submit through `OBJECT_SUBOP_SUBMIT`: the whole-object ops. The
/// offset ops and the commit go through `OBJECT_SUBOP_SUBMIT_AT` (#312), whose descriptor
/// carries the offset that `SUBMIT` has no register for; [`ObjectSubmitAt::decode`] decides
/// which ops it takes.
fn native_submit_op(op: u64) -> bool {
    matches!(op, OBJECT_OP_READ | OBJECT_OP_WRITE | OBJECT_OP_DELETE)
}

/// Wait key the storage service blocks on in `OBJECT_SUBOP_SERVICE_NEXT` while no
/// request is `Pending`; woken by every submit and by a service-exit requeue.
const OBJECT_SERVICE_WORK_KEY: WaitKey = WaitKey(0x47_u64 << 56);

/// Kernel-internal authority check for a holder acting on an object without a raw
/// handle (Linux `/tmp` projection). Denials are logged like native submit denials.
#[cfg(clean_slate_linux_rootfs)]
pub(crate) fn authorize_holder_object_op(
    holder: HolderId,
    object_id: u64,
    op: u64,
) -> Result<(), SyscallQueueError> {
    let required = required_rights(op).ok_or(SyscallQueueError::InvalidRequest)?;
    if super::holder_has_resource_rights(holder, ResourceRef::object(object_id), required) {
        Ok(())
    } else {
        log_deny(holder, object_id, op, CapabilityError::UnauthorizedHolder);
        #[cfg(feature = "m9-userspace-self-test")]
        crate::selftest::m9_userspace::observe_object_denial(op != OBJECT_OP_READ);
        Err(SyscallQueueError::UnauthorizedHolder)
    }
}

#[cfg(clean_slate_linux_rootfs)]
pub(crate) fn object_queue_submit(
    client: HolderId,
    op: u64,
    object_id: u64,
    payload: &[u8],
) -> Result<u64, SyscallQueueError> {
    authorize_holder_object_op(client, object_id, op)?;
    // Holder grants to `/tmp` objects name the object id only, not an epoch.
    queue_mut().submit(
        client,
        op,
        object_id,
        clean_slate_service_fixtures::OBJECT_EPOCH_UNBOUND,
        payload,
    )
}

/// Submits `op` on `object_id` for `holder`, authorised by the holder's rights on
/// `authority_id` instead of on the object itself: the Linux `/home` projection's one
/// directory capability covers every file object in it (#304), since the per-holder
/// capability quota cannot hold one capability per file.
#[cfg(clean_slate_linux_rootfs)]
pub(crate) fn object_queue_submit_under(
    client: HolderId,
    authority_id: u64,
    op: u64,
    object_id: u64,
    offset: u64,
    payload: &[u8],
) -> Result<u64, SyscallQueueError> {
    authorize_holder_object_op(client, authority_id, op)?;
    queue_mut().submit_at(
        client,
        op,
        object_id,
        clean_slate_service_fixtures::OBJECT_EPOCH_UNBOUND,
        offset,
        payload,
    )
}

/// Object request slots not yet released by their client.
#[cfg(feature = "m9-userspace-self-test")]
pub(crate) fn object_queue_occupied_slots() -> usize {
    queue_mut()
        .slots
        .iter()
        .filter(|slot| slot.state != SlotState::Free)
        .count()
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
pub(crate) fn object_request_is_pending(request_id: u64) -> bool {
    queue_mut()
        .slots
        .iter()
        .any(|slot| slot.request_id == request_id && slot.state == SlotState::Pending)
}

#[cfg(clean_slate_linux_rootfs)]
pub(crate) fn object_queue_poll(
    client: HolderId,
    request_id: u64,
    out: &mut [u8],
) -> Result<u64, SyscallQueueError> {
    queue_mut().poll(client, request_id, out)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SyscallQueueError {
    QueueFull,
    InvalidRequest,
    UnauthorizedHolder,
    BufferTooSmall,
    PayloadTooLarge,
    CompletionStatus(u64),
}

impl SyscallQueueError {
    fn syscall_status(self) -> u64 {
        match self {
            Self::QueueFull => SYSCALL_ENOSPC,
            Self::UnauthorizedHolder => SYSCALL_EACCES,
            Self::InvalidRequest | Self::BufferTooSmall | Self::PayloadTooLarge => SYSCALL_EINVAL,
            Self::CompletionStatus(status) => status,
        }
    }
}

static OBJECT_REQUEST_QUEUE: GlobalCell<ObjectRequestQueue> =
    GlobalCell::new(ObjectRequestQueue::new());

fn queue_mut() -> &'static mut ObjectRequestQueue {
    unsafe { &mut *OBJECT_REQUEST_QUEUE.get() }
}

fn holder_holds_object_service_role(holder: HolderId) -> bool {
    let role = ResourceRef::object(OBJECT_SERVICE_ROLE_ID);
    with_capability_space(|table| {
        for slot in 0..table.capacity() {
            let record = table.record_at(slot);
            if record.state == CapabilityState::Live
                && record.holder == holder
                && record.resource == role
                && record.rights.contains(Rights::INSPECT)
            {
                return true;
            }
        }
        false
    })
}

fn rollback_installed_capability(handle: CapabilityHandle) {
    let table = unsafe { capability_space_mut() };
    let slot = usize::from(handle.slot);
    let record = table.record(handle);
    if table.revoke(handle).is_ok() {
        table.release_slot(slot);
        if let Ok(record) = record {
            super::audit::record_kernel_revoke(record.holder, record.resource, 1);
        }
    }
}

/// Requeues in-service object requests when the storage-service holder tears down.
pub(crate) fn recover_object_queue_for_service_holder_exit(holder: HolderId) {
    if !holder_holds_object_service_role(holder) {
        return;
    }
    let requeued = queue_mut().requeue_in_service();
    if requeued > 0 {
        kernel_log_fmt(format_args!(
            "[CAP ] object queue requeued in-service={requeued}\n",
        ));
    }
}

/// Drops all object request slots owned by a client holder that is tearing down.
pub(crate) fn reclaim_object_requests_for_holder(holder: HolderId) {
    let reclaimed = queue_mut().reclaim_for_holder(holder);
    if reclaimed > 0 {
        kernel_log_fmt(format_args!(
            "[CAP ] object queue reclaimed holder={} requests={reclaimed}\n",
            holder.0,
        ));
    }
}

fn op_name(op: u64) -> &'static str {
    match op {
        OBJECT_OP_READ => "read",
        OBJECT_OP_WRITE => "write",
        OBJECT_OP_DELETE => "delete",
        OBJECT_OP_READ_AT => "read-at",
        OBJECT_OP_WRITE_AT => "write-at",
        OBJECT_OP_TRUNCATE => "truncate",
        OBJECT_OP_COMMIT => "commit",
        _ => "unknown",
    }
}

fn deny_reason_name(error: CapabilityError) -> &'static str {
    match error {
        CapabilityError::InvalidHandle | CapabilityError::UnauthorizedHolder => "no-authority",
        other => other.error_name(),
    }
}

fn log_deny(holder: HolderId, object_id: u64, op: u64, error: CapabilityError) {
    kernel_log_fmt(format_args!(
        "[CAP ] deny holder={} object={} op={} reason={}\n",
        holder.0,
        object_id,
        op_name(op),
        deny_reason_name(error),
    ));
}

fn log_allowed(holder: HolderId, object_id: u64, op: u64) {
    kernel_log_fmt(format_args!(
        "[CAP ] object allowed holder={} object={} op={}\n",
        holder.0,
        object_id,
        op_name(op),
    ));
}

#[cfg_attr(
    not(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test")),
    allow(dead_code)
)] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
fn log_grant(holder: HolderId, object_id: u64, rights: Rights) {
    let mut names = super::RightsNameBuf {
        bytes: [0; 64],
        len: 0,
    };
    names.format_rights(rights);
    let rights_text = core::str::from_utf8(&names.bytes[..names.len]).unwrap_or("?");
    kernel_log_fmt(format_args!(
        "[CAP ] object grant holder={} object={} rights={}\n",
        holder.0, object_id, rights_text,
    ));
}

#[cfg_attr(
    not(any(
        feature = "m6-object-self-test",
        feature = "m6-capabilities-self-test",
        feature = "m9-linux-fs-self-test",
        clean_slate_linux_rootfs
    )),
    allow(dead_code)
)] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn grant_object_capability(
    holder: HolderId,
    object_id: u64,
    rights: Rights,
) -> Result<CapabilityHandle, CapabilityError> {
    let handle = grant_root(holder, ResourceRef::object(object_id), rights)?;
    log_grant(holder, object_id, rights);
    Ok(handle)
}

#[cfg_attr(
    not(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test")),
    allow(dead_code)
)] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn grant_object_service_role(
    holder: HolderId,
) -> Result<CapabilityHandle, CapabilityError> {
    let handle = grant_root(
        holder,
        ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
        Rights::INSPECT,
    )?;
    log_grant(holder, OBJECT_SERVICE_ROLE_ID, Rights::INSPECT);
    Ok(handle)
}

#[cfg_attr(
    not(any(
        clean_slate_userspace_selftest = "m6-object",
        feature = "m6-capabilities-self-test",
        test
    )),
    allow(dead_code)
)] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn register_pending_bootstrap_grant(
    holder: HolderId,
    object_id: u64,
    rights: Rights,
) -> Result<(), CapabilityError> {
    let handle = grant_object_capability(holder, object_id, rights)?;
    if super::bootstrap_grant::register_bootstrap_grant(holder, handle).is_err() {
        rollback_installed_capability(handle);
        return Err(CapabilityError::CapacityExhausted);
    }
    Ok(())
}

/// Authorizes `op` on `object_id` and returns the object epoch the capability is bound to
/// (its resource's `instance_generation`; 0 for an unbound capability).
fn authorize_object_op(raw_handle: u64, object_id: u64, op: u64) -> Result<u64, CapabilityError> {
    let holder = current_holder().map_err(|_| CapabilityError::UnauthorizedHolder)?;
    let required = required_rights(op).ok_or(CapabilityError::InvalidHandle)?;
    let record = authorize_current_class(raw_handle, ResourceClass::PersistentObject, required)?;
    if record.resource.id != object_id {
        return Err(CapabilityError::WrongResource);
    }
    log_allowed(holder, object_id, op);
    Ok(record.resource.instance_generation)
}

fn authorize_service_role(raw_handle: u64) -> Result<(), CapabilityError> {
    authorize_current(
        raw_handle,
        ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
        Rights::INSPECT,
    )?;
    Ok(())
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    match frame.rdi {
        OBJECT_SUBOP_SUBMIT => handle_submit(frame),
        OBJECT_SUBOP_SUBMIT_AT => handle_submit_at(frame),
        OBJECT_SUBOP_POLL => handle_poll(frame),
        OBJECT_SUBOP_SERVICE_NEXT => handle_service_next(frame),
        OBJECT_SUBOP_SERVICE_COMPLETE => handle_service_complete(frame),
        OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT => handle_claim_bootstrap_grant(frame),
        _ => frame.rax = SYSCALL_ENOSYS,
    }
}

fn handle_claim_bootstrap_grant(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    match super::bootstrap_grant::claim_bootstrap_grant(holder) {
        Some(handle) => frame.rax = handle.encode(),
        None => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_submit(frame: &mut SyscallContext) {
    let raw_handle = frame.rsi;
    let op = frame.rdx;
    let object_id = frame.r10;
    let len = match usize::try_from(frame.r9) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if len > OBJECT_MAX_PAYLOAD_BYTES || !native_submit_op(op) {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if len > 0 && validate_user_pointer_range(frame.r8, frame.r9).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let epoch = match authorize_object_op(raw_handle, object_id, op) {
        Ok(epoch) => epoch,
        Err(error) => {
            log_deny(holder, object_id, op, error);
            frame.rax = error.syscall_status();
            return;
        }
    };
    let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    if len > 0 && copy_from_user(&mut payload[..len], frame.r8).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    match queue_mut().submit(holder, op, object_id, epoch, &payload[..len]) {
        Ok(request_id) => frame.rax = request_id,
        Err(error) => frame.rax = error.syscall_status(),
    }
}

/// `OBJECT_SUBOP_SUBMIT_AT` (#312): a native holder's offset op or commit, under the same
/// rights and epoch rules as `SUBMIT`. The storage service applies the live-byte budget
/// (`NO_SPACE`) and the staging rules the Linux `/home` projection already uses.
fn handle_submit_at(frame: &mut SyscallContext) {
    let raw_handle = frame.rsi;
    if frame.r10 != OBJECT_SUBMIT_AT_BYTES as u64
        || validate_user_pointer_range(frame.rdx, frame.r10).is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut descriptor = [0u8; OBJECT_SUBMIT_AT_BYTES];
    if copy_from_user(&mut descriptor, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let Ok(submit) = ObjectSubmitAt::decode(&descriptor) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    let payload_len = submit.payload_len();
    if payload_len > 0 && validate_user_pointer_range(submit.data, submit.len).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let epoch = match authorize_object_op(raw_handle, submit.object_id, submit.op) {
        Ok(epoch) => epoch,
        Err(error) => {
            log_deny(holder, submit.object_id, submit.op, error);
            frame.rax = error.syscall_status();
            return;
        }
    };
    let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    if payload_len > 0 && copy_from_user(&mut payload[..payload_len], submit.data).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    match queue_mut().submit_native_at(
        holder,
        submit.op,
        submit.object_id,
        epoch,
        submit.offset,
        &payload[..queued_len(&submit)],
    ) {
        Ok(request_id) => frame.rax = request_id,
        Err(error) => frame.rax = error.syscall_status(),
    }
}

/// The request length queued for a decoded `SUBMIT_AT`: the bytes a `READ_AT` asks for or a
/// `WRITE_AT` carries, 0 for a truncate or a commit.
fn queued_len(submit: &ObjectSubmitAt) -> usize {
    match submit.op {
        OBJECT_OP_READ_AT | OBJECT_OP_WRITE_AT => submit.len as usize,
        _ => 0,
    }
}

fn handle_poll(frame: &mut SyscallContext) {
    let request_id = frame.rsi;
    let len = match usize::try_from(frame.rdx) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if len > 0 && validate_user_writable_pointer_range(frame.r10, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let deadline_ns = match decode_poll_deadline(frame.r8, tsc_hz().is_some()) {
        Ok(deadline_ns) => deadline_ns,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let mut scratch = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    let out = &mut scratch[..len.min(OBJECT_MAX_PAYLOAD_BYTES)];
    match queue_mut().poll(holder, request_id, out) {
        Ok(OBJECT_STATUS_PENDING) => {
            if deadline_passed(deadline_ns, monotonic_ns) {
                frame.rax = STATUS_ETIMEDOUT;
            } else {
                block_until_request_completes(frame, request_id, deadline_ns);
            }
        }
        Ok(written) => {
            let copied = &out[..(written as usize).min(out.len())];
            frame.rax = if copied.is_empty() || copy_to_user(frame.r10, copied).is_ok() {
                written
            } else {
                SYSCALL_EINVAL
            };
        }
        Err(error) => frame.rax = error.syscall_status(),
    }
}

/// `r8` of `OBJECT_SUBOP_POLL`. A deadline is only meaningful on a calibrated clock.
fn decode_poll_deadline(raw: u64, is_clock_calibrated: bool) -> Result<Option<u64>, u64> {
    if raw == OBJECT_POLL_NO_DEADLINE {
        return Ok(None);
    }
    if !is_clock_calibrated {
        return Err(SYSCALL_EINVAL);
    }
    Ok(Some(raw))
}

/// The deadline is compared, never added to, so a far-future value cannot wrap early.
fn deadline_passed(deadline_ns: Option<u64>, now_ns: impl FnOnce() -> u64) -> bool {
    deadline_ns.is_some_and(|deadline_ns| now_ns() >= deadline_ns)
}

/// A poll of a pending request blocks until `service_complete` wakes the request's
/// key or the caller's deadline passes (`ETIMEDOUT`; the request stays queued). A wake
/// restarts the syscall, which polls again with the caller's original arguments; the
/// deadline is absolute, so it survives the restart unchanged. Syscalls run with
/// interrupts masked, so the completion cannot slip in between the pending check and
/// the block.
fn block_until_request_completes(
    frame: &mut SyscallContext,
    request_id: u64,
    deadline_ns: Option<u64>,
) {
    match block_current_thread_with_resume(
        frame as *mut SyscallContext,
        object_request_wait_key(request_id),
        deadline_ns.map(Deadline::MonotonicNs),
        BlockedResume::RestartSyscall {
            nr: SYSCALL_NR_CAP_OBJECT,
            timeout_rax: STATUS_ETIMEDOUT,
        },
    ) {
        Ok(_) => handle_poll(frame),
        Err(message) => fatal_kernel_error(message),
    }
}

fn handle_service_next(frame: &mut SyscallContext) {
    if validate_user_writable_pointer_range(frame.rdx, OBJECT_SERVICE_REQUEST_BYTES as u64).is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    if let Err(error) = authorize_service_role(frame.rsi) {
        log_deny(holder, OBJECT_SERVICE_ROLE_ID, 0, error);
        frame.rax = error.syscall_status();
        return;
    }
    match queue_mut().service_next() {
        Some(request) => {
            frame.rax = match copy_to_user(frame.rdx, &request.encode()) {
                Ok(()) => 1,
                Err(_) => SYSCALL_EINVAL,
            };
        }
        None => block_until_service_work(frame),
    }
}

/// An empty queue blocks the storage service on [`OBJECT_SERVICE_WORK_KEY`] with no
/// deadline; the restarted syscall dequeues the request that woke it. Syscalls run
/// with interrupts masked, so a submit cannot slip in between the empty check and
/// the block.
fn block_until_service_work(frame: &mut SyscallContext) {
    match block_current_thread_with_resume(
        frame as *mut SyscallContext,
        OBJECT_SERVICE_WORK_KEY,
        None,
        BlockedResume::RestartSyscall {
            nr: SYSCALL_NR_CAP_OBJECT,
            timeout_rax: SYSCALL_EINVAL,
        },
    ) {
        Ok(_) => handle_service_next(frame),
        Err(message) => fatal_kernel_error(message),
    }
}

fn handle_service_complete(frame: &mut SyscallContext) {
    let request_id = frame.rdx;
    let status = frame.r10;
    let len = match usize::try_from(frame.r9) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if len > OBJECT_MAX_PAYLOAD_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if len > 0 && validate_user_pointer_range(frame.r8, frame.r9).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    if let Err(error) = authorize_service_role(frame.rsi) {
        log_deny(holder, OBJECT_SERVICE_ROLE_ID, 0, error);
        frame.rax = error.syscall_status();
        return;
    }
    let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    if len > 0 && copy_from_user(&mut payload[..len], frame.r8).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    match queue_mut().service_complete(request_id, status, &payload[..len]) {
        Ok(()) => frame.rax = 0,
        Err(error) => frame.rax = error.syscall_status(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::{CapabilityHandle, CapabilityTable, Provenance};
    use clean_slate_service_fixtures::{
        OBJECT_STATUS_NOT_FOUND, OBJECT_STATUS_STORE_ERROR, OBJECT_STATUS_TOO_LARGE,
    };

    fn grant_read(table: &mut CapabilityTable<8>, holder: HolderId, object_id: u64) -> u64 {
        table
            .grant(
                holder,
                ResourceRef::object(object_id),
                Rights::READ,
                Provenance::root(holder),
            )
            .expect("grant")
            .encode()
    }

    fn grant_write_read(table: &mut CapabilityTable<8>, holder: HolderId, object_id: u64) -> u64 {
        table
            .grant(
                holder,
                ResourceRef::object(object_id),
                Rights::READ.union(Rights::WRITE),
                Provenance::root(holder),
            )
            .expect("grant")
            .encode()
    }

    fn authorize_submit(
        table: &CapabilityTable<8>,
        holder: HolderId,
        handle: u64,
        object_id: u64,
        op: u64,
    ) -> Result<(), CapabilityError> {
        let required = required_rights(op).ok_or(CapabilityError::InvalidHandle)?;
        let decoded = CapabilityHandle::decode(handle)?;
        let record =
            table.authorize_class(holder, decoded, ResourceClass::PersistentObject, required)?;
        if record.resource.id != object_id {
            return Err(CapabilityError::WrongResource);
        }
        Ok(())
    }

    #[test]
    fn delete_needs_the_write_right() {
        let mut table = CapabilityTable::<8>::new();
        let client = HolderId(3);
        let read_only = grant_read(&mut table, client, 7);
        assert_eq!(
            authorize_submit(&table, client, read_only, 7, OBJECT_OP_DELETE),
            Err(CapabilityError::MissingRight)
        );
        let read_write = grant_write_read(&mut table, client, 8);
        assert!(authorize_submit(&table, client, read_write, 8, OBJECT_OP_DELETE).is_ok());
        assert_eq!(required_rights(OBJECT_OP_DELETE), Some(Rights::WRITE));
        assert_eq!(required_rights(99), None);
    }

    #[test]
    fn the_service_sees_the_capabilitys_epoch() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(3);
        queue
            .submit(client, OBJECT_OP_DELETE, 7, 0x42, &[])
            .unwrap();
        queue.submit(client, OBJECT_OP_READ, 8, 0, &[]).unwrap();
        let first = queue.service_next().unwrap();
        assert_eq!(
            (first.op, first.object_id, first.epoch),
            (OBJECT_OP_DELETE, 7, 0x42)
        );
        let second = queue.service_next().unwrap();
        assert_eq!((second.object_id, second.epoch), (8, 0));
    }

    #[test]
    fn the_service_sees_an_offset_ops_offset_and_length() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(3);
        queue
            .submit_at(client, OBJECT_OP_WRITE_AT, 7, 0, 0x2_d000, b"save")
            .unwrap();
        queue
            .submit_at(client, OBJECT_OP_READ_AT, 7, 0, 1024, &[0; 512])
            .unwrap();
        let write = queue.service_next().unwrap();
        assert_eq!(
            (write.op, write.offset, write.len, &write.payload[..4]),
            (OBJECT_OP_WRITE_AT, 0x2_d000, 4, &b"save"[..])
        );
        let read = queue.service_next().unwrap();
        assert_eq!(
            (read.op, read.offset, read.len),
            (OBJECT_OP_READ_AT, 1024, 512)
        );
    }

    #[test]
    fn offset_ops_need_the_same_rights_as_whole_object_ops() {
        assert_eq!(required_rights(OBJECT_OP_READ_AT), Some(Rights::READ));
        assert_eq!(required_rights(OBJECT_OP_WRITE_AT), Some(Rights::WRITE));
        assert_eq!(required_rights(OBJECT_OP_TRUNCATE), Some(Rights::WRITE));
        assert_eq!(required_rights(OBJECT_OP_COMMIT), Some(Rights::WRITE));
        assert!(native_submit_op(OBJECT_OP_WRITE));
        assert!(!native_submit_op(OBJECT_OP_WRITE_AT));
        assert!(!native_submit_op(OBJECT_OP_READ_AT));
        assert!(!native_submit_op(OBJECT_OP_TRUNCATE));
        assert!(!native_submit_op(OBJECT_OP_COMMIT));
    }

    fn decoded(op: u64, offset: u64, len: u64) -> ObjectSubmitAt {
        ObjectSubmitAt::decode(
            &ObjectSubmitAt {
                op,
                object_id: 7,
                offset,
                len,
                data: 0x4000_0000,
                ..Default::default()
            }
            .encode(),
        )
        .expect("decode")
    }

    #[test]
    fn native_offset_ops_need_their_rights() {
        let mut table = CapabilityTable::<8>::new();
        let client = HolderId(3);
        let read_only = grant_read(&mut table, client, 7);
        assert!(authorize_submit(&table, client, read_only, 7, OBJECT_OP_READ_AT).is_ok());
        for op in [OBJECT_OP_WRITE_AT, OBJECT_OP_TRUNCATE, OBJECT_OP_COMMIT] {
            assert_eq!(
                authorize_submit(&table, client, read_only, 7, op),
                Err(CapabilityError::MissingRight)
            );
        }
        let read_write = grant_write_read(&mut table, client, 8);
        for op in [
            OBJECT_OP_READ_AT,
            OBJECT_OP_WRITE_AT,
            OBJECT_OP_TRUNCATE,
            OBJECT_OP_COMMIT,
        ] {
            assert!(authorize_submit(&table, client, read_write, 8, op).is_ok());
            assert_eq!(
                authorize_submit(&table, client, read_write, 7, op),
                Err(CapabilityError::WrongResource)
            );
            assert_eq!(
                authorize_submit(&table, HolderId(4), read_write, 8, op),
                Err(CapabilityError::UnauthorizedHolder)
            );
        }
    }

    #[test]
    fn a_native_submit_at_queues_its_offset_length_and_epoch() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(3);
        for (submit, epoch) in [
            (decoded(OBJECT_OP_WRITE_AT, 0x8_0000, 4), 0x42),
            (decoded(OBJECT_OP_READ_AT, 0x8_0000, 512), 0x42),
            (decoded(OBJECT_OP_TRUNCATE, 0x10_0000, 0), 0),
            (decoded(OBJECT_OP_COMMIT, 0, 0), 0),
        ] {
            let payload = [0xAB; OBJECT_MAX_PAYLOAD_BYTES];
            queue
                .submit_native_at(
                    client,
                    submit.op,
                    submit.object_id,
                    epoch,
                    submit.offset,
                    &payload[..queued_len(&submit)],
                )
                .unwrap();
            let request = queue.service_next().unwrap();
            assert_eq!(
                (request.op, request.offset, request.len, request.epoch),
                (submit.op, submit.offset, queued_len(&submit) as u64, epoch)
            );
            queue.service_complete(request.request_id, 0, &[]).unwrap();
            assert_eq!(queue.poll(client, request.request_id, &mut []), Ok(0));
        }
        assert_eq!(decoded(OBJECT_OP_READ_AT, 0, 512).payload_len(), 0);
    }

    #[test]
    fn a_native_submit_at_failure_polls_as_a_status_not_a_length() {
        use clean_slate_native_abi::status::{STATUS_ENOENT, STATUS_ENOSPC, STATUS_ESTALE};
        use clean_slate_service_fixtures::{OBJECT_STATUS_NO_SPACE, OBJECT_STATUS_STALE};
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(3);
        for (status, native) in [
            (OBJECT_STATUS_NOT_FOUND, STATUS_ENOENT),
            (OBJECT_STATUS_NO_SPACE, STATUS_ENOSPC),
            (OBJECT_STATUS_STALE, STATUS_ESTALE),
        ] {
            let id = queue
                .submit_native_at(client, OBJECT_OP_WRITE_AT, 7, 0, 0, b"x")
                .unwrap();
            queue.service_next().unwrap();
            queue.service_complete(id, status, &[]).unwrap();
            assert_eq!(
                queue.poll(client, id, &mut []),
                Err(SyscallQueueError::CompletionStatus(native))
            );
        }
        // `SUBMIT`'s requests keep the raw object status.
        let id = queue.submit(client, OBJECT_OP_READ, 7, 0, &[]).unwrap();
        queue.service_next().unwrap();
        queue
            .service_complete(id, OBJECT_STATUS_NOT_FOUND, &[])
            .unwrap();
        assert_eq!(
            queue.poll(client, id, &mut []),
            Err(SyscallQueueError::CompletionStatus(OBJECT_STATUS_NOT_FOUND))
        );
        assert_eq!(decoded(OBJECT_OP_WRITE_AT, 0, 4).payload_len(), 4);
    }

    #[test]
    fn queue_allows_read_write_when_authorized() {
        let mut table = CapabilityTable::<8>::new();
        let client = HolderId(3);
        let handle = grant_write_read(&mut table, client, 7);
        assert!(authorize_submit(&table, client, handle, 7, OBJECT_OP_WRITE).is_ok());
        let mut queue = ObjectRequestQueue::new();
        assert_eq!(
            queue
                .submit(client, OBJECT_OP_WRITE, 7, 0, b"alpha-v1")
                .unwrap(),
            1
        );
    }

    #[test]
    fn read_only_cap_rejects_write_before_enqueue() {
        let mut table = CapabilityTable::<8>::new();
        let client = HolderId(4);
        let handle = grant_read(&mut table, client, 7);
        assert_eq!(
            authorize_submit(&table, client, handle, 7, OBJECT_OP_WRITE),
            Err(CapabilityError::MissingRight)
        );
        let queue = ObjectRequestQueue::new();
        assert!(queue.slots.iter().all(|slot| slot.state == SlotState::Free));
    }

    #[test]
    fn poll_rejects_wrong_holder() {
        let mut queue = ObjectRequestQueue::new();
        let owner = HolderId(1);
        let other = HolderId(2);
        let request_id = queue.submit(owner, OBJECT_OP_READ, 7, 0, &[]).unwrap();
        let mut out = [0u8; 8];
        assert_eq!(
            queue.poll(other, request_id, &mut out),
            Err(SyscallQueueError::UnauthorizedHolder)
        );
    }

    #[test]
    fn wrong_object_id_rejected() {
        let mut table = CapabilityTable::<8>::new();
        let client = HolderId(5);
        let handle = grant_read(&mut table, client, 7);
        assert_eq!(
            authorize_submit(&table, client, handle, 9, OBJECT_OP_READ),
            Err(CapabilityError::WrongResource)
        );
    }

    #[test]
    fn stale_handle_rejected_queue_unchanged() {
        let mut table = CapabilityTable::<8>::new();
        let client = HolderId(6);
        let handle = grant_read(&mut table, client, 7);
        table.revoke_holder(client);
        assert_eq!(
            authorize_submit(&table, client, handle, 7, OBJECT_OP_READ),
            Err(CapabilityError::StaleHandle)
        );
        let queue = ObjectRequestQueue::new();
        assert!(queue.slots.iter().all(|slot| slot.state == SlotState::Free));
    }

    #[test]
    fn queue_full_returns_enospc_status() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(7);
        for _ in 0..OBJECT_REQUEST_SLOTS {
            queue.submit(client, OBJECT_OP_READ, 1, 0, &[]).unwrap();
        }
        assert_eq!(
            queue.submit(client, OBJECT_OP_READ, 1, 0, &[]),
            Err(SyscallQueueError::QueueFull)
        );
        assert_eq!(
            SyscallQueueError::QueueFull.syscall_status(),
            SYSCALL_ENOSPC
        );
    }

    #[test]
    fn service_role_old_holder_rejected_after_restart() {
        let mut table = CapabilityTable::<8>::new();
        let old_holder = HolderId(10);
        let new_holder = HolderId(11);
        let role = table
            .grant(
                old_holder,
                ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
                Rights::INSPECT,
                Provenance::root(old_holder),
            )
            .expect("grant");
        let raw = role.encode();
        table.revoke_holder(old_holder);
        let new_role = table
            .grant(
                new_holder,
                ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
                Rights::INSPECT,
                Provenance::root(new_holder),
            )
            .expect("grant");
        assert!(table
            .authorize(
                new_holder,
                new_role,
                ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
                Rights::INSPECT,
            )
            .is_ok());
        assert_eq!(
            table.authorize(
                new_holder,
                role,
                ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
                Rights::INSPECT,
            ),
            Err(CapabilityError::StaleHandle)
        );
        // The old instance's handle is stale for everyone, including the old holder:
        // the slot generation was bumped on release, so it can never re-authorize.
        let stale = CapabilityHandle::decode(raw).expect("decode stale role");
        assert_eq!(
            table.authorize(
                old_holder,
                stale,
                ResourceRef::object(OBJECT_SERVICE_ROLE_ID),
                Rights::INSPECT,
            ),
            Err(CapabilityError::StaleHandle)
        );
    }

    #[test]
    fn object_handle_does_not_authorize_block_device() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(12);
        let handle = grant_read(&mut table, holder, 7);
        let decoded = CapabilityHandle::decode(handle).unwrap();
        assert_eq!(
            table.authorize_class(holder, decoded, ResourceClass::BlockDevice, Rights::READ),
            Err(CapabilityError::WrongResource)
        );
    }

    fn complete_next_with_status(queue: &mut ObjectRequestQueue, status: u64) -> u64 {
        let request = queue.service_next().expect("pending request");
        queue
            .service_complete(request.request_id, status, &[])
            .expect("complete");
        request.request_id
    }

    #[test]
    fn poll_frees_slot_on_error_completion_and_allows_resubmit() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(30);
        let error_statuses = [
            OBJECT_STATUS_NOT_FOUND,
            OBJECT_STATUS_STORE_ERROR,
            OBJECT_STATUS_TOO_LARGE,
        ];
        let mut request_ids = [0u64; OBJECT_REQUEST_SLOTS];
        for index in 0..OBJECT_REQUEST_SLOTS {
            request_ids[index] = queue.submit(client, OBJECT_OP_READ, 1, 0, &[]).unwrap();
            let status = error_statuses[index % error_statuses.len()];
            assert_eq!(
                complete_next_with_status(&mut queue, status),
                request_ids[index]
            );
        }
        assert_eq!(
            queue.submit(client, OBJECT_OP_READ, 1, 0, &[]),
            Err(SyscallQueueError::QueueFull)
        );
        let mut out = [0u8; 8];
        for (index, request_id) in request_ids.iter().enumerate() {
            let status = error_statuses[index % error_statuses.len()];
            assert_eq!(
                queue.poll(client, *request_id, &mut out),
                Err(SyscallQueueError::CompletionStatus(status))
            );
        }
        for _ in 0..OBJECT_REQUEST_SLOTS {
            queue.submit(client, OBJECT_OP_READ, 2, 0, &[]).unwrap();
        }
    }

    #[test]
    fn poll_after_consumed_error_completion_returns_invalid_request() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(31);
        let request_id = queue.submit(client, OBJECT_OP_READ, 1, 0, &[]).unwrap();
        complete_next_with_status(&mut queue, OBJECT_STATUS_NOT_FOUND);
        let mut out = [0u8; 8];
        assert_eq!(
            queue.poll(client, request_id, &mut out),
            Err(SyscallQueueError::CompletionStatus(OBJECT_STATUS_NOT_FOUND))
        );
        assert_eq!(
            queue.poll(client, request_id, &mut out),
            Err(SyscallQueueError::InvalidRequest)
        );
    }

    #[test]
    fn holder_exit_reclaims_pending_in_service_and_done_slots() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(20);
        for _ in 0..OBJECT_REQUEST_SLOTS {
            queue.submit(client, OBJECT_OP_READ, 1, 0, &[]).unwrap();
        }
        queue.service_next().expect("pending request");
        let second = queue.service_next().expect("second pending");
        queue
            .service_complete(second.request_id, 0, b"done")
            .unwrap();
        assert_eq!(queue.reclaim_for_holder(client), OBJECT_REQUEST_SLOTS);
        for _ in 0..OBJECT_REQUEST_SLOTS {
            queue.submit(client, OBJECT_OP_READ, 2, 0, &[]).unwrap();
        }
    }

    #[test]
    fn service_complete_fails_after_holder_reclaim() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(21);
        let request_id = queue.submit(client, OBJECT_OP_READ, 1, 0, &[]).unwrap();
        queue.service_next().expect("dequeue");
        assert_eq!(queue.reclaim_for_holder(client), 1);
        assert_eq!(
            queue.service_complete(request_id, 0, &[]),
            Err(SyscallQueueError::InvalidRequest)
        );
    }

    #[test]
    fn service_holder_exit_requeues_in_service_requests() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(22);
        queue
            .submit(client, OBJECT_OP_WRITE, 7, 0, b"payload")
            .unwrap();
        let first = queue.service_next().expect("first dequeue");
        assert_eq!(queue.requeue_in_service(), 1);
        let second = queue.service_next().expect("requeued dequeue");
        assert_eq!(first.request_id, second.request_id);
    }

    #[test]
    fn poll_deadline_zero_means_none_and_others_are_absolute() {
        assert_eq!(
            decode_poll_deadline(OBJECT_POLL_NO_DEADLINE, true),
            Ok(None)
        );
        assert_eq!(
            decode_poll_deadline(OBJECT_POLL_NO_DEADLINE, false),
            Ok(None)
        );
        for deadline in [1, 5_000_000, u64::MAX] {
            assert_eq!(decode_poll_deadline(deadline, true), Ok(Some(deadline)));
            assert_eq!(decode_poll_deadline(deadline, false), Err(SYSCALL_EINVAL));
        }
    }

    #[test]
    fn poll_deadline_expires_at_or_after_the_deadline_only() {
        let no_clock = || -> u64 { panic!("the clock must not be read without a deadline") };
        assert!(!deadline_passed(None, no_clock));
        assert!(deadline_passed(Some(1), || 500));
        assert!(deadline_passed(Some(500), || 500));
        assert!(!deadline_passed(Some(501), || 500));
        assert!(!deadline_passed(Some(u64::MAX), || u64::MAX - 1));
        assert!(deadline_passed(Some(u64::MAX), || u64::MAX));
    }

    #[test]
    fn poll_timeout_leaves_the_request_queued_for_a_later_poll() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(40);
        let request_id = queue.submit(client, OBJECT_OP_READ, 7, 0, &[]).unwrap();
        let mut out = [0u8; 8];
        assert_eq!(
            queue.poll(client, request_id, &mut out),
            Ok(OBJECT_STATUS_PENDING)
        );
        let request = queue
            .service_next()
            .expect("still pending after the timeout");
        assert_eq!(request.request_id, request_id);
        queue.service_complete(request_id, 0, b"late").unwrap();
        assert_eq!(queue.poll(client, request_id, &mut out), Ok(4));
        assert_eq!(&out[..4], b"late");
    }

    /// Completions that land before the client polls must not fill the pending-wake table
    /// that `NativeOutcome` waiters (the net service) rely on.
    #[test]
    fn completions_before_poll_leave_the_pending_wake_table_free() {
        use crate::sched::wait::{
            consume_pending_wake_for_tests, pending_wake_keys_for_tests, wake_all, MAX_WAITERS,
        };
        let is_object_queue_key = |key: u64| matches!(key >> 56, 0x46 | 0x47);
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(42);
        let mut out = [0u8; 8];
        for _ in 0..2 * MAX_WAITERS {
            let request_id = queue.submit(client, OBJECT_OP_READ, 7, 0, &[]).unwrap();
            let request = queue.service_next().expect("pending");
            queue
                .service_complete(request.request_id, 0, b"ok")
                .unwrap();
            assert_eq!(queue.poll(client, request_id, &mut out), Ok(2));
        }
        assert!(!pending_wake_keys_for_tests()
            .into_iter()
            .any(is_object_queue_key));

        let native_key = WaitKey(0x54 << 56 | 0xE200_0001);
        assert_eq!(wake_all(native_key), 0);
        assert!(
            consume_pending_wake_for_tests(native_key),
            "a NativeOutcome waiter's wake was dropped"
        );
    }

    #[test]
    fn object_queue_code_never_records_pending_wakes() {
        let code = include_str!("object.rs")
            .split("mod tests {")
            .next()
            .unwrap();
        for forbidden in ["wake_all(", "wake_one("] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
    }

    fn poll_frame(deadline: u64) -> SyscallContext {
        SyscallContext {
            rax: SYSCALL_NR_CAP_OBJECT,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 1,
            rdi: OBJECT_SUBOP_POLL,
            r8: deadline,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0x40_1002,
            user_rflags: 0x202,
            user_rsp: 0x7fff_0000,
        }
    }

    #[test]
    fn poll_handler_refuses_a_deadline_without_a_calibrated_clock() {
        crate::time::set_test_monotonic_tsc(0, 0);
        let mut frame = poll_frame(100);
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, SYSCALL_EINVAL);

        crate::time::set_test_monotonic_tsc(1_000_000_000, 0);
        let mut frame = poll_frame(100);
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, SYSCALL_EACCES);
        let mut frame = poll_frame(OBJECT_POLL_NO_DEADLINE);
        crate::time::set_test_monotonic_tsc(0, 0);
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, SYSCALL_EACCES);
    }

    #[test]
    fn pending_bootstrap_grant_rolls_back_when_bootstrap_table_is_full() {
        use clean_slate_capability::list_holder;

        use super::register_pending_bootstrap_grant;
        use crate::capability::bootstrap_grant::{
            discard_bootstrap_grants_for_holder, register_bootstrap_grant,
        };
        use crate::capability::{grant_root, revoke_for_holder};

        let holder = HolderId(88_881);
        let target_object = 4242u64;
        // Other holders fill the bootstrap table, so `holder` stays under its slot quota.
        let filler = |object_id: u64| HolderId(88_900 + object_id);
        for object_id in 0..16u64 {
            let handle = grant_root(
                filler(object_id),
                ResourceRef::object(object_id + 10_000),
                Rights::READ,
            )
            .expect("fill bootstrap grants");
            register_bootstrap_grant(filler(object_id), handle).expect("register filler grant");
        }
        let live_before = with_capability_space(|table| table.live_count());
        let listed_before = with_capability_space(|table| {
            let mut cursor = 0usize;
            let mut found = false;
            while let Some((next, _handle, record)) = list_holder(table, holder, cursor) {
                if record.resource.id == target_object {
                    found = true;
                }
                cursor = next;
            }
            found
        });
        assert_eq!(
            register_pending_bootstrap_grant(holder, target_object, Rights::READ),
            Err(CapabilityError::CapacityExhausted)
        );
        let live_after = with_capability_space(|table| table.live_count());
        assert_eq!(live_before, live_after);
        let listed_after = with_capability_space(|table| {
            let mut cursor = 0usize;
            let mut found = false;
            while let Some((next, _handle, record)) = list_holder(table, holder, cursor) {
                if record.resource.id == target_object {
                    found = true;
                }
                cursor = next;
            }
            found
        });
        assert_eq!(listed_before, listed_after);
        assert!(!listed_after);
        for object_id in 0..16u64 {
            discard_bootstrap_grants_for_holder(filler(object_id));
            revoke_for_holder(filler(object_id));
        }
        revoke_for_holder(holder);
    }
}
