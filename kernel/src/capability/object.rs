//! M6.3 persistent object/file capability surface (kernel side of SYSCALL_NR_CAP_OBJECT).

use core::ptr;

use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ENOSYS,
};
use clean_slate_capability::{
    CapabilityError, CapabilityHandle, CapabilityState, HolderId, ResourceClass, ResourceRef,
    Rights,
};
use clean_slate_service_fixtures::{
    ObjectServiceRequest, OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_READ, OBJECT_OP_WRITE,
    OBJECT_REQUEST_SLOTS, OBJECT_SERVICE_REQUEST_BYTES, OBJECT_SERVICE_ROLE_ID,
    OBJECT_STATUS_PENDING, OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, OBJECT_SUBOP_POLL,
    OBJECT_SUBOP_SERVICE_COMPLETE, OBJECT_SUBOP_SERVICE_NEXT, OBJECT_SUBOP_SUBMIT,
};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::sync::global_cell::GlobalCell;

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
    len: usize,
    payload: [u8; OBJECT_MAX_PAYLOAD_BYTES],
    status: u64,
}

impl ObjectRequestSlot {
    const fn free() -> Self {
        Self {
            state: SlotState::Free,
            client: HolderId(0),
            request_id: 0,
            op: 0,
            object_id: 0,
            len: 0,
            payload: [0; OBJECT_MAX_PAYLOAD_BYTES],
            status: 0,
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
        slot.len = len;
        slot.payload[..len].copy_from_slice(payload);
        self.slots[slot_index] = slot;
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
        // #101: wake blocked Linux fs syscalls waiting on this object request.
        crate::sched::wait::wake_one(crate::sched::wait::WaitKey(
            0x46_u64 << 56 | (request_id & 0x00FF_FFFF_FFFF_FFFF),
        ));
        Ok(())
    }
}

#[allow(dead_code)] // #101 object-backed /tmp writes (blocking path lands next).
pub(crate) fn object_queue_submit(
    client: HolderId,
    op: u64,
    object_id: u64,
    payload: &[u8],
) -> Result<u64, SyscallQueueError> {
    queue_mut().submit(client, op, object_id, payload)
}

#[allow(dead_code)]
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
    if table.revoke(handle).is_ok() {
        table.release_slot(slot);
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
        feature = "m9-rootfs"
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
    not(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test")),
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

fn authorize_object_op(raw_handle: u64, object_id: u64, op: u64) -> Result<(), CapabilityError> {
    let holder = current_holder().map_err(|_| CapabilityError::UnauthorizedHolder)?;
    let required = match op {
        OBJECT_OP_READ => Rights::READ,
        OBJECT_OP_WRITE => Rights::WRITE,
        _ => return Err(CapabilityError::InvalidHandle),
    };
    let record = authorize_current_class(raw_handle, ResourceClass::PersistentObject, required)?;
    if record.resource.id != object_id {
        return Err(CapabilityError::WrongResource);
    }
    log_allowed(holder, object_id, op);
    Ok(())
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
    if let Err(error) = authorize_object_op(raw_handle, object_id, op) {
        log_deny(holder, object_id, op, error);
        frame.rax = error.syscall_status();
        return;
    }
    let mut payload = [0u8; OBJECT_MAX_PAYLOAD_BYTES];
    if len > 0 {
        unsafe {
            ptr::copy_nonoverlapping(frame.r8 as *const u8, payload.as_mut_ptr(), len);
        }
    }
    match queue_mut().submit(holder, op, object_id, &payload[..len]) {
        Ok(request_id) => frame.rax = request_id,
        Err(error) => frame.rax = error.syscall_status(),
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
        Ok(OBJECT_STATUS_PENDING) => frame.rax = OBJECT_STATUS_PENDING,
        Ok(written) => {
            unsafe {
                ptr::copy_nonoverlapping(out.as_ptr(), frame.r10 as *mut u8, written as usize);
            }
            frame.rax = written;
        }
        Err(error) => frame.rax = error.syscall_status(),
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
            let bytes = request.encode();
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), frame.rdx as *mut u8, bytes.len());
            }
            frame.rax = 1;
        }
        None => frame.rax = 0,
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
    if len > 0 {
        unsafe {
            ptr::copy_nonoverlapping(frame.r8 as *const u8, payload.as_mut_ptr(), len);
        }
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
        let required = match op {
            OBJECT_OP_READ => Rights::READ,
            OBJECT_OP_WRITE => Rights::WRITE,
            _ => return Err(CapabilityError::InvalidHandle),
        };
        let decoded = CapabilityHandle::decode(handle)?;
        let record =
            table.authorize_class(holder, decoded, ResourceClass::PersistentObject, required)?;
        if record.resource.id != object_id {
            return Err(CapabilityError::WrongResource);
        }
        Ok(())
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
                .submit(client, OBJECT_OP_WRITE, 7, b"alpha-v1")
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
        let request_id = queue.submit(owner, OBJECT_OP_READ, 7, &[]).unwrap();
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
            queue.submit(client, OBJECT_OP_READ, 1, &[]).unwrap();
        }
        assert_eq!(
            queue.submit(client, OBJECT_OP_READ, 1, &[]),
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
            request_ids[index] = queue.submit(client, OBJECT_OP_READ, 1, &[]).unwrap();
            let status = error_statuses[index % error_statuses.len()];
            assert_eq!(
                complete_next_with_status(&mut queue, status),
                request_ids[index]
            );
        }
        assert_eq!(
            queue.submit(client, OBJECT_OP_READ, 1, &[]),
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
            queue.submit(client, OBJECT_OP_READ, 2, &[]).unwrap();
        }
    }

    #[test]
    fn poll_after_consumed_error_completion_returns_invalid_request() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(31);
        let request_id = queue.submit(client, OBJECT_OP_READ, 1, &[]).unwrap();
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
            queue.submit(client, OBJECT_OP_READ, 1, &[]).unwrap();
        }
        queue.service_next().expect("pending request");
        let second = queue.service_next().expect("second pending");
        queue
            .service_complete(second.request_id, 0, b"done")
            .unwrap();
        assert_eq!(queue.reclaim_for_holder(client), OBJECT_REQUEST_SLOTS);
        for _ in 0..OBJECT_REQUEST_SLOTS {
            queue.submit(client, OBJECT_OP_READ, 2, &[]).unwrap();
        }
    }

    #[test]
    fn service_complete_fails_after_holder_reclaim() {
        let mut queue = ObjectRequestQueue::new();
        let client = HolderId(21);
        let request_id = queue.submit(client, OBJECT_OP_READ, 1, &[]).unwrap();
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
            .submit(client, OBJECT_OP_WRITE, 7, b"payload")
            .unwrap();
        let first = queue.service_next().expect("first dequeue");
        assert_eq!(queue.requeue_in_service(), 1);
        let second = queue.service_next().expect("requeued dequeue");
        assert_eq!(first.request_id, second.request_id);
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
        for object_id in 0..16u64 {
            let handle = grant_root(
                holder,
                ResourceRef::object(object_id + 10_000),
                Rights::READ,
            )
            .expect("fill bootstrap grants");
            register_bootstrap_grant(holder, handle).expect("register filler grant");
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
        discard_bootstrap_grants_for_holder(holder);
        revoke_for_holder(holder);
    }
}
