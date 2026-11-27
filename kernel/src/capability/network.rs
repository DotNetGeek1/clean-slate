//! M7.7 network capability broker over the production M6 capability table.

#![cfg_attr(not(feature = "m7-net-caps-self-test"), allow(dead_code))]

use core::fmt::{self, Write};

use clean_slate_capability::{
    revoke_subtree, AuditEvent, AuditKind, CapabilityError, CapabilityHandle, CapabilityRecord,
    CapabilityState, CapabilityTable, HolderId, PolicyRefusal, Provenance, ResourceClass,
    ResourceRef, Rights,
};
use clean_slate_network::error::DenialReason;
use clean_slate_network::session::{SessionGeneration, SessionId};
use clean_slate_service_lifecycle::ServiceId;

use crate::diagnostics::log::kernel_log_fmt;
#[cfg(any(test, clean_slate_linux_socket))]
use crate::service::instance_generation::live_network_instance_generation;
use crate::service::instance_generation::live_network_service_generation;
use crate::sync::global_cell::GlobalCell;

use super::audit::{self, record_decision, record_kernel_revoke};
use super::{capability_space_mut, grant_root, with_capability_space};

/// Logical network service id for `ResourceClass::Network` capability records.
pub(crate) const NETWORK_SERVICE_ID: ServiceId = ServiceId(0x0000_5200);

const MAX_TRACKED_SESSIONS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkOp {
    Resolve,
    Connect,
    Send,
    Receive,
    RawDevice,
}

impl NetworkOp {
    pub(crate) const fn required_right(self) -> Rights {
        match self {
            Self::Resolve => Rights::NET_RESOLVE,
            Self::Connect => Rights::NET_CONNECT,
            Self::Send => Rights::NET_SEND,
            Self::Receive => Rights::NET_RECEIVE,
            Self::RawDevice => Rights::NET_RAW_DEVICE,
        }
    }

    fn op_name(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Connect => "connect",
            Self::Send => "send",
            Self::Receive => "receive",
            Self::RawDevice => "raw-device",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizedNetworkOp {
    pub holder: HolderId,
    pub resource: ResourceRef,
    pub op: NetworkOp,
    pub live_generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkGrantPolicy {
    Application,
    NetworkService,
}

#[derive(Clone, Copy)]
struct SessionEntry {
    holder: HolderId,
    session: SessionId,
    capability_slot: u16,
}

struct NetworkSessionRegistry {
    sessions: [Option<SessionEntry>; MAX_TRACKED_SESSIONS],
}

impl NetworkSessionRegistry {
    const fn new() -> Self {
        Self {
            sessions: [None; MAX_TRACKED_SESSIONS],
        }
    }

    fn register(
        &mut self,
        holder: HolderId,
        session: SessionId,
        handle: CapabilityHandle,
    ) -> Result<(), &'static str> {
        let slot = self
            .sessions
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or("network session registry full")?;
        *slot = Some(SessionEntry {
            holder,
            session,
            capability_slot: handle.slot,
        });
        Ok(())
    }

    fn sessions_for_handle(&self, handle: CapabilityHandle) -> [SessionId; MAX_TRACKED_SESSIONS] {
        let mut out = [SessionId::from_raw(0); MAX_TRACKED_SESSIONS];
        let mut index = 0;
        for entry in &self.sessions {
            let Some(record) = entry else {
                continue;
            };
            if record.capability_slot != handle.slot || index >= MAX_TRACKED_SESSIONS {
                continue;
            }
            out[index] = record.session;
            index += 1;
        }
        out
    }

    fn clear_holder(&mut self, holder: HolderId) -> usize {
        let mut cleared = 0;
        for entry in &mut self.sessions {
            if matches!(entry, Some(record) if record.holder == holder) {
                *entry = None;
                cleared += 1;
            }
        }
        cleared
    }

    fn clear_all(&mut self) {
        for entry in &mut self.sessions {
            *entry = None;
        }
    }
}

static NETWORK_SESSIONS: GlobalCell<NetworkSessionRegistry> =
    GlobalCell::new(NetworkSessionRegistry::new());
static NETWORK_AUDIT_SERIAL: GlobalCell<bool> = GlobalCell::new(false);

pub(crate) fn set_network_audit_serial_echo(enabled: bool) {
    unsafe {
        *NETWORK_AUDIT_SERIAL.get() = enabled;
    }
}

pub(crate) fn network_service_resource() -> Result<ResourceRef, CapabilityError> {
    let generation = live_network_service_generation()
        .map(|g| u64::from(g.0))
        .ok_or(CapabilityError::WrongResource)?;
    Ok(ResourceRef::network(
        u64::from(NETWORK_SERVICE_ID.0),
        generation,
    ))
}

#[allow(dead_code)] // Session-scoped caps are optional until #83 wires per-session grants.
pub(crate) fn network_session_resource(session: SessionId) -> ResourceRef {
    ResourceRef::network_session(session.generation().get(), session.index())
}

fn sanitize_application_rights(rights: Rights) -> Result<Rights, CapabilityError> {
    let valid = Rights::valid_for(ResourceClass::Network);
    if !rights.is_subset_of(valid) {
        return Err(CapabilityError::InvalidRights);
    }
    if rights.contains(Rights::NET_RAW_DEVICE) {
        return Err(CapabilityError::InvalidRights);
    }
    Ok(rights)
}

pub(crate) fn grant_network_authority(
    target_holder: HolderId,
    rights: Rights,
    policy: NetworkGrantPolicy,
    instance_generation: Option<u64>,
) -> Result<CapabilityHandle, CapabilityError> {
    let effective = match policy {
        NetworkGrantPolicy::Application => sanitize_application_rights(rights),
        NetworkGrantPolicy::NetworkService
            if !rights.is_subset_of(Rights::valid_for(ResourceClass::Network)) =>
        {
            Err(CapabilityError::InvalidRights)
        }
        NetworkGrantPolicy::NetworkService => Ok(rights),
    };
    let effective = effective.inspect_err(|error| {
        audit::record(
            AuditEvent::new(
                AuditKind::Grant,
                HolderId::KERNEL,
                network_service_any_instance(),
                rights,
            )
            .with_subject(target_holder)
            .with_result(Err(*error)),
        );
    })?;
    let resource = match instance_generation {
        Some(generation) => ResourceRef::network(u64::from(NETWORK_SERVICE_ID.0), generation),
        None => network_service_resource()?,
    };
    let handle = grant_root(target_holder, resource, effective)?;
    log_grant(target_holder, effective, resource.instance_generation);
    Ok(handle)
}

fn log_grant(holder: HolderId, rights: Rights, generation: u64) {
    let mut names = RightsNameBuf {
        bytes: [0; 64],
        len: 0,
    };
    let _ = rights.write_names(&mut names);
    let rights_text = core::str::from_utf8(&names.bytes[..names.len]).unwrap_or("?");
    kernel_log_fmt(format_args!(
        "[CAP ] net grant holder={} rights={} generation={}\n",
        holder.0, rights_text, generation
    ));
}

fn log_allow(holder: HolderId, op: NetworkOp) {
    #[cfg(feature = "m7-net-caps-self-test")]
    kernel_log_fmt(format_args!(
        "[CAP ] net allow op={} holder={}\n",
        op.op_name(),
        holder.0
    ));
    let _ = (holder, op);
}

fn log_denied(holder: HolderId, reason: DenialReason) {
    let reason_name = match reason {
        DenialReason::NoCapability => "no-authority",
        DenialReason::MissingRight => "missing-right",
        DenialReason::StaleGeneration => "stale-generation",
        DenialReason::Revoked => "revoked",
        DenialReason::Destination => "destination",
    };
    kernel_log_fmt(format_args!(
        "[NET ] denied pid={} reason={}\n",
        holder.0, reason_name
    ));
}

fn log_stale_session(generation: u64) {
    kernel_log_fmt(format_args!(
        "[NET ] stale-session denied generation={}\n",
        generation
    ));
}

fn capability_error_to_denial(error: CapabilityError) -> DenialReason {
    match error {
        CapabilityError::MissingRight => DenialReason::MissingRight,
        CapabilityError::Revoked => DenialReason::Revoked,
        CapabilityError::WrongResource => DenialReason::StaleGeneration,
        CapabilityError::InvalidHandle
        | CapabilityError::StaleHandle
        | CapabilityError::UnauthorizedHolder => DenialReason::NoCapability,
        _ => DenialReason::NoCapability,
    }
}

fn record_network_audit(
    actor: HolderId,
    resource: ResourceRef,
    op: NetworkOp,
    handle: CapabilityHandle,
    depth: u8,
    result: Result<(), CapabilityError>,
) {
    record_decision(actor, resource, op.required_right(), handle, depth, result);
    if !unsafe { *NETWORK_AUDIT_SERIAL.get() } {
        return;
    }
    let outcome = match result {
        Ok(()) => "allow",
        Err(_) => "deny",
    };
    if outcome == "allow" && matches!(op, NetworkOp::RawDevice) {
        return;
    }
    kernel_log_fmt(format_args!(
        "[AUD ] net op={} actor={} outcome={} resource={} generation={}\n",
        op.op_name(),
        actor.0,
        outcome,
        resource.id,
        resource.instance_generation
    ));
}

pub(crate) fn authorize_network_op(
    trusted_holder: HolderId,
    raw_handle: u64,
    op: NetworkOp,
    session_generation: Option<SessionGeneration>,
) -> Result<AuthorizedNetworkOp, DenialReason> {
    let live_resource = match network_service_resource() {
        Ok(resource) => resource,
        Err(error) => {
            let handle = CapabilityHandle::decode(raw_handle).unwrap_or(CapabilityHandle::INVALID);
            record_network_audit(
                trusted_holder,
                ResourceRef {
                    class: ResourceClass::Network,
                    id: u64::from(NETWORK_SERVICE_ID.0),
                    instance_generation: 0,
                },
                op,
                handle,
                0,
                Err(error),
            );
            return Err(DenialReason::StaleGeneration);
        }
    };
    if let Some(session_gen) = session_generation {
        if session_gen.get() != live_resource.instance_generation {
            audit::record(
                AuditEvent::new(
                    AuditKind::Authorize,
                    trusted_holder,
                    live_resource,
                    op.required_right(),
                )
                .with_handle(
                    CapabilityHandle::decode(raw_handle).unwrap_or(CapabilityHandle::INVALID),
                )
                .refused(PolicyRefusal::StaleTarget),
            );
            log_stale_session(session_gen.get());
            return Err(DenialReason::StaleGeneration);
        }
    }
    let handle = match CapabilityHandle::decode(raw_handle) {
        Ok(handle) => handle,
        Err(error) => {
            record_network_audit(
                trusted_holder,
                live_resource,
                op,
                CapabilityHandle::INVALID,
                0,
                Err(error),
            );
            log_denied(trusted_holder, DenialReason::NoCapability);
            return Err(DenialReason::NoCapability);
        }
    };
    let required = op.required_right();
    let auth = with_capability_space(|table| {
        let record = table.authorize(trusted_holder, handle, live_resource, required)?;
        if is_network_client_entitlement(&record) {
            return Err(CapabilityError::WrongResource);
        }
        Ok(record)
    });
    let (record, result) = match auth {
        Ok(record) => (record, Ok(())),
        Err(error) => {
            let depth = with_capability_space(|table| {
                table
                    .record(handle)
                    .map(|record| record.provenance.depth)
                    .unwrap_or(0)
            });
            record_network_audit(trusted_holder, live_resource, op, handle, depth, Err(error));
            let denial = capability_error_to_denial(error);
            log_denied(trusted_holder, denial);
            return Err(denial);
        }
    };
    record_network_audit(
        trusted_holder,
        record.resource,
        op,
        handle,
        record.provenance.depth,
        result,
    );
    log_allow(trusted_holder, op);
    Ok(AuthorizedNetworkOp {
        holder: trusted_holder,
        resource: record.resource,
        op,
        live_generation: live_resource.instance_generation,
    })
}

pub(crate) fn register_network_session(
    holder: HolderId,
    session: SessionId,
    capability_handle: CapabilityHandle,
) -> Result<(), &'static str> {
    unsafe { &mut *NETWORK_SESSIONS.get() }.register(holder, session, capability_handle)
}

/// Returns impacted sessions for a revoked network capability (best-effort, fixed capacity).
pub(crate) fn on_revoked(handle: CapabilityHandle) -> [SessionId; MAX_TRACKED_SESSIONS] {
    let impacted = unsafe { (*NETWORK_SESSIONS.get()).sessions_for_handle(handle) };
    let table = unsafe { capability_space_mut() };
    let record = table.record(handle);
    if let (Ok(record), Ok(count)) = (record, revoke_subtree(table, handle)) {
        record_kernel_revoke(record.holder, record.resource, count);
    }
    impacted
}

/// Revokes live network capabilities for a holder (used before re-granting after service restart).
#[allow(dead_code)]
pub(crate) fn revoke_network_capabilities_for_holder(holder: HolderId) {
    let handles: [Option<CapabilityHandle>; MAX_TRACKED_SESSIONS] =
        with_capability_space(|table| {
            let mut out = [None; MAX_TRACKED_SESSIONS];
            let mut index = 0usize;
            for slot in 0..table.capacity() {
                if index >= MAX_TRACKED_SESSIONS {
                    break;
                }
                if table.state_at(slot) != CapabilityState::Live {
                    continue;
                }
                let record = table.record_at(slot);
                if record.holder != holder || record.resource.class != ResourceClass::Network {
                    continue;
                }
                out[index] = table.handle_at(slot);
                index += 1;
            }
            out
        });
    for handle in handles.into_iter().flatten() {
        let _ = on_revoked(handle);
    }
}

// #218 S7: the `NetworkClient` grant.
//
// The grant installs an entitlement record naming the network SERVICE with no instance
// generation (`NETWORK_CLIENT_ENTITLEMENT_GENERATION`, outside the `u32` range of instance
// generations). No live resource can match it, and `authorize_network_op` refuses it
// regardless, so it confers no network operation by itself. It
// lives in the capability space: fork copies it, teardown revokes it, and the launch audit
// counts it on its own.
//
// From the entitlement the kernel derives a client capability bound to the live network
// instance: at grant time when an instance is live, and for every entitlement holder each
// time an instance registers. When an instance goes away the derived capabilities are
// revoked and their slots released, so every entitlement holder holds at most one client
// capability. Holders without the entitlement (the M7 and M9 self-test clients) are never
// touched.

/// Rights of the entitlement and of every client capability derived from it.
pub(crate) const NETWORK_CLIENT_RIGHTS: Rights = Rights::NET_CONNECT
    .union(Rights::NET_SEND)
    .union(Rights::NET_RECEIVE);

/// Generation of the entitlement record: the network service, no instance. Instance
/// generations are `u32`, and an M7 grant made before the first network start sits on the
/// authoritative generation 0, so no other network record can carry this one.
const NETWORK_CLIENT_ENTITLEMENT_GENERATION: u64 = u64::MAX;

pub(crate) const fn network_client_entitlement_resource() -> ResourceRef {
    ResourceRef::network(
        NETWORK_SERVICE_ID.0 as u64,
        NETWORK_CLIENT_ENTITLEMENT_GENERATION,
    )
}

pub(crate) fn is_network_client_entitlement(record: &CapabilityRecord) -> bool {
    record.resource == network_client_entitlement_resource()
}

/// Whether `generation` can be a started network instance's: instances start at 1 and are
/// numbered in `u32`.
fn is_started_instance_generation(generation: u64) -> bool {
    (1..=u64::from(u32::MAX)).contains(&generation)
}

/// A client capability bound to a started network-service instance, without raw-device
/// authority.
pub(crate) fn is_instance_bound_network_client(record: &CapabilityRecord) -> bool {
    record.resource.class == ResourceClass::Network
        && record.resource.id == u64::from(NETWORK_SERVICE_ID.0)
        && is_started_instance_generation(record.resource.instance_generation)
        && !record.rights.contains(Rights::NET_RAW_DEVICE)
}

#[cfg(any(test, clean_slate_linux_socket))]
fn holds_live_entitlement<const N: usize>(table: &CapabilityTable<N>, holder: HolderId) -> bool {
    (0..N).any(|slot| {
        let record = table.record_at(slot);
        record.state == CapabilityState::Live
            && record.holder == holder
            && is_network_client_entitlement(record)
    })
}

/// Distinct holders of a live entitlement, in slot order.
fn entitlement_holders<const N: usize>(table: &CapabilityTable<N>) -> ([HolderId; N], usize) {
    let mut holders = [HolderId(0); N];
    let mut count = 0usize;
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.state != CapabilityState::Live
            || !is_network_client_entitlement(record)
            || holders[..count].contains(&record.holder)
        {
            continue;
        }
        holders[count] = record.holder;
        count += 1;
    }
    (holders, count)
}

/// Revokes `holder`'s instance-bound client capabilities with their subtrees (copies a
/// fork made from them), then releases the revoked client slots so revocation never
/// accumulates records. Returns the number of records revoked.
fn revoke_client_capabilities_in<const N: usize>(
    table: &mut CapabilityTable<N>,
    holder: HolderId,
) -> usize {
    let mut revoked = 0usize;
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.state != CapabilityState::Live
            || record.holder != holder
            || !is_instance_bound_network_client(record)
        {
            continue;
        }
        if let Some(handle) = table.handle_at(slot) {
            revoked += revoke_subtree(table, handle).unwrap_or(0);
        }
    }
    for slot in 0..N {
        let record = table.record_at(slot);
        if record.state == CapabilityState::Revoked && is_instance_bound_network_client(record) {
            table.release_slot(slot);
        }
    }
    if revoked > 0 {
        record_kernel_revoke(holder, network_service_any_instance(), revoked);
    }
    revoked
}

/// Names the network service across instances, for records about client capabilities.
const fn network_service_any_instance() -> ResourceRef {
    ResourceRef::network(NETWORK_SERVICE_ID.0 as u64, 0)
}

fn record_client_grant(
    holder: HolderId,
    resource: ResourceRef,
    result: Result<CapabilityHandle, CapabilityError>,
) {
    audit::record(
        AuditEvent::new(
            AuditKind::Grant,
            HolderId::KERNEL,
            resource,
            NETWORK_CLIENT_RIGHTS,
        )
        .with_subject(holder)
        .with_handle(*result.as_ref().unwrap_or(&CapabilityHandle::INVALID))
        .with_result(result.map(|_| ())),
    );
}

/// Replaces `holder`'s client capability with one bound to instance `generation`.
fn issue_client_capability_in<const N: usize>(
    table: &mut CapabilityTable<N>,
    holder: HolderId,
    generation: u64,
) -> Result<CapabilityHandle, CapabilityError> {
    let resource = ResourceRef::network(u64::from(NETWORK_SERVICE_ID.0), generation);
    let result = if is_started_instance_generation(generation) {
        revoke_client_capabilities_in(table, holder);
        table.grant(
            holder,
            resource,
            NETWORK_CLIENT_RIGHTS,
            Provenance::root(holder),
        )
    } else {
        Err(CapabilityError::WrongResource)
    };
    record_client_grant(holder, resource, result);
    result
}

/// Installs the entitlement for `holder`, and its client capability when an instance is
/// live (`live_generation`).
#[cfg(any(test, clean_slate_linux_socket))]
fn grant_entitlement_in<const N: usize>(
    table: &mut CapabilityTable<N>,
    holder: HolderId,
    live_generation: Option<u64>,
) -> Result<(), CapabilityError> {
    let entitlement = table.grant(
        holder,
        network_client_entitlement_resource(),
        NETWORK_CLIENT_RIGHTS,
        Provenance::root(holder),
    );
    record_client_grant(holder, network_client_entitlement_resource(), entitlement);
    entitlement?;
    if let Some(generation) = live_generation {
        issue_client_capability_in(table, holder, generation)?;
    }
    Ok(())
}

/// Gives every entitlement holder a client capability for instance `generation`, calling
/// `issued` with each holder (or the error that left it without one).
fn reissue_client_capabilities_in<const N: usize>(
    table: &mut CapabilityTable<N>,
    generation: u64,
    mut issued: impl FnMut(HolderId, Result<CapabilityHandle, CapabilityError>),
) {
    let (holders, count) = entitlement_holders(table);
    for &holder in &holders[..count] {
        let result = issue_client_capability_in(table, holder, generation);
        issued(holder, result);
    }
}

/// Revokes the client capabilities of every entitlement holder. Returns the number revoked.
fn revoke_entitled_client_capabilities_in<const N: usize>(table: &mut CapabilityTable<N>) -> usize {
    let (holders, count) = entitlement_holders(table);
    holders[..count]
        .iter()
        .map(|&holder| revoke_client_capabilities_in(table, holder))
        .sum()
}

/// `NetworkClient` launch grant for `holder`. Only a build with the Linux socket layer
/// launches with it (`system_shell::grant_network_client`).
#[cfg(any(test, clean_slate_linux_socket))]
pub(crate) fn grant_network_client_entitlement(holder: HolderId) -> Result<(), CapabilityError> {
    let live_generation = live_network_instance_generation().map(|g| u64::from(g.0));
    let table = unsafe { capability_space_mut() };
    // An entitlement installed without its client capability is left for the launch's
    // teardown to revoke; only a grant that installed nothing is retried.
    match grant_entitlement_in(table, holder, live_generation) {
        Err(CapabilityError::CapacityExhausted) if !holds_live_entitlement(table, holder) => {
            let _ = clean_slate_capability::release_revoked(table);
            grant_entitlement_in(table, holder, live_generation)
        }
        other => other,
    }?;
    log_entitlement(holder, live_generation);
    Ok(())
}

#[cfg(any(test, clean_slate_linux_socket))]
fn log_entitlement(holder: HolderId, live_generation: Option<u64>) {
    match live_generation {
        Some(generation) => kernel_log_fmt(format_args!(
            "[CAP ] net client entitlement holder={} service={} instance-generation={}\n",
            holder.0, NETWORK_SERVICE_ID.0, generation
        )),
        None => kernel_log_fmt(format_args!(
            "[CAP ] net client entitlement holder={} service={} instance-generation=none\n",
            holder.0, NETWORK_SERVICE_ID.0
        )),
    }
}

/// A network instance of `generation` has registered: re-issue every entitlement holder's
/// client capability for it.
pub(crate) fn on_network_instance_registered(generation: u64) {
    let table = unsafe { capability_space_mut() };
    reissue_client_capabilities_in(table, generation, |holder, result| match result {
        Ok(_) => kernel_log_fmt(format_args!(
            "[CAP ] net client reissued holder={} generation={}\n",
            holder.0, generation
        )),
        Err(error) => kernel_log_fmt(format_args!(
            "[FAIL] net client reissue failed holder={} generation={} err={:?}\n",
            holder.0, generation, error
        )),
    });
}

/// The network instance went away: revoke every entitlement holder's client capability.
pub(crate) fn on_network_instance_gone() {
    let revoked = revoke_entitled_client_capabilities_in(unsafe { capability_space_mut() });
    if revoked > 0 {
        kernel_log_fmt(format_args!(
            "[CAP ] net client revoked count={} reason=instance-gone\n",
            revoked
        ));
    }
}

/// Clears tracked network sessions after M6 holder revocation (call from process teardown).
pub(crate) fn on_holder_exit(holder: HolderId) -> usize {
    let sessions_cleared = unsafe { (&mut *NETWORK_SESSIONS.get()).clear_holder(holder) };
    let network_caps = with_capability_space(|table| {
        let mut count = 0usize;
        for slot in 0..table.capacity() {
            if table.state_at(slot) == CapabilityState::Live
                && table.record_at(slot).holder == holder
                && table.record_at(slot).resource.class == ResourceClass::Network
            {
                count += 1;
            }
        }
        count
    });
    kernel_log_fmt(format_args!(
        "[CAP ] net released holder={} count={}\n",
        holder.0,
        network_caps.max(sessions_cleared)
    ));
    network_caps.max(sessions_cleared)
}

#[cfg(feature = "m7-net-caps-self-test")]
pub(crate) fn clear_network_sessions_for_test() {
    unsafe { (&mut *NETWORK_SESSIONS.get()).clear_all() };
}

struct RightsNameBuf {
    bytes: [u8; 64],
    len: usize,
}

impl Write for RightsNameBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        if self.len + bytes.len() > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::{
        authorize, delegate, event_for, CapabilityTable, Provenance, MAX_SLOTS,
    };

    #[test]
    fn application_grant_refuses_raw_device() {
        let rights = Rights::NET_CONNECT.union(Rights::NET_RAW_DEVICE);
        assert_eq!(
            sanitize_application_rights(rights),
            Err(CapabilityError::InvalidRights)
        );
    }

    #[test]
    fn denial_mapping_distinct() {
        assert_eq!(
            capability_error_to_denial(CapabilityError::MissingRight),
            DenialReason::MissingRight
        );
        assert_eq!(
            capability_error_to_denial(CapabilityError::Revoked),
            DenialReason::Revoked
        );
        assert_eq!(
            capability_error_to_denial(CapabilityError::WrongResource),
            DenialReason::StaleGeneration
        );
        assert_eq!(
            capability_error_to_denial(CapabilityError::InvalidHandle),
            DenialReason::NoCapability
        );
    }

    #[test]
    fn audit_records_contain_no_payload_marker() {
        let event = event_for(
            1,
            HolderId(3),
            ResourceRef::network(1, 2),
            Rights::NET_SEND,
            CapabilityHandle::new(0, 1),
            0,
            Ok(()),
        );
        let mut line = [0u8; 128];
        let mut writer = TestLine {
            buf: &mut line,
            len: 0,
        };
        clean_slate_capability::format_audit_line(&event, &mut writer).unwrap();
        let formatted_len = writer.len;
        let text = core::str::from_utf8(&line[..formatted_len]).unwrap();
        assert!(!text.contains("payload"));
        assert!(!text.contains("hostname"));
    }

    struct TestLine<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    impl<'a> fmt::Write for TestLine<'a> {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            let bytes = s.as_bytes();
            if self.len + bytes.len() > self.buf.len() {
                return Err(fmt::Error);
            }
            self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
            self.len += bytes.len();
            Ok(())
        }
    }

    #[test]
    fn delegated_receive_only_cannot_connect() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        let holder = HolderId(1);
        let child = HolderId(2);
        let resource = ResourceRef::network(0x5200, 1);
        let parent_rights = Rights::NET_CONNECT
            .union(Rights::NET_RECEIVE)
            .union(Rights::DELEGATE);
        let parent = table
            .grant(holder, resource, parent_rights, Provenance::root(holder))
            .expect("grant");
        let child_rights = Rights::NET_RECEIVE;
        let child_handle =
            delegate(&mut table, holder, parent, child, child_rights).expect("delegate");
        let child_record = table.record(child_handle).expect("child");
        assert_eq!(
            authorize(
                &child_record,
                child_handle,
                child,
                resource,
                Rights::NET_CONNECT,
            ),
            Err(CapabilityError::MissingRight)
        );
        assert!(child_record.rights.contains(Rights::NET_RECEIVE));
    }

    const SHELL: HolderId = HolderId(4);
    const CHILD: HolderId = HolderId(9);
    /// An M7/M9-style client granted directly, without the entitlement.
    const DIRECT_CLIENT: HolderId = HolderId(12);

    fn instance(generation: u64) -> ResourceRef {
        ResourceRef::network(u64::from(NETWORK_SERVICE_ID.0), generation)
    }

    /// Live `(entitlements, instance-bound clients)` held by `holder`.
    fn held<const N: usize>(table: &CapabilityTable<N>, holder: HolderId) -> (usize, usize) {
        let live = (0..N)
            .map(|slot| table.record_at(slot))
            .filter(|record| record.state == CapabilityState::Live && record.holder == holder);
        live.fold((0, 0), |(entitlements, clients), record| {
            (
                entitlements + usize::from(is_network_client_entitlement(record)),
                clients + usize::from(is_instance_bound_network_client(record)),
            )
        })
    }

    fn client_slot<const N: usize>(table: &CapabilityTable<N>, holder: HolderId) -> usize {
        (0..N)
            .find(|&slot| {
                let record = table.record_at(slot);
                record.state == CapabilityState::Live
                    && record.holder == holder
                    && is_instance_bound_network_client(record)
            })
            .expect("holder has a client capability")
    }

    fn client_handle<const N: usize>(
        table: &CapabilityTable<N>,
        holder: HolderId,
    ) -> CapabilityHandle {
        table.handle_at(client_slot(table, holder)).unwrap()
    }

    fn client_generation<const N: usize>(table: &CapabilityTable<N>, holder: HolderId) -> u64 {
        table
            .record_at(client_slot(table, holder))
            .resource
            .instance_generation
    }

    fn occupied<const N: usize>(table: &CapabilityTable<N>) -> usize {
        (0..N)
            .filter(|&slot| table.state_at(slot) != CapabilityState::Empty)
            .count()
    }

    /// What `fork(2)` does (`inherit_capabilities_for_fork`) for network records, which carry
    /// no root-only right: every live record of `parent` copied to `child`, derived from the
    /// parent's.
    fn fork<const N: usize>(table: &mut CapabilityTable<N>, parent: HolderId, child: HolderId) {
        for slot in 0..N {
            let record = *table.record_at(slot);
            if record.state != CapabilityState::Live || record.holder != parent {
                continue;
            }
            let handle = table.handle_at(slot).unwrap();
            table
                .install(CapabilityRecord {
                    holder: child,
                    provenance: Provenance::child_of(handle, &record.provenance).unwrap(),
                    ..record
                })
                .unwrap();
        }
    }

    #[test]
    fn the_entitlement_names_the_service_and_no_instance_and_authorises_no_instance() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, None).unwrap();
        assert_eq!(held(&table, SHELL), (1, 0));
        let handle = table.handle_at(0).unwrap();
        let record = table.record(handle).unwrap();
        assert_eq!(record.rights, NETWORK_CLIENT_RIGHTS);
        assert_eq!(record.resource, network_client_entitlement_resource());
        assert!(is_network_client_entitlement(&record));
        assert!(!is_instance_bound_network_client(&record));
        // Generation 0 is the authoritative generation before the network's first start.
        for generation in [0, 1, 2, 7, u64::from(u32::MAX)] {
            for op in [NetworkOp::Connect, NetworkOp::Send, NetworkOp::Receive] {
                assert_eq!(
                    table.authorize(SHELL, handle, instance(generation), op.required_right()),
                    Err(CapabilityError::WrongResource)
                );
            }
        }
        for generation in [0, NETWORK_CLIENT_ENTITLEMENT_GENERATION] {
            assert_eq!(
                issue_client_capability_in(&mut table, SHELL, generation),
                Err(CapabilityError::WrongResource)
            );
        }
        assert_eq!(held(&table, SHELL), (1, 0));
    }

    /// An M7 client granted before the network's first start sits on generation 0; it is
    /// neither an entitlement nor a derived client, so the S7 paths never touch it.
    #[test]
    fn a_pre_start_m7_client_is_not_an_entitlement_or_a_derived_client() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        let handle = table
            .grant(
                SHELL,
                instance(0),
                NETWORK_CLIENT_RIGHTS,
                Provenance::root(SHELL),
            )
            .unwrap();
        let record = table.record(handle).unwrap();
        assert!(!is_network_client_entitlement(&record));
        assert!(!is_instance_bound_network_client(&record));
        assert_eq!(revoke_entitled_client_capabilities_in(&mut table), 0);
        assert_eq!(revoke_client_capabilities_in(&mut table, SHELL), 0);
        assert!(table
            .authorize(SHELL, handle, instance(0), Rights::NET_CONNECT)
            .is_ok());
    }

    #[test]
    fn a_launch_with_no_live_instance_holds_the_entitlement_only() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, None).unwrap();
        assert_eq!(held(&table, SHELL), (1, 0));
        assert_eq!(occupied(&table), 1);
    }

    #[test]
    fn a_launch_with_a_live_instance_also_holds_a_client_for_that_instance() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, Some(1)).unwrap();
        assert_eq!(held(&table, SHELL), (1, 1));
        assert_eq!(client_generation(&table, SHELL), 1);
        let client = client_handle(&table, SHELL);
        assert!(table
            .authorize(SHELL, client, instance(1), Rights::NET_CONNECT)
            .is_ok());
        assert_eq!(table.record(client).unwrap().rights, NETWORK_CLIENT_RIGHTS);
    }

    #[test]
    fn a_new_instance_reissues_the_client_and_the_old_one_stops_authorising() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, Some(1)).unwrap();
        let old = client_handle(&table, SHELL);

        assert_eq!(revoke_entitled_client_capabilities_in(&mut table), 1);
        assert!(table
            .authorize(SHELL, old, instance(1), Rights::NET_CONNECT)
            .is_err());
        assert_eq!(held(&table, SHELL), (1, 0));
        let mut issued = std::vec::Vec::new();
        reissue_client_capabilities_in(&mut table, 2, |holder, result| {
            issued.push((holder, result.is_ok()))
        });
        assert_eq!(issued, [(SHELL, true)]);
        assert_eq!(held(&table, SHELL), (1, 1));
        assert_eq!(client_generation(&table, SHELL), 2);
        assert!(table
            .authorize(SHELL, old, instance(2), Rights::NET_CONNECT)
            .is_err());
    }

    #[test]
    fn a_new_instance_without_the_old_one_going_first_still_leaves_one_client() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, Some(1)).unwrap();
        reissue_client_capabilities_in(&mut table, 2, |_, result| assert!(result.is_ok()));
        assert_eq!(held(&table, SHELL), (1, 1));
        assert_eq!(client_generation(&table, SHELL), 2);
        assert_eq!(occupied(&table), 2);
    }

    /// The shell and a child it forked before the first restart, across many restarts. Each
    /// restart revokes and releases the old clients before the new ones are issued, so the
    /// table holds exactly two records per entitlement holder however many restarts run:
    /// the bound is the number of entitlement holders, not the number of restarts.
    #[test]
    fn many_restarts_never_accumulate_records() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, Some(1)).unwrap();
        fork(&mut table, SHELL, CHILD);
        table
            .grant(
                DIRECT_CLIENT,
                instance(1),
                NETWORK_CLIENT_RIGHTS,
                Provenance::root(DIRECT_CLIENT),
            )
            .unwrap();
        assert_eq!(held(&table, CHILD), (1, 1));
        assert_eq!(occupied(&table), 5);

        for generation in 2..=1_000u64 {
            revoke_entitled_client_capabilities_in(&mut table);
            assert_eq!(held(&table, SHELL), (1, 0));
            assert_eq!(held(&table, CHILD), (1, 0));
            reissue_client_capabilities_in(&mut table, generation, |_, result| {
                assert!(result.is_ok())
            });
            for holder in [SHELL, CHILD] {
                assert_eq!(held(&table, holder), (1, 1), "generation {generation}");
                assert_eq!(client_generation(&table, holder), generation);
            }
            assert_eq!(occupied(&table), 5, "generation {generation}");
            assert_eq!(table.live_count(), 5);
        }
        // Holders without the entitlement keep exactly what they were granted.
        assert_eq!(held(&table, DIRECT_CLIENT), (0, 1));
        assert_eq!(client_generation(&table, DIRECT_CLIENT), 1);
    }

    /// The fork child's first client is derived from the parent's; revoking the parent's
    /// takes the child's with it, and the child's replacement is its own root grant.
    #[test]
    fn a_child_forked_before_a_restart_holds_its_own_client_after_it() {
        let mut table = CapabilityTable::<MAX_SLOTS>::new();
        grant_entitlement_in(&mut table, SHELL, Some(1)).unwrap();
        fork(&mut table, SHELL, CHILD);
        let derived = table.record_at(client_slot(&table, CHILD));
        assert_eq!(derived.provenance.depth, 1);

        revoke_entitled_client_capabilities_in(&mut table);
        reissue_client_capabilities_in(&mut table, 2, |_, result| assert!(result.is_ok()));
        let reissued = table.record_at(client_slot(&table, CHILD));
        assert_eq!(reissued.provenance.depth, 0);
        assert_eq!(reissued.resource, instance(2));

        // The parent exiting still revokes what the child inherited from it, as for every
        // inherited record (teardown revokes each of the parent's records with its
        // subtree); the child's own client survives it.
        for slot in 0..MAX_SLOTS {
            let record = table.record_at(slot);
            if record.state == CapabilityState::Live && record.holder == SHELL {
                let handle = table.handle_at(slot).unwrap();
                revoke_subtree(&mut table, handle).unwrap();
            }
        }
        assert_eq!(held(&table, CHILD), (0, 1));
    }

    #[test]
    fn a_failed_reissue_is_reported_for_its_holder() {
        let mut table = CapabilityTable::<2>::new();
        grant_entitlement_in(&mut table, SHELL, None).unwrap();
        grant_entitlement_in(&mut table, CHILD, None).unwrap();
        let mut results = std::vec::Vec::new();
        reissue_client_capabilities_in(&mut table, 1, |holder, result| {
            results.push((holder, result.map(|_| ())))
        });
        assert_eq!(
            results,
            [
                (SHELL, Err(CapabilityError::CapacityExhausted)),
                (CHILD, Err(CapabilityError::CapacityExhausted)),
            ]
        );
    }

    #[test]
    fn session_registry_capacity_reused_after_holder_clear() {
        let mut registry = NetworkSessionRegistry::new();
        let holder = HolderId(7);
        let handle = CapabilityHandle::new(3, 1);
        for index in 0..MAX_TRACKED_SESSIONS {
            registry
                .register(
                    holder,
                    SessionId::new(SessionGeneration::new(1), index as u32),
                    handle,
                )
                .expect("session insert");
        }
        assert!(registry
            .register(
                holder,
                SessionId::new(SessionGeneration::new(1), 42),
                handle
            )
            .is_err());
        assert_eq!(registry.clear_holder(holder), MAX_TRACKED_SESSIONS);
        for index in 0..MAX_TRACKED_SESSIONS {
            registry
                .register(
                    holder,
                    SessionId::new(SessionGeneration::new(2), index as u32),
                    handle,
                )
                .expect("session reinsert");
        }
    }
}
