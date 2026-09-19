//! M7.7 network capability broker over the production M6 capability table.

#![cfg_attr(not(feature = "m7-net-caps-self-test"), allow(dead_code))]

use core::fmt::{self, Write};

use clean_slate_capability::{
    revoke_subtree, CapabilityError, CapabilityHandle, CapabilityState, HolderId, ResourceClass,
    ResourceRef, Rights,
};
use clean_slate_network::error::DenialReason;
use clean_slate_network::session::{SessionGeneration, SessionId};
use clean_slate_service_lifecycle::ServiceId;

use crate::diagnostics::log::kernel_log_fmt;
use crate::service::instance_generation::live_network_service_generation;
use crate::sync::global_cell::GlobalCell;

use super::audit::record_decision;
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
        NetworkGrantPolicy::Application => sanitize_application_rights(rights)?,
        NetworkGrantPolicy::NetworkService => {
            if !rights.is_subset_of(Rights::valid_for(ResourceClass::Network)) {
                return Err(CapabilityError::InvalidRights);
            }
            rights
        }
    };
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
        table.authorize(trusted_holder, handle, live_resource, required)
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
    let _ = revoke_subtree(table, handle);
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
