//! Host-side stand-in for syscall 17 `SERVICE_PORT`, driving the same [`PortCore`] engine.

use clean_slate_capability::{
    revoke_holder_tree, CapabilityHandle, CapabilityTable, HolderId, Provenance, ResourceClass,
    ResourceRef, Rights,
};
use clean_slate_native_abi::status::{STATUS_EINVAL, STATUS_ENOSPC, STATUS_ESTALE};
use clean_slate_native_abi::{
    ConnectionId, PortEventRecord, PortParams, PortRecvRecord, SharedBufferId,
};

use crate::{Caller, Effects, PortCore, PortCounts, PortReleaseCounts, Transfer};

pub const FAKE_CONNECTIONS: usize = 16;
pub const FAKE_CAPS: usize = 64;
pub const FAKE_FIXTURES: usize = 16;

/// The fake compositor process.
pub const FAKE_SERVER: Caller = Caller {
    holder: HolderId(1),
    generation: 1,
    domain: 1,
};

pub const FAKE_RESOURCE: ResourceRef = ResourceRef::graphics(1, 1);

/// Stand-in for the kernel's work-set binding; [`crate::Effect::Signal`] carries it.
pub type FakeWake = u32;

pub struct FakePort {
    core: PortCore<1, FAKE_CONNECTIONS, FakeWake>,
    table: CapabilityTable<FAKE_CAPS>,
    fixtures: [Option<(SharedBufferId, u64)>; FAKE_FIXTURES],
    effects: Effects<FakeWake>,
    serve: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeConnection {
    holder: HolderId,
    id: ConnectionId,
}

impl FakeConnection {
    pub const fn id(self) -> ConnectionId {
        self.id
    }

    pub const fn holder(self) -> HolderId {
        self.holder
    }

    pub fn send(
        self,
        port: &mut FakePort,
        frame: &[u8; 64],
        transfer: Option<u64>,
    ) -> Result<(), u64> {
        port.effects.clear();
        let transfer = match transfer {
            None => None,
            Some(raw) => {
                let handle = CapabilityHandle::decode(raw).map_err(|_| STATUS_EINVAL)?;
                Some(Transfer {
                    handle,
                    attestation: port.attest_transfer(handle),
                })
            }
        };
        port.core
            .send(
                &mut port.table,
                FakePort::caller(self.holder),
                self.id.encode(),
                frame,
                transfer,
                &mut port.effects,
            )
            .map_err(|error| error.status())
    }

    pub fn recv_event(self, port: &mut FakePort) -> Result<PortEventRecord, u64> {
        port.effects.clear();
        port.core
            .recv_event(
                &mut port.table,
                FakePort::caller(self.holder),
                self.id.encode(),
                &mut port.effects,
            )
            .map_err(|error| error.status())
    }

    pub fn close(self, port: &mut FakePort, reason: u32) -> Result<(), u64> {
        port.effects.clear();
        port.core
            .close(
                &mut port.table,
                FakePort::caller(self.holder),
                self.id.encode(),
                reason,
                &mut port.effects,
            )
            .map_err(|error| error.status())
    }
}

impl FakePort {
    pub fn new(params: PortParams) -> Result<Self, u64> {
        let mut core = PortCore::new();
        core.register(
            FAKE_RESOURCE,
            FAKE_SERVER.holder,
            FAKE_SERVER.generation,
            params,
        )
        .map_err(|_| STATUS_EINVAL)?;
        let mut table = CapabilityTable::new();
        let serve = grant_capability(
            &mut table,
            FAKE_SERVER.holder,
            FAKE_RESOURCE,
            Rights::GFX_SERVE,
        )?;
        Ok(Self {
            core,
            table,
            fixtures: [None; FAKE_FIXTURES],
            effects: Effects::new(),
            serve,
        })
    }

    pub const fn caller(holder: HolderId) -> Caller {
        Caller {
            holder,
            generation: 1,
            domain: holder.0,
        }
    }

    pub fn add_client(&mut self, holder: HolderId) -> Result<u64, u64> {
        grant_capability(&mut self.table, holder, FAKE_RESOURCE, Rights::GFX_CONNECT)
    }

    pub fn grant_shared_buffer(
        &mut self,
        holder: HolderId,
        id: SharedBufferId,
        byte_len: u64,
        rights: Rights,
    ) -> Result<u64, u64> {
        self.reserve_fixture(id, byte_len)?;
        let resource = ResourceRef::shared_buffer(id.encode());
        grant_capability(&mut self.table, holder, resource, rights)
    }

    pub fn connect(&mut self, holder: HolderId, handle: u64) -> Result<FakeConnection, u64> {
        self.effects.clear();
        let id = self
            .core
            .connect(
                &self.table,
                Self::caller(holder),
                handle,
                ResourceClass::Graphics as u64,
                FAKE_RESOURCE.id,
            )
            .map_err(|error| error.status())?;
        Ok(FakeConnection { holder, id })
    }

    pub fn server_recv(&mut self) -> Result<PortRecvRecord, u64> {
        self.effects.clear();
        self.core
            .recv(&self.table, FAKE_SERVER, self.serve, &mut self.effects)
            .map_err(|error| error.status())
    }

    pub fn server_post(&mut self, connection: ConnectionId, frame: &[u8; 64]) -> Result<(), u64> {
        self.effects.clear();
        self.core
            .post(
                &self.table,
                FAKE_SERVER,
                self.serve,
                connection.encode(),
                frame,
                &mut self.effects,
            )
            .map_err(|error| error.status())
    }

    pub fn server_disconnect(&mut self, connection: ConnectionId, reason: u32) -> Result<(), u64> {
        self.effects.clear();
        self.core
            .disconnect(
                &mut self.table,
                FAKE_SERVER,
                self.serve,
                connection.encode(),
                reason,
                &mut self.effects,
            )
            .map_err(|error| error.status())
    }

    pub fn server_bind_wake(
        &mut self,
        target: FakeWake,
        request_bit: u32,
        notice_bit: u32,
    ) -> Result<(), u64> {
        self.effects.clear();
        self.core
            .bind_wake(
                &self.table,
                FAKE_SERVER,
                self.serve,
                target,
                request_bit,
                notice_bit,
                &mut self.effects,
            )
            .map_err(|error| error.status())
    }

    pub fn exit_holder(&mut self, holder: HolderId) -> PortReleaseCounts {
        self.effects.clear();
        let counts = self
            .core
            .on_holder_exit(&mut self.table, holder, &mut self.effects);
        revoke_holder_tree(&mut self.table, holder);
        counts
    }

    pub fn effects(&self) -> &Effects<FakeWake> {
        &self.effects
    }

    pub fn table(&self) -> &CapabilityTable<FAKE_CAPS> {
        &self.table
    }

    pub fn counts(&self) -> PortCounts {
        self.core.global_counts()
    }

    fn attest_transfer(&self, handle: CapabilityHandle) -> Result<(SharedBufferId, u64), u64> {
        let record = self.table.record(handle).map_err(|_| STATUS_ESTALE)?;
        let buffer_id = SharedBufferId::decode(record.resource.id).map_err(|_| STATUS_ESTALE)?;
        for entry in self.fixtures.iter().flatten() {
            if entry.0 == buffer_id {
                return Ok((buffer_id, entry.1));
            }
        }
        Err(STATUS_ESTALE)
    }

    fn reserve_fixture(&mut self, id: SharedBufferId, byte_len: u64) -> Result<(), u64> {
        for entry in &mut self.fixtures {
            if let Some((existing, _)) = entry {
                if *existing == id {
                    *entry = Some((id, byte_len));
                    return Ok(());
                }
            }
        }
        for entry in &mut self.fixtures {
            if entry.is_none() {
                *entry = Some((id, byte_len));
                return Ok(());
            }
        }
        Err(STATUS_ENOSPC)
    }
}

fn grant_capability(
    table: &mut CapabilityTable<FAKE_CAPS>,
    holder: HolderId,
    resource: ResourceRef,
    rights: Rights,
) -> Result<u64, u64> {
    table
        .grant(holder, resource, rights, Provenance::root(holder))
        .map(|handle| handle.encode())
        .map_err(|_| STATUS_ENOSPC)
}

#[cfg(test)]
mod tests {
    use clean_slate_capability::CapabilityHandle;
    use clean_slate_native_abi::status::{STATUS_EAGAIN, STATUS_ECONNREFUSED, STATUS_ESTALE};
    use clean_slate_native_abi::{EventKind, PortParams, RecvKind};

    use super::*;

    #[test]
    fn two_clients_exchange_requests_and_events() {
        let mut port = FakePort::new(PortParams {
            event_depth: 2,
            request_depth: 4,
            max_connections: 3,
            max_outstanding: 2,
            max_connections_per_holder: 1,
        })
        .unwrap();

        let cap2 = port.add_client(HolderId(2)).unwrap();
        let cap3 = port.add_client(HolderId(3)).unwrap();
        let client2 = port.connect(HolderId(2), cap2).unwrap();
        let client3 = port.connect(HolderId(3), cap3).unwrap();

        client2.send(&mut port, &[1; 64], None).unwrap();
        client3.send(&mut port, &[2; 64], None).unwrap();

        let first = port.server_recv().unwrap();
        assert_eq!(first.kind, RecvKind::Request);
        assert_eq!(first.envelope.pid, 2);
        assert_eq!(first.envelope.connection, client2.id());
        assert_eq!(first.frame, [1; 64]);

        let second = port.server_recv().unwrap();
        assert_eq!(second.kind, RecvKind::Request);
        assert_eq!(second.envelope.pid, 3);
        assert_eq!(second.envelope.connection, client3.id());
        assert_eq!(second.frame, [2; 64]);

        port.server_post(client3.id(), &[9; 64]).unwrap();

        let event3 = client3.recv_event(&mut port).unwrap();
        assert_eq!(event3.kind, EventKind::Frame);
        assert_eq!(event3.frame, [9; 64]);

        assert_eq!(client2.recv_event(&mut port), Err(STATUS_EAGAIN));

        let buffer_id = SharedBufferId::new(1, 1).unwrap();
        let buf_cap = port
            .grant_shared_buffer(
                HolderId(2),
                buffer_id,
                4096,
                Rights::READ.union(Rights::DELEGATE),
            )
            .unwrap();
        client2.send(&mut port, &[1; 64], Some(buf_cap)).unwrap();

        let xfer_recv = port.server_recv().unwrap();
        let transfer = xfer_recv.envelope.transfer.expect("transfer present");
        assert_eq!(transfer.byte_len, 4096);
        assert_eq!(
            SharedBufferId::decode(transfer.buffer_id).unwrap(),
            buffer_id
        );

        let child = CapabilityHandle::decode(transfer.handle).unwrap();
        let record = port.table().record(child).unwrap();
        assert_eq!(record.holder, FAKE_SERVER.holder);
    }

    #[test]
    fn server_exit_reports_server_gone() {
        let mut port = FakePort::new(PortParams {
            event_depth: 2,
            request_depth: 4,
            max_connections: 3,
            max_outstanding: 2,
            max_connections_per_holder: 1,
        })
        .unwrap();

        let cap = port.add_client(HolderId(2)).unwrap();
        let client = port.connect(HolderId(2), cap).unwrap();

        let counts = port.exit_holder(FAKE_SERVER.holder);
        assert_eq!(counts.served_ports, 1);

        let event = client.recv_event(&mut port).unwrap();
        assert_eq!(event.kind, EventKind::ServerGone);

        assert_eq!(client.recv_event(&mut port), Err(STATUS_ESTALE));

        let fresh = port.add_client(HolderId(3)).unwrap();
        assert_eq!(port.connect(HolderId(3), fresh), Err(STATUS_ECONNREFUSED));

        assert_eq!(port.counts(), PortCounts::default());
    }
}
