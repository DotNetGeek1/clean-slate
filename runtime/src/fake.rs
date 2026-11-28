//! A host stand-in for the kernel, for host tests of runtime clients: syscall 17 runs on the
//! real port engine through `clean-slate-port`'s `fake` feature, syscall 16 keeps buffers in
//! host memory, console messages are recorded, and any call can be given a canned answer.

extern crate std;

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use clean_slate_capability::{HolderId, Rights};
use clean_slate_native_abi::desktop::SYSCALL_NR_IPC_SEND;
use clean_slate_native_abi::directory::is_entry_of;
use clean_slate_native_abi::net::{
    NetAddr, SYSCALL_NR_NETWORK_CAPABILITY, SYSCALL_NR_NETWORK_REQUEST,
};
use clean_slate_native_abi::object::{
    ObjectSubmitAt, OBJECT_OP_COMMIT, OBJECT_OP_READ_AT, OBJECT_OP_TRUNCATE, OBJECT_OP_WRITE_AT,
    OBJECT_SUBMIT_AT_BYTES, OBJECT_SUBOP_POLL, OBJECT_SUBOP_SUBMIT_AT, SYSCALL_NR_CAP_OBJECT,
};
use clean_slate_native_abi::port::{
    PORT_FRAME_BYTES, PORT_OP_BIND_EVENTS, PORT_OP_CLOSE, PORT_OP_CONNECT, PORT_OP_FIND_HANDLE,
    PORT_OP_RECV_EVENT, PORT_OP_SEND, PORT_RECV_NONBLOCK,
};
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_EINVAL, STATUS_ENOENT, STATUS_ENOSPC, STATUS_ENOSYS,
    STATUS_ESTALE,
};
use clean_slate_native_abi::work_set::SYSCALL_NR_WORK_SET;
use clean_slate_native_abi::{
    ConnectionId, PortEventRecord, PortParams, SharedBufferId, SHARED_BUFFER_SUBOP_ALLOCATE,
    SHARED_BUFFER_SUBOP_MAP, SHARED_BUFFER_SUBOP_RELEASE, SHARED_BUFFER_SUBOP_UNMAP,
    SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
};
use clean_slate_port::fake::{FakeConnection, FakePort, FAKE_RESOURCE, FAKE_SERVER};

use crate::Syscalls;

/// The client process under test.
pub const CLIENT: HolderId = HolderId(2);

struct Buffer {
    handle: u64,
    bytes: Vec<u8>,
    mapped: bool,
}

/// A persistent object the fake keeps: its staged bytes, and the bytes of the last commit.
struct FakeObject {
    id: u64,
    staged: Option<Vec<u8>>,
    committed: Option<Vec<u8>>,
}

/// The fake's object capability (syscall 8): grants, objects and completed requests.
#[derive(Default)]
struct FakeObjects {
    /// `(handle, object id, write right)`.
    grants: Vec<(u64, u64, bool)>,
    /// `(handle, directory id)`: read-write on the table and its entries.
    directories: Vec<(u64, u64)>,
    objects: Vec<FakeObject>,
    /// Objects whose epoch-bound capability is stale: every request polls `ESTALE`.
    gone: Vec<u64>,
    budget: Option<usize>,
    next_request: u64,
    /// `(request id, poll result, bytes read)`.
    done: Vec<(u64, u64, Vec<u8>)>,
    /// `(op, object id, offset, len)` of every submitted request.
    requests: Vec<(u64, u64, u64, u64)>,
}

pub struct FakeKernel {
    port: FakePort,
    client_cap: Option<u64>,
    connection: Option<FakeConnection>,
    buffers: Vec<Buffer>,
    next_buffer_slot: u16,
    canned: VecDeque<(u64, u64)>,
    calls: Vec<(u64, [u64; 6])>,
    console: Vec<Vec<u8>>,
    objects: FakeObjects,
    net: crate::fake_net::FakeNet,
    resources: FakeResources,
}

/// What syscall 28 `RESOURCES` answers (#379).
#[derive(Clone, Debug, Default)]
struct FakeResources {
    caller: u64,
    observer: bool,
    now_ns: u64,
    rows: Vec<clean_slate_native_abi::resources::ProcessRow>,
}

impl FakeResources {
    fn call(&self, args: [u64; 6]) -> u64 {
        use clean_slate_native_abi::resources::{
            rows_that_fit, snapshot_len, SnapshotHeader, RESOURCES_OP_SELF, RESOURCES_OP_SYSTEM,
            SNAPSHOT_FLAG_SYSTEM, SNAPSHOT_HEADER_BYTES,
        };
        use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL};

        if args[3..].iter().any(|arg| *arg != 0) {
            return STATUS_EINVAL;
        }
        let Some(max_rows) = rows_that_fit(args[2] as usize) else {
            return STATUS_EINVAL;
        };
        let system = match args[0] {
            RESOURCES_OP_SELF => false,
            RESOURCES_OP_SYSTEM if self.observer => true,
            RESOURCES_OP_SYSTEM => return STATUS_EACCES,
            _ => return STATUS_EINVAL,
        };
        let visible: Vec<_> = self
            .rows
            .iter()
            .filter(|row| system || row.pid == self.caller)
            .collect();
        let written = visible.len().min(max_rows);
        let busy: u64 = self.rows.iter().map(|row| row.cpu_ns).sum();
        let header = SnapshotHeader {
            flags: if system { SNAPSHOT_FLAG_SYSTEM } else { 0 },
            rows: written as u32,
            total_rows: visible.len() as u32,
            snapshot_ns: self.now_ns,
            elapsed_ns: if system { self.now_ns.max(busy) } else { 0 },
            busy_ns: if system { busy } else { 0 },
            idle_ns: if system {
                self.now_ns.max(busy) - busy
            } else {
                0
            },
            unattributed_ns: 0,
        };
        let mut bytes = Vec::from(header.encode());
        for row in visible.iter().take(written) {
            bytes.extend_from_slice(&row.encode());
        }
        debug_assert_eq!(bytes.len(), snapshot_len(written));
        debug_assert!(bytes.len() >= SNAPSHOT_HEADER_BYTES);
        // SAFETY: the client passes a live buffer of `args[2]` bytes, and `bytes` fits in it.
        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), args[1] as *mut u8, bytes.len());
        }
        bytes.len() as u64
    }
}

impl FakeKernel {
    pub fn new() -> Self {
        let mut kernel = Self::without_client_capability();
        kernel.client_cap = Some(kernel.port.add_client(CLIENT).expect("client capability"));
        kernel
    }

    pub fn without_client_capability() -> Self {
        Self {
            port: FakePort::new(PortParams {
                event_depth: 16,
                request_depth: 16,
                max_connections: 4,
                max_outstanding: 16,
                max_connections_per_holder: 1,
            })
            .expect("port"),
            client_cap: None,
            connection: None,
            buffers: Vec::new(),
            next_buffer_slot: 1,
            canned: VecDeque::new(),
            calls: Vec::new(),
            console: Vec::new(),
            objects: FakeObjects::default(),
            net: crate::fake_net::FakeNet::default(),
            resources: FakeResources::default(),
        }
    }

    /// #379: the processes `RESOURCES` reports. The caller is `caller`; with `observer` it
    /// holds the system observer grant and may read every row.
    pub fn resources(
        &mut self,
        caller: u64,
        observer: bool,
        rows: &[clean_slate_native_abi::resources::ProcessRow],
    ) {
        self.resources.caller = caller;
        self.resources.observer = observer;
        self.resources.rows = rows.to_vec();
    }

    /// The monotonic time the next snapshots are taken at.
    pub fn resources_at(&mut self, now_ns: u64) {
        self.resources.now_ns = now_ns;
    }

    /// Process `pid` has now run `cpu_ns` in all.
    pub fn resources_cpu(&mut self, pid: u64, cpu_ns: u64) {
        for row in self.resources.rows.iter_mut().filter(|row| row.pid == pid) {
            row.cpu_ns = cpu_ns;
        }
    }

    /// Gives the client the network client capability `handle` (#353); without it every
    /// network call is refused with `EACCES`. The fake's service may resolve names until
    /// [`Self::net_forbid_resolve`].
    pub fn net_grant(&mut self, handle: u64) {
        self.net.grant(handle);
    }

    /// The service's resolver answers `name` with `ip`.
    pub fn net_name(&mut self, name: &str, ip: [u8; 4]) {
        self.net.name(name, ip);
    }

    /// The client's policy may not resolve names.
    pub fn net_forbid_resolve(&mut self) {
        self.net.forbid_resolve();
    }

    /// The client's policy refuses `addr` (`NET_ERROR_DESTINATION_DENIED`).
    pub fn net_deny(&mut self, addr: NetAddr) {
        self.net.deny(addr);
    }

    /// A TCP peer at `addr` that sends `answer` once it has received `after` bytes, then closes
    /// its side when `close`. Streams to any other address fail to connect (`ETIMEDOUT`).
    pub fn net_tcp_peer(&mut self, addr: NetAddr, after: usize, answer: &[u8], close: bool) {
        self.net.tcp_peer(addr, after, answer, close);
    }

    /// A TLS peer at `addr` that answers any request with `answer`. An exchange with any other
    /// address fails (`ETIMEDOUT`).
    pub fn net_tls_peer(&mut self, addr: NetAddr, answer: &[u8]) {
        self.net.tls_peer(addr, answer);
    }

    /// A UDP peer at `addr` that echoes every datagram.
    pub fn net_udp_echo(&mut self, addr: NetAddr) {
        self.net.udp_echo(addr);
    }

    /// `addr` sends `bytes` on every stream connected to it.
    pub fn net_push(&mut self, addr: NetAddr, bytes: &[u8]) {
        self.net.push(addr, bytes);
    }

    /// The client's policy may not listen on `port` (#359).
    pub fn net_forbid_listen(&mut self, port: u16) {
        self.net.forbid_listen(port);
    }

    /// A peer at `peer` connects to local `port` (#359) and sends `bytes`; when `close`, it
    /// closes its side once the client has sent it as many bytes, as an echo client does (at once
    /// when `bytes` is empty). A
    /// listener on `port` takes it on its next accept.
    pub fn net_connect_in(&mut self, port: u16, peer: NetAddr, bytes: &[u8], close: bool) {
        self.net.connect_in(port, peer, bytes, close);
    }

    /// The network service restarts: its sessions go stale and the client capability becomes
    /// `new_handle`.
    pub fn net_restart(&mut self, new_handle: u64) {
        self.net.restart(new_handle);
    }

    /// #378: the client capability carries `NET_STATS`, and `STATS` answers `rows` with
    /// `untracked` requests from apps the table had no room for.
    pub fn net_stats(&mut self, rows: &[clean_slate_native_abi::net::NetAppStats], untracked: u32) {
        self.net.stats(rows, untracked);
    }

    /// Every byte the client sent to `addr`.
    pub fn net_sent_to(&self, addr: NetAddr) -> Vec<u8> {
        self.net.sent_to(addr)
    }

    /// Sessions the client has open with the service.
    pub fn net_open_sessions(&self) -> usize {
        self.net.open_sessions()
    }

    /// Requests the client submitted and has neither polled nor discarded.
    pub fn net_outstanding_requests(&self) -> usize {
        self.net.outstanding_requests()
    }

    /// What the policy refused, in order: a destination, or `None` for a name resolution.
    pub fn net_refusals(&self) -> &[Option<NetAddr>] {
        self.net.refusals()
    }

    /// Gives the client `handle`, authorising object `id` (`READ`, and `WRITE` when `write`).
    pub fn grant_object(&mut self, handle: u64, id: u64, write: bool) {
        self.objects.grants.retain(|grant| grant.0 != handle);
        self.objects.grants.push((handle, id, write));
    }

    /// Gives the client `handle` with `READ | WRITE | DIRECTORY` on directory `id`: the table
    /// and every entry object.
    pub fn grant_directory(&mut self, handle: u64, id: u64) {
        self.objects.grants.retain(|grant| grant.0 != handle);
        self.objects.directories.push((handle, id));
    }

    /// Object `id`'s bytes as staged, if it exists.
    pub fn object_staged(&self, id: u64) -> Option<&[u8]> {
        self.find_object(id)
            .and_then(|object| object.staged.as_deref())
    }

    /// Object `id`'s bytes as of the last commit, if it existed then.
    pub fn object_committed(&self, id: u64) -> Option<&[u8]> {
        self.find_object(id)
            .and_then(|object| object.committed.as_deref())
    }

    /// The store's live-byte budget: a write past it polls `ENOSPC`.
    pub fn set_object_budget(&mut self, bytes: usize) {
        self.objects.budget = Some(bytes);
    }

    /// Object `id` was deleted under the client's epoch-bound capability.
    pub fn object_gone(&mut self, id: u64) {
        self.objects.gone.push(id);
    }

    /// The storage service restarted, or the machine rebooted: everything staged since the
    /// last commit is forgotten, and buffers and requests are gone with the old process.
    pub fn restart_storage(&mut self) {
        for object in &mut self.objects.objects {
            object.staged = object.committed.clone();
        }
        self.objects.done.clear();
        self.buffers.clear();
    }

    /// `(op, object id, offset, len)` of every object request submitted.
    pub fn object_requests(&self) -> &[(u64, u64, u64, u64)] {
        &self.objects.requests
    }

    fn find_object(&self, id: u64) -> Option<&FakeObject> {
        self.objects.objects.iter().find(|object| object.id == id)
    }

    fn object_call(&mut self, args: [u64; 6]) -> u64 {
        match args[0] {
            OBJECT_SUBOP_SUBMIT_AT => {
                if args[3] != OBJECT_SUBMIT_AT_BYTES as u64 {
                    return STATUS_EINVAL;
                }
                // SAFETY: the client passes a pointer to a live descriptor.
                let bytes = unsafe {
                    std::slice::from_raw_parts(args[2] as *const u8, OBJECT_SUBMIT_AT_BYTES)
                };
                let Ok(submit) = ObjectSubmitAt::decode(bytes) else {
                    return STATUS_EINVAL;
                };
                let directory = self
                    .objects
                    .directories
                    .iter()
                    .find(|grant| grant.0 == args[1])
                    .map(|&(_, directory)| directory);
                let id = submit.object_id;
                if let Some(directory) = directory {
                    if id != directory && !is_entry_of(directory, id) {
                        return STATUS_EACCES;
                    }
                } else {
                    let Some(&(_, granted, write)) =
                        self.objects.grants.iter().find(|grant| grant.0 == args[1])
                    else {
                        return STATUS_EACCES;
                    };
                    if granted != id || (submit.op != OBJECT_OP_READ_AT && !write) {
                        return STATUS_EACCES;
                    }
                }
                let staged = if submit.buffer == 0 {
                    None
                } else {
                    let Some(index) = self.buffers.iter().position(|b| b.handle == submit.buffer)
                    else {
                        return STATUS_EACCES;
                    };
                    let start = submit.buffer_offset as usize;
                    let end = start + submit.len as usize;
                    if end > self.buffers[index].bytes.len() {
                        return STATUS_EINVAL;
                    }
                    Some((index, start, end))
                };
                let payload = if let Some((index, start, end)) = staged {
                    if submit.op == OBJECT_OP_WRITE_AT {
                        self.buffers[index].bytes[start..end].to_vec()
                    } else {
                        Vec::new()
                    }
                } else if submit.op == OBJECT_OP_WRITE_AT {
                    // SAFETY: the client passes `len` live bytes at `data`.
                    unsafe {
                        std::slice::from_raw_parts(submit.data as *const u8, submit.len as usize)
                    }
                    .to_vec()
                } else {
                    Vec::new()
                };
                self.objects
                    .requests
                    .push((submit.op, id, submit.offset, submit.len));
                let (mut result, mut read) = self.serve_object(&submit, &payload);
                if let Some((index, start, _)) = staged {
                    // The bytes moved through the buffer: the poll returns their count.
                    if submit.op == OBJECT_OP_READ_AT {
                        self.buffers[index].bytes[start..start + read.len()].copy_from_slice(&read);
                    } else if result == 0 {
                        result = submit.len;
                    }
                    read = Vec::new();
                }
                self.objects.next_request += 1;
                let request_id = self.objects.next_request;
                self.objects.done.push((request_id, result, read));
                request_id
            }
            OBJECT_SUBOP_POLL => {
                let Some(index) = self.objects.done.iter().position(|d| d.0 == args[1]) else {
                    return STATUS_EINVAL;
                };
                let (_, result, read) = self.objects.done.remove(index);
                if read.len() > args[2] as usize {
                    return STATUS_EINVAL;
                }
                // SAFETY: the client passes `args[2]` writable bytes at `args[3]`.
                unsafe {
                    std::ptr::copy_nonoverlapping(read.as_ptr(), args[3] as *mut u8, read.len());
                }
                result
            }
            _ => STATUS_EINVAL,
        }
    }

    /// Runs one request like the storage service: the poll result and the bytes read.
    fn serve_object(&mut self, submit: &ObjectSubmitAt, payload: &[u8]) -> (u64, Vec<u8>) {
        let id = submit.object_id;
        if self.objects.gone.contains(&id) {
            return (STATUS_ESTALE, Vec::new());
        }
        let live: usize = self
            .objects
            .objects
            .iter()
            .filter_map(|object| object.staged.as_ref().map(Vec::len))
            .sum();
        let index = match self.objects.objects.iter().position(|o| o.id == id) {
            Some(index) => index,
            None => {
                self.objects.objects.push(FakeObject {
                    id,
                    staged: None,
                    committed: None,
                });
                self.objects.objects.len() - 1
            }
        };
        let object = &mut self.objects.objects[index];
        let offset = submit.offset as usize;
        let current = object.staged.as_ref().map_or(0, Vec::len);
        let new_len = match submit.op {
            OBJECT_OP_WRITE_AT => current.max(offset + payload.len()),
            OBJECT_OP_TRUNCATE => offset,
            _ => current,
        };
        if new_len > current
            && self
                .objects
                .budget
                .is_some_and(|budget| live + new_len - current > budget)
        {
            return (STATUS_ENOSPC, Vec::new());
        }
        let object = &mut self.objects.objects[index];
        match submit.op {
            OBJECT_OP_READ_AT => match &object.staged {
                Some(bytes) => {
                    let start = offset.min(bytes.len());
                    let end = (start + submit.len as usize).min(bytes.len());
                    let read = bytes[start..end].to_vec();
                    (read.len() as u64, read)
                }
                None => (STATUS_ENOENT, Vec::new()),
            },
            OBJECT_OP_WRITE_AT | OBJECT_OP_TRUNCATE => {
                let bytes = object.staged.get_or_insert_with(Vec::new);
                bytes.resize(new_len, 0);
                if submit.op == OBJECT_OP_WRITE_AT {
                    bytes[offset..offset + payload.len()].copy_from_slice(payload);
                }
                (0, Vec::new())
            }
            OBJECT_OP_COMMIT => {
                for object in &mut self.objects.objects {
                    object.committed = object.staged.clone();
                }
                (0, Vec::new())
            }
            _ => (STATUS_EINVAL, Vec::new()),
        }
    }

    pub fn resource_id(&self) -> u64 {
        FAKE_RESOURCE.id
    }

    /// The next call to `nr` returns `value` instead of running.
    pub fn answer_next(&mut self, nr: u64, value: u64) {
        self.canned.push_back((nr, value));
    }

    pub fn last_call(&self) -> (u64, [u64; 6]) {
        *self.calls.last().expect("a call")
    }

    pub fn calls(&self) -> &[(u64, [u64; 6])] {
        &self.calls
    }

    pub fn console(&self) -> &[Vec<u8>] {
        &self.console
    }

    fn connection_id(&self) -> ConnectionId {
        self.connection.expect("connected").id()
    }

    /// The server's next request frame, if one is queued.
    pub fn server_recv_frame(&mut self) -> Option<[u8; PORT_FRAME_BYTES]> {
        self.port.server_recv().ok().map(|record| record.frame)
    }

    pub fn server_post(&mut self, frame: &[u8; PORT_FRAME_BYTES]) {
        let id = self.connection_id();
        self.port.server_post(id, frame).expect("post");
    }

    pub fn server_disconnect(&mut self, reason: u32) {
        let id = self.connection_id();
        self.port.server_disconnect(id, reason).expect("disconnect");
    }

    /// The server process exits.
    pub fn server_exit(&mut self) {
        self.port.exit_holder(FAKE_SERVER.holder);
    }

    /// Buffers allocated and not yet released.
    pub fn live_buffers(&self) -> usize {
        self.buffers.len()
    }

    pub fn mapped_buffers(&self) -> usize {
        self.buffers.iter().filter(|buffer| buffer.mapped).count()
    }

    fn port_call(&mut self, args: [u64; 6]) -> u64 {
        match args[0] {
            PORT_OP_FIND_HANDLE => self.client_cap.unwrap_or(STATUS_EINVAL),
            PORT_OP_CONNECT => match self.port.connect(CLIENT, args[1]) {
                Ok(connection) => {
                    self.connection = Some(connection);
                    connection.id().encode()
                }
                Err(status) => status,
            },
            PORT_OP_SEND => {
                let Some(connection) = self.connection.filter(|c| c.id().encode() == args[2])
                else {
                    return STATUS_EINVAL;
                };
                // SAFETY: the client passes a pointer to a live 64-byte frame.
                let frame = unsafe { *(args[3] as *const [u8; PORT_FRAME_BYTES]) };
                let transfer = (args[4] != 0).then_some(args[4]);
                status_or_zero(connection.send(&mut self.port, &frame, transfer))
            }
            PORT_OP_RECV_EVENT => {
                let Some(connection) = self.connection.filter(|c| c.id().encode() == args[2])
                else {
                    return STATUS_EINVAL;
                };
                if args[4] != PortEventRecord::BYTES as u64 {
                    return STATUS_EINVAL;
                }
                match connection.recv_event(&mut self.port) {
                    Ok(record) => {
                        // SAFETY: the client passes a pointer to a live 80-byte record.
                        unsafe {
                            *(args[3] as *mut [u8; PortEventRecord::BYTES]) = record.encode();
                        }
                        record.kind as u64
                    }
                    // The fake never blocks: an empty queue on a waiting receive is a test bug.
                    Err(STATUS_EAGAIN) if args[1] & PORT_RECV_NONBLOCK == 0 => {
                        panic!("blocking receive on an empty queue")
                    }
                    Err(status) => status,
                }
            }
            PORT_OP_CLOSE => {
                let Some(connection) = self.connection.filter(|c| c.id().encode() == args[2])
                else {
                    return STATUS_EINVAL;
                };
                status_or_zero(connection.close(&mut self.port, args[3] as u32))
            }
            // The fake has no work sets: a bind on the open connection is accepted and seen
            // only in `calls`.
            PORT_OP_BIND_EVENTS => match self.connection {
                Some(c) if c.id().encode() == args[2] && args[4] < 32 => 0,
                _ => STATUS_EINVAL,
            },
            _ => STATUS_EINVAL,
        }
    }

    fn buffer_call(&mut self, args: [u64; 6]) -> u64 {
        match args[0] {
            SHARED_BUFFER_SUBOP_ALLOCATE => {
                let len = args[2] as usize;
                let id = SharedBufferId::new(self.next_buffer_slot, 1).expect("buffer id");
                self.next_buffer_slot += 1;
                let handle = match self.port.grant_shared_buffer(
                    CLIENT,
                    id,
                    len as u64,
                    Rights::READ.union(Rights::DELEGATE),
                ) {
                    Ok(handle) => handle,
                    Err(status) => return status,
                };
                self.buffers.push(Buffer {
                    handle,
                    bytes: vec![0; len],
                    mapped: false,
                });
                handle
            }
            SHARED_BUFFER_SUBOP_MAP => {
                let Some(buffer) = self.buffers.iter_mut().find(|b| b.handle == args[1]) else {
                    return STATUS_EINVAL;
                };
                buffer.mapped = true;
                buffer.bytes.as_mut_ptr() as u64
            }
            SHARED_BUFFER_SUBOP_UNMAP => {
                let Some(buffer) = self
                    .buffers
                    .iter_mut()
                    .find(|b| b.mapped && b.bytes.as_ptr() as u64 == args[2])
                else {
                    return STATUS_EINVAL;
                };
                buffer.mapped = false;
                0
            }
            SHARED_BUFFER_SUBOP_RELEASE => {
                let Some(index) = self.buffers.iter().position(|b| b.handle == args[1]) else {
                    return STATUS_EINVAL;
                };
                if self.buffers[index].mapped {
                    return STATUS_EINVAL;
                }
                self.buffers.remove(index);
                0
            }
            _ => STATUS_EINVAL,
        }
    }
}

impl Default for FakeKernel {
    fn default() -> Self {
        Self::new()
    }
}

impl Syscalls for FakeKernel {
    fn syscall(&mut self, nr: u64, args: [u64; 6]) -> u64 {
        self.calls.push((nr, args));
        if let Some(&(canned_nr, value)) = self.canned.front() {
            if canned_nr == nr {
                self.canned.pop_front();
                return value;
            }
        }
        match nr {
            SYSCALL_NR_SERVICE_PORT => self.port_call(args),
            SYSCALL_NR_SHARED_BUFFER => self.buffer_call(args),
            SYSCALL_NR_CAP_OBJECT => self.object_call(args),
            SYSCALL_NR_NETWORK_CAPABILITY => self.net.capability_call(args),
            SYSCALL_NR_NETWORK_REQUEST => self.net.request_call(args),
            SYSCALL_NR_WORK_SET => 1,
            clean_slate_native_abi::resources::SYSCALL_NR_RESOURCES => self.resources.call(args),
            SYSCALL_NR_IPC_SEND => {
                // SAFETY: the client passes a live slice.
                let bytes =
                    unsafe { std::slice::from_raw_parts(args[1] as *const u8, args[2] as usize) };
                self.console.push(bytes.to_vec());
                args[2]
            }
            _ => STATUS_ENOSYS,
        }
    }
}

fn status_or_zero(result: Result<(), u64>) -> u64 {
    match result {
        Ok(()) => 0,
        Err(status) => status,
    }
}
