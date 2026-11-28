//! The network client (#353): name resolution, TCP streams, connected UDP sockets and TLS
//! exchanges through the network service, over syscalls 14 and 15
//! (`clean_slate_native_abi::net`).
//!
//! A program needs `Grant::NativeNetworkClient` on its manifest row, and what it may reach is
//! its row's network policy: a destination the policy refuses fails with
//! [`Error::Failed`]`(STATUS_EACCES)`, and the refusal is in the audit log. When the network
//! service restarts, every open socket fails with [`Error::Gone`] (or `Failed(STATUS_EACCES)`
//! while no instance is running); open new ones. Each call asks the kernel for the current
//! client capability, which a restart replaces, so nothing here holds a stale handle.
//!
//! Every call that waits for the network takes a [`Deadline`]; a call that reaches it fails with
//! [`Error::TimedOut`]. A [`TcpStream::read`] or [`UdpSocket::recv`] that timed out leaves its
//! receive with the service, so bytes that arrive later are returned by the next read rather
//! than lost.
//!
//! The service holds no state a program has to free on exit: a process's sockets are closed
//! when it exits. A long-running program should still [`TcpStream::close`] what it is done with,
//! since the service's tables are bounded.

use clean_slate_native_abi::net::{
    net_error_status, NetRequest, NetResponse, NETWORK_CAPABILITY_VERSION,
    NETWORK_CLIENT_DEVICE_ID, NET_FRAME_BYTES, NET_MAX_PAYLOAD_BYTES, NET_SOCKET_DATAGRAM,
    NET_SOCKET_STREAM, NET_SOCKET_TLS_EXCHANGE, NET_SUBOP_DISCARD, NET_SUBOP_POLL,
    NET_SUBOP_SUBMIT, NET_SUBOP_WAIT, SYSCALL_NR_NETWORK_CAPABILITY, SYSCALL_NR_NETWORK_REQUEST,
};
use clean_slate_native_abi::status::STATUS_EINVAL;

pub use clean_slate_native_abi::net::{NetAddr, NET_MAX_HOSTNAME_BYTES};

use crate::port::Deadline;
use crate::{Error, Syscalls};

/// The client capability's handle: what every request is checked against. A network-service
/// restart revokes it and issues another, so it is looked up for each call rather than kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Client(u64);

impl Client {
    fn get<S: Syscalls>(sys: &mut S) -> Result<Self, Error> {
        sys.call(
            SYSCALL_NR_NETWORK_CAPABILITY,
            [
                NETWORK_CLIENT_DEVICE_ID,
                u64::from(NETWORK_CAPABILITY_VERSION),
                0,
                0,
                0,
                0,
            ],
        )
        .map(Self)
    }

    fn submit<S: Syscalls>(
        self,
        sys: &mut S,
        request: NetRequest<'_>,
        payload: &[u8],
    ) -> Result<u64, Error> {
        let frame = request.encode().map_err(|_| Error::Failed(STATUS_EINVAL))?;
        sys.call(
            SYSCALL_NR_NETWORK_REQUEST,
            [
                NET_SUBOP_SUBMIT,
                self.0,
                frame.as_ptr() as u64,
                payload.as_ptr() as u64,
                payload.len() as u64,
                0,
            ],
        )
    }

    /// Waits for `id` to complete; `Err(TimedOut)` leaves it outstanding.
    fn wait<S: Syscalls>(self, sys: &mut S, id: u64, deadline: Deadline) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_NETWORK_REQUEST,
            [NET_SUBOP_WAIT, self.0, id, deadline.raw(), 0, 0],
        )
        .map(|_| ())
    }

    /// Takes the completed `id`'s response, its payload copied into `out`.
    fn poll<S: Syscalls>(self, sys: &mut S, id: u64, out: &mut [u8]) -> Result<NetResponse, Error> {
        let mut frame = [0u8; NET_FRAME_BYTES];
        sys.call(
            SYSCALL_NR_NETWORK_REQUEST,
            [
                NET_SUBOP_POLL,
                self.0,
                id,
                frame.as_mut_ptr() as u64,
                out.as_mut_ptr() as u64,
                out.len() as u64,
            ],
        )?;
        match NetResponse::decode(&frame) {
            Ok(NetResponse::Error { code }) => Err(Error::from_status(net_error_status(code))),
            Ok(response) => Ok(response),
            Err(_) => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    fn discard<S: Syscalls>(self, sys: &mut S, id: u64) {
        // Only a request the caller no longer has fails, and then there is nothing to drop.
        let _ = sys.call(
            SYSCALL_NR_NETWORK_REQUEST,
            [NET_SUBOP_DISCARD, self.0, id, 0, 0, 0],
        );
    }

    /// Submits `request` and returns its response. A request that reaches `deadline` is
    /// discarded: the service still finishes it, and nobody reads the answer.
    fn exchange<S: Syscalls>(
        self,
        sys: &mut S,
        request: NetRequest<'_>,
        payload: &[u8],
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<NetResponse, Error> {
        let id = self.submit(sys, request, payload)?;
        if let Err(error) = self.wait(sys, id, deadline) {
            self.discard(sys, id);
            return Err(error);
        }
        self.poll(sys, id, out)
    }

    fn open<S: Syscalls>(self, sys: &mut S, kind: u8) -> Result<u64, Error> {
        match self.exchange(
            sys,
            NetRequest::Open { kind },
            &[],
            &mut [],
            Deadline::NEVER,
        )? {
            NetResponse::Open { session } => Ok(session),
            _ => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    /// Opens a `kind` session connected to `peer`; a session whose connect fails is closed.
    fn open_connected<S: Syscalls>(
        self,
        sys: &mut S,
        kind: u8,
        peer: NetAddr,
        deadline: Deadline,
    ) -> Result<u64, Error> {
        let session = self.open(sys, kind)?;
        let connected = self.exchange(
            sys,
            NetRequest::Connect { session, peer },
            &[],
            &mut [],
            deadline,
        );
        match connected {
            Ok(NetResponse::Connect) => Ok(session),
            Ok(_) => {
                self.close(sys, session);
                Err(Error::Failed(STATUS_EINVAL))
            }
            Err(error) => {
                self.close(sys, session);
                Err(error)
            }
        }
    }

    /// Closes `session`; a close that fails leaves nothing more to do.
    fn close<S: Syscalls>(self, sys: &mut S, session: u64) {
        let _ = self.exchange(
            sys,
            NetRequest::Close { session },
            &[],
            &mut [],
            Deadline::NEVER,
        );
    }
}

/// Resolves `name` (ASCII, at most [`NET_MAX_HOSTNAME_BYTES`]) to an IPv4 address through the
/// service's resolver. A name the resolver does not know fails with `Failed(STATUS_ENOENT)`.
pub fn resolve<S: Syscalls>(sys: &mut S, name: &str, deadline: Deadline) -> Result<[u8; 4], Error> {
    let client = Client::get(sys)?;
    let request = NetRequest::Resolve {
        name: name.as_bytes(),
    };
    match client.exchange(sys, request, &[], &mut [], deadline)? {
        NetResponse::Resolve { ip, .. } => Ok(ip),
        _ => Err(Error::Failed(STATUS_EINVAL)),
    }
}

/// Bytes received and not yet read, and the receive the service holds for more.
struct Inbox {
    bytes: [u8; NET_MAX_PAYLOAD_BYTES],
    start: usize,
    end: usize,
    pending: Option<u64>,
}

impl Inbox {
    const fn new() -> Self {
        Self {
            bytes: [0; NET_MAX_PAYLOAD_BYTES],
            start: 0,
            end: 0,
            pending: None,
        }
    }

    fn take(&mut self, out: &mut [u8]) -> usize {
        let len = out.len().min(self.end - self.start);
        out[..len].copy_from_slice(&self.bytes[self.start..self.start + len]);
        self.start += len;
        len
    }

    /// Fills the inbox from one receive: the one left outstanding, or a new one. Returns the
    /// bytes received, 0 at the end of a stream.
    fn fill<S: Syscalls>(
        &mut self,
        sys: &mut S,
        client: Client,
        session: u64,
        deadline: Deadline,
    ) -> Result<usize, Error> {
        let id = match self.pending {
            Some(id) => id,
            None => {
                let request = NetRequest::Receive {
                    session,
                    max_len: NET_MAX_PAYLOAD_BYTES as u32,
                };
                let id = client.submit(sys, request, &[])?;
                self.pending = Some(id);
                id
            }
        };
        client.wait(sys, id, deadline)?;
        self.pending = None;
        match client.poll(sys, id, &mut self.bytes)? {
            NetResponse::Receive { len } => {
                let len = (len as usize).min(self.bytes.len());
                self.start = 0;
                self.end = len;
                Ok(len)
            }
            _ => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    /// Drops the outstanding receive, if any; the session's close cancels it in the service.
    fn abandon<S: Syscalls>(&mut self, sys: &mut S, client: Client) {
        if let Some(id) = self.pending.take() {
            client.discard(sys, id);
        }
    }
}

/// A TCP connection.
pub struct TcpStream {
    session: u64,
    inbox: Inbox,
    eof: bool,
}

impl TcpStream {
    /// Connects to `peer`; the handshake has completed on success.
    pub fn connect<S: Syscalls>(
        sys: &mut S,
        peer: NetAddr,
        deadline: Deadline,
    ) -> Result<Self, Error> {
        let client = Client::get(sys)?;
        let session = client.open_connected(sys, NET_SOCKET_STREAM, peer, deadline)?;
        Ok(Self {
            session,
            inbox: Inbox::new(),
            eof: false,
        })
    }

    /// Sends some of `data`, at most [`NET_MAX_PAYLOAD_BYTES`]; returns how many bytes the
    /// connection took, which may be 0 while its send window is full.
    pub fn write<S: Syscalls>(&mut self, sys: &mut S, data: &[u8]) -> Result<usize, Error> {
        let chunk = &data[..data.len().min(NET_MAX_PAYLOAD_BYTES)];
        let request = NetRequest::Send {
            session: self.session,
            len: chunk.len() as u32,
        };
        match Client::get(sys)?.exchange(sys, request, chunk, &mut [], Deadline::NEVER)? {
            NetResponse::Send { accepted } => Ok((accepted as usize).min(chunk.len())),
            _ => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    /// Sends all of `data`, retrying while the send window is full, until `deadline`.
    pub fn write_all<S: Syscalls>(
        &mut self,
        sys: &mut S,
        mut data: &[u8],
        deadline: Deadline,
    ) -> Result<(), Error> {
        while !data.is_empty() {
            let sent = self.write(sys, data)?;
            if sent == 0 && deadline != Deadline::NEVER && crate::port::now(sys)? >= deadline.raw()
            {
                return Err(Error::TimedOut);
            }
            data = &data[sent..];
        }
        Ok(())
    }

    /// Reads into `out`; returns the bytes read, 0 once the peer has closed its side.
    pub fn read<S: Syscalls>(
        &mut self,
        sys: &mut S,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<usize, Error> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.inbox.start == self.inbox.end {
            if self.eof {
                return Ok(0);
            }
            let client = Client::get(sys)?;
            if self.inbox.fill(sys, client, self.session, deadline)? == 0 {
                self.eof = true;
                return Ok(0);
            }
        }
        Ok(self.inbox.take(out))
    }

    /// Reads until `out` is full or the peer closes; returns the bytes read.
    pub fn read_to_end<S: Syscalls>(
        &mut self,
        sys: &mut S,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<usize, Error> {
        let mut done = 0;
        while done < out.len() {
            let read = self.read(sys, &mut out[done..], deadline)?;
            if read == 0 {
                break;
            }
            done += read;
        }
        Ok(done)
    }

    /// Closes the connection.
    pub fn close<S: Syscalls>(mut self, sys: &mut S) {
        if let Ok(client) = Client::get(sys) {
            self.inbox.abandon(sys, client);
            client.close(sys, self.session);
        }
    }
}

/// A UDP socket connected to one peer.
pub struct UdpSocket {
    session: u64,
    inbox: Inbox,
}

impl UdpSocket {
    /// Opens a socket on an ephemeral port that sends to, and receives from, `peer` only.
    pub fn connect<S: Syscalls>(sys: &mut S, peer: NetAddr) -> Result<Self, Error> {
        let client = Client::get(sys)?;
        let session = client.open_connected(sys, NET_SOCKET_DATAGRAM, peer, Deadline::NEVER)?;
        Ok(Self {
            session,
            inbox: Inbox::new(),
        })
    }

    /// Sends one datagram.
    pub fn send<S: Syscalls>(&mut self, sys: &mut S, datagram: &[u8]) -> Result<(), Error> {
        if datagram.len() > NET_MAX_PAYLOAD_BYTES {
            return Err(Error::Failed(STATUS_EINVAL));
        }
        let request = NetRequest::Send {
            session: self.session,
            len: datagram.len() as u32,
        };
        match Client::get(sys)?.exchange(sys, request, datagram, &mut [], Deadline::NEVER)? {
            NetResponse::Send { .. } => Ok(()),
            _ => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    /// Receives one datagram into `out`; returns its length. A datagram longer than `out` is
    /// cut to fit.
    pub fn recv<S: Syscalls>(
        &mut self,
        sys: &mut S,
        out: &mut [u8],
        deadline: Deadline,
    ) -> Result<usize, Error> {
        let client = Client::get(sys)?;
        self.inbox.fill(sys, client, self.session, deadline)?;
        let len = self.inbox.take(out);
        self.inbox.start = self.inbox.end;
        Ok(len)
    }

    pub fn close<S: Syscalls>(mut self, sys: &mut S) {
        if let Ok(client) = Client::get(sys) {
            self.inbox.abandon(sys, client);
            client.close(sys, self.session);
        }
    }
}

/// One TLS request and response with `peer`: connects, verifies the peer's certificate chain
/// against the network service's trust anchors and its configured server name, sends `request`
/// (at most [`NET_MAX_PAYLOAD_BYTES`]) and reads the answer until the peer closes. Returns the
/// answer's length; `response` holds as much of it as fits. A failed handshake, a peer the
/// service does not trust, or an exchange that outlasts the service's own budget fails with
/// [`Error::TimedOut`].
pub fn tls_exchange<S: Syscalls>(
    sys: &mut S,
    peer: NetAddr,
    request: &[u8],
    response: &mut [u8],
    deadline: Deadline,
) -> Result<usize, Error> {
    if request.len() > NET_MAX_PAYLOAD_BYTES {
        return Err(Error::Failed(STATUS_EINVAL));
    }
    let client = Client::get(sys)?;
    let session = client.open_connected(sys, NET_SOCKET_TLS_EXCHANGE, peer, deadline)?;
    let result = tls_send_and_receive(sys, client, session, request, response, deadline);
    client.close(sys, session);
    result
}

fn tls_send_and_receive<S: Syscalls>(
    sys: &mut S,
    client: Client,
    session: u64,
    request: &[u8],
    response: &mut [u8],
    deadline: Deadline,
) -> Result<usize, Error> {
    let send = NetRequest::Send {
        session,
        len: request.len() as u32,
    };
    client.exchange(sys, send, request, &mut [], deadline)?;
    let mut answer = Inbox::new();
    let filled = answer.fill(sys, client, session, deadline);
    answer.abandon(sys, client);
    let len = filled?;
    answer.take(response);
    Ok(len)
}

#[cfg(test)]
mod tests;
