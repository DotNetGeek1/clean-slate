//! A compositor client: one port connection to the compositor, `N` shared pixel buffers, and
//! the request and event frames of the #110 surface protocol.
//!
//! Sessions (the playground's, the desktop shell's) decide what to say; this client says it.
//! It tags requests, sends a buffer's capability along with the request that registers it,
//! decodes events, and reports the compositor ending as [`Error::Gone`].

use clean_slate_capability::ResourceClass;
use clean_slate_graphics::protocol::{Event, Request};
use clean_slate_native_abi::status::STATUS_EINVAL;

use crate::buffer::SharedBuffer;
use crate::port::{Connection, Deadline, Wait};
use crate::{Error, Syscalls};

/// Close reason sent when the client ends the connection itself.
pub const CLOSE_REASON_DONE: u32 = 0;

pub struct CompositorClient<S: Syscalls, const N: usize> {
    sys: S,
    connection: Connection,
    next_tag: u32,
    buffers: [Option<SharedBuffer>; N],
}

impl<S: Syscalls, const N: usize> CompositorClient<S, N> {
    /// Connects to the compositor port `resource_id` with the caller's graphics capability.
    pub fn connect(mut sys: S, resource_id: u64) -> Result<Self, Error> {
        let connection = Connection::connect(&mut sys, ResourceClass::Graphics, resource_id)?;
        Ok(Self {
            sys,
            connection,
            next_tag: 1,
            buffers: [const { None }; N],
        })
    }

    /// The syscalls, for calls outside the compositor protocol.
    pub fn sys(&mut self) -> &mut S {
        &mut self.sys
    }

    pub const fn connection(&self) -> Connection {
        self.connection
    }

    /// Allocates and maps buffer `slot` with at least `byte_len` bytes, replacing (and
    /// releasing) any buffer already there.
    pub fn allocate(&mut self, slot: usize, byte_len: usize) -> Result<(), Error> {
        let entry = self
            .buffers
            .get_mut(slot)
            .ok_or(Error::Failed(STATUS_EINVAL))?;
        if let Some(old) = entry.take() {
            let _ = old.release(&mut self.sys);
        }
        *entry = Some(SharedBuffer::allocate(&mut self.sys, byte_len)?);
        Ok(())
    }

    /// Sends `request`. `transfer` names the buffer whose capability travels with it
    /// (`RegisterBuffer`); waits as long as the queue is full.
    pub fn send(&mut self, request: &Request, transfer: Option<usize>) -> Result<(), Error> {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        let frame = request
            .encode(tag)
            .map_err(|_| Error::Failed(STATUS_EINVAL))?;
        let transfer = match transfer {
            Some(slot) => Some(
                self.buffers
                    .get(slot)
                    .and_then(Option::as_ref)
                    .ok_or(Error::Failed(STATUS_EINVAL))?
                    .handle(),
            ),
            None => None,
        };
        self.connection
            .send(&mut self.sys, &frame, transfer, Deadline::NEVER)
    }

    /// The mapped bytes of buffer `slot`.
    pub fn pixels(&mut self, slot: usize) -> Option<&mut [u8]> {
        self.buffers
            .get_mut(slot)
            .and_then(Option::as_mut)
            .map(SharedBuffer::bytes)
    }

    /// The next event. Frames that do not decode are skipped; a disconnect or compositor exit
    /// is [`Error::Gone`].
    pub fn next_event(&mut self, wait: Wait) -> Result<Event, Error> {
        loop {
            let frame = self.connection.recv_frame(&mut self.sys, wait)?;
            if let Ok(tagged) = Event::decode(&frame) {
                return Ok(tagged.message);
            }
        }
    }

    /// Closes the connection, then unmaps and releases every buffer.
    pub fn shut_down(&mut self) {
        let _ = self.connection.close(&mut self.sys, CLOSE_REASON_DONE);
        for slot in &mut self.buffers {
            if let Some(buffer) = slot.take() {
                let _ = buffer.release(&mut self.sys);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_graphics::protocol::{
        Features, ProtocolVersion, PROTOCOL_MAJOR, PROTOCOL_MINOR,
    };

    type Client = CompositorClient<FakeKernel, 2>;

    fn connect() -> Client {
        let sys = FakeKernel::new();
        let id = sys.resource_id();
        Client::connect(sys, id).expect("connect")
    }

    fn hello() -> Request {
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        }
    }

    #[test]
    fn requests_are_tagged_in_order() {
        let mut client = connect();
        client.send(&hello(), None).expect("send");
        client.send(&hello(), None).expect("send");
        for expected in [1, 2] {
            let frame = client.sys().server_recv_frame().expect("frame");
            let decoded = Request::decode(&frame).expect("decode");
            assert_eq!(decoded.tag, expected);
            assert_eq!(decoded.message, hello());
        }
    }

    #[test]
    fn a_buffer_travels_with_its_registration() {
        let mut client = connect();
        client.allocate(0, 4096).expect("allocate");
        client.pixels(0).expect("pixels")[0] = 1;
        let register = Request::CreateSurface;
        client.send(&register, Some(0)).expect("send with transfer");
        assert_eq!(
            client.send(&register, Some(1)),
            Err(Error::Failed(STATUS_EINVAL)),
            "slot 1 has no buffer"
        );
        assert!(client.pixels(1).is_none());
        assert!(client.pixels(2).is_none());
    }

    #[test]
    fn events_decode_and_garbage_is_skipped() {
        let mut client = connect();
        client.sys().server_post(&[0xFF; 64]);
        let event = Event::Error {
            object: 3,
            request_opcode: 0x10,
            code: clean_slate_graphics::protocol::ProtocolError::InvalidObject,
        };
        let frame = event.encode(9).expect("encode");
        client.sys().server_post(&frame);
        assert_eq!(client.next_event(Wait::FOREVER), Ok(event));
    }

    #[test]
    fn a_compositor_that_exits_is_gone_on_receive_and_send() {
        let mut client = connect();
        client.sys().server_exit();
        assert_eq!(client.next_event(Wait::FOREVER), Err(Error::Gone));
        assert_eq!(client.send(&hello(), None), Err(Error::Gone));
    }

    #[test]
    fn a_disconnect_is_gone() {
        let mut client = connect();
        client.sys().server_disconnect(7);
        assert_eq!(client.next_event(Wait::FOREVER), Err(Error::Gone));
    }

    #[test]
    fn shut_down_releases_every_buffer() {
        let mut client = connect();
        client.allocate(0, 4096).expect("allocate");
        client.allocate(1, 4096).expect("allocate");
        client.allocate(1, 8192).expect("replace");
        assert_eq!(client.sys().live_buffers(), 2);
        client.shut_down();
        assert_eq!(client.sys().live_buffers(), 0);
    }
}
