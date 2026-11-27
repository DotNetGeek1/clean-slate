//! The runtime's compositor client is the shell's [`Host`]: the CPL3 binary passes it to the
//! session as is, so the binary holds no port or buffer code of its own.

use clean_slate_graphics::protocol::Request;
use clean_slate_runtime::compositor::CompositorClient;
use clean_slate_runtime::Syscalls;

use crate::session::{BufferSlot, Host, HostError, BUFFER_COUNT};

/// The client the CPL3 binary runs the session against.
pub type Client<S> = CompositorClient<S, BUFFER_COUNT>;

impl<S: Syscalls> Host for Client<S> {
    fn allocate(&mut self, slot: BufferSlot, byte_len: usize) -> Result<(), HostError> {
        CompositorClient::allocate(self, usize::from(slot.0), byte_len)
    }

    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError> {
        CompositorClient::send(self, request, transfer.map(|slot| usize::from(slot.0)))
    }

    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]> {
        CompositorClient::pixels(self, usize::from(slot.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::exit_reason;
    use crate::session::{ExitReason, Outcome};
    use clean_slate_runtime::fake::FakeKernel;
    use clean_slate_runtime::port::Wait;

    fn client() -> Client<FakeKernel> {
        let sys = FakeKernel::new();
        let id = sys.resource_id();
        Client::connect(sys, id).expect("connect")
    }

    #[test]
    fn buffers_are_allocated_per_slot_and_released_on_shut_down() {
        let mut client = client();
        for slot in BufferSlot::ALL {
            Host::allocate(&mut client, slot, 4096).expect("allocate");
            assert!(Host::pixels(&mut client, slot).is_some());
        }
        assert_eq!(client.sys().live_buffers(), BUFFER_COUNT);
        Host::send(
            &mut client,
            &Request::CreateSurface,
            Some(BufferSlot::ALL[0]),
        )
        .expect("send");
        client.shut_down();
        assert_eq!(client.sys().live_buffers(), 0);
    }

    /// #315: a send to a compositor that has exited is `Gone`, so the shell reports
    /// `compositor-gone`, not `setup-failed`, and init relaunches it.
    #[test]
    fn a_compositor_exit_reads_as_compositor_gone_on_send_and_receive() {
        let mut client = client();
        client.sys().server_exit();
        let sent = Host::send(&mut client, &Request::CreateSurface, None);
        assert_eq!(sent, Err(HostError::Gone));
        let outcome = Outcome::Exit(ExitReason::HostFailed(sent.unwrap_err()));
        assert_eq!(exit_reason(outcome), "compositor-gone");

        let received = client.next_event(Wait::FOREVER).unwrap_err();
        let outcome = Outcome::Exit(ExitReason::HostFailed(received));
        assert_eq!(exit_reason(outcome), "compositor-gone");
    }

    /// #315: a compositor that disconnected the app (the send sees `EPIPE`, not `ESTALE`) is
    /// `Gone` too, so the exit still reads as `compositor-gone`.
    #[test]
    fn a_compositor_disconnect_reads_as_compositor_gone_on_send() {
        let mut client = client();
        client.sys().server_disconnect(0);
        let sent = Host::send(&mut client, &Request::CreateSurface, None);
        assert_eq!(sent, Err(HostError::Gone));
        let outcome = Outcome::Exit(ExitReason::HostFailed(sent.unwrap_err()));
        assert_eq!(exit_reason(outcome), "compositor-gone");
    }
}
