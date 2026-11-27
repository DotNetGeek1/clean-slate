//! The runtime's compositor client is the app's [`Host`]: the CPL3 binary passes it to the
//! session as is, so the binary holds no port or buffer code of its own.

use clean_slate_graphics::protocol::Request;
use clean_slate_runtime::compositor::CompositorClient;
use clean_slate_runtime::Syscalls;

use crate::session::{buffer_layout, BufferSlot, Host, HostError, BUFFER_COUNT};

/// The client the CPL3 binary runs the session against.
pub type Client<S> = CompositorClient<S, BUFFER_COUNT>;

impl<S: Syscalls> Host for Client<S> {
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError> {
        CompositorClient::send(self, request, transfer.map(|slot| usize::from(slot.0)))
    }

    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]> {
        CompositorClient::pixels(self, usize::from(slot.0))
    }
}

/// Allocates and maps both pixel buffers at the size [`buffer_layout`] gives.
pub fn allocate_buffers<S: Syscalls>(client: &mut Client<S>) -> Result<(), HostError> {
    let len = buffer_layout()
        .ok_or(HostError::Failed(
            clean_slate_native_abi::status::STATUS_EINVAL,
        ))?
        .byte_len();
    for slot in BufferSlot::ALL {
        client.allocate(usize::from(slot.0), len)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diag::exit_reason;
    use crate::session::{ExitReason, Outcome, Session};
    use clean_slate_runtime::fake::FakeKernel;
    use clean_slate_runtime::port::Wait;
    use clean_slate_ui::QualityTier;
    use std::boxed::Box;

    fn client() -> Client<FakeKernel> {
        let sys = FakeKernel::new();
        let id = sys.resource_id();
        Client::connect(sys, id).expect("connect")
    }

    #[test]
    fn the_session_starts_over_the_runtime_client() {
        let mut client = client();
        allocate_buffers(&mut client).expect("buffers");
        assert_eq!(client.sys().live_buffers(), BUFFER_COUNT);
        let mut session = Box::new(Session::new(QualityTier::Q1));
        assert_eq!(session.start(&mut client), Outcome::Continue);
        assert!(client.sys().server_recv_frame().is_some(), "Hello was sent");
        client.shut_down();
        assert_eq!(client.sys().live_buffers(), 0);
    }

    /// #315: a send to a compositor that has exited is `Gone`, so the app reports
    /// `compositor-gone` whether it saw the exit on a send or on a receive.
    #[test]
    fn a_compositor_exit_reads_as_compositor_gone_on_send_and_receive() {
        let mut client = client();
        allocate_buffers(&mut client).expect("buffers");
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
        allocate_buffers(&mut client).expect("buffers");
        client.sys().server_disconnect(0);
        let sent = Host::send(&mut client, &Request::CreateSurface, None);
        assert_eq!(sent, Err(HostError::Gone));
        let outcome = Outcome::Exit(ExitReason::HostFailed(sent.unwrap_err()));
        assert_eq!(exit_reason(outcome), "compositor-gone");
    }
}
