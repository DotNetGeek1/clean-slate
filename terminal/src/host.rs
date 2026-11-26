//! The runtime's compositor client is the terminal's [`Host`], as it is the playground's.

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

/// The word the exit line gives for `outcome`.
pub const fn exit_reason(outcome: crate::Outcome) -> &'static str {
    use crate::{ExitReason, Outcome};
    match outcome {
        Outcome::Exit(ExitReason::Closed) => "closed",
        Outcome::Continue | Outcome::Exit(ExitReason::HostFailed(HostError::Gone)) => {
            "compositor-gone"
        }
        Outcome::Exit(_) => "failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::Session;
    use crate::Outcome;
    use clean_slate_runtime::fake::FakeKernel;
    use std::boxed::Box;

    #[test]
    fn the_session_starts_over_the_runtime_client() {
        let sys = FakeKernel::new();
        let id = sys.resource_id();
        let mut client = Client::connect(sys, id).expect("connect");
        allocate_buffers(&mut client).expect("buffers");
        assert_eq!(client.sys().live_buffers(), BUFFER_COUNT);
        let mut session = Box::new(Session::new());
        assert_eq!(session.start(&mut client), Outcome::Continue);
        assert!(client.sys().server_recv_frame().is_some(), "Hello was sent");
        client.shut_down();
        assert_eq!(client.sys().live_buffers(), 0);
        assert_eq!(exit_reason(Outcome::Continue), "compositor-gone");
    }
}
