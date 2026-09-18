//! Optional QEMU self-test handshake progress hooks.

#[cfg(feature = "m7-handshake-trace")]
pub static mut HANDSHAKE_MARKER: Option<fn(&'static str)> = None;

pub(crate) fn handshake_step(msg: &'static str) {
    #[cfg(feature = "m7-handshake-trace")]
    unsafe {
        if let Some(marker) = HANDSHAKE_MARKER {
            marker(msg);
        }
    }
    let _ = msg;
}
