//! Per-run loopback QMP endpoint that QEMU connects out to.
//!
//! The accept runs on its own thread and blocks; nothing polls. It ends in
//! exactly one of three ways, arbitrated by [`AcceptShared::state`]: QEMU
//! connects (`CLAIMED`), the one-shot connect deadline fires (`TIMED_OUT`),
//! or the owner cancels (`CANCELLED`). The latter two wake the blocked
//! accept with a throwaway local connection, which is only made while the
//! state says the accept thread has not claimed a peer, so the listener is
//! still open and the wake cannot be refused.

use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::json::JsonValue;
use super::{QmpClient, QmpError, QmpTimeouts};

const WAITING: u8 = 0;
const CLAIMED: u8 = 1;
const TIMED_OUT: u8 = 2;
const CANCELLED: u8 = 3;
const WAKE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A bound listener plus the `-name` nonce QEMU must report back.
#[derive(Debug)]
pub(crate) struct QmpEndpoint {
    listener: TcpListener,
    port: u16,
    nonce: String,
}

impl QmpEndpoint {
    pub(crate) fn bind() -> std::io::Result<Self> {
        let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let port = listener.local_addr()?.port();
        let sequence = NEXT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            listener,
            port,
            nonce: format!("clean-slate-{}-{sequence}", std::process::id()),
        })
    }

    pub(crate) fn port(&self) -> u16 {
        self.port
    }

    #[cfg(test)]
    pub(crate) fn nonce(&self) -> &str {
        &self.nonce
    }

    /// Arguments that make QEMU connect to this endpoint and name itself
    /// with the nonce.
    pub(crate) fn qemu_args(&self) -> Vec<String> {
        vec![
            "-name".to_owned(),
            self.nonce.clone(),
            "-qmp".to_owned(),
            format!("tcp:127.0.0.1:{}", self.port),
        ]
    }

    /// Starts accepting exactly one connection. `notify` runs once, on the
    /// accept thread, after the outcome is ready in [`PendingSession`].
    pub(crate) fn listen(
        self,
        timeouts: QmpTimeouts,
        notify: impl FnOnce() + Send + 'static,
    ) -> PendingSession {
        let shared = Arc::new(AcceptShared {
            state: AtomicU8::new(WAITING),
            cancel_requested: AtomicBool::new(false),
            stream: Mutex::new(None),
        });
        let (result_tx, result_rx) = mpsc::channel();
        let (timer_stop_tx, timer_stop_rx) = mpsc::channel::<()>();
        let port = self.port;

        let accept_shared = Arc::clone(&shared);
        let accept_thread = thread::spawn(move || {
            let _stop_timer = timer_stop_tx;
            if let Some(outcome) = accept_one(self, &accept_shared, timeouts) {
                let _ = result_tx.send(outcome);
                notify();
            }
        });

        let timer_shared = Arc::clone(&shared);
        let timer_thread = thread::spawn(move || {
            if timer_stop_rx.recv_timeout(timeouts.connect) == Err(mpsc::RecvTimeoutError::Timeout)
            {
                timer_shared.interrupt(TIMED_OUT, port);
            }
        });

        PendingSession {
            port,
            shared,
            result: result_rx,
            accept_thread: Some(accept_thread),
            timer_thread: Some(timer_thread),
        }
    }

    /// Blocking accept for callers without an event loop.
    #[cfg(test)]
    pub(crate) fn accept(self, timeouts: QmpTimeouts) -> Result<QmpClient, QmpError> {
        self.listen(timeouts, || {}).wait()
    }
}

struct AcceptShared {
    state: AtomicU8,
    /// Set before `stream` is inspected by a cancel; checked under the same
    /// lock after the clone is stored, so one side always shuts it down.
    cancel_requested: AtomicBool,
    /// The claimed connection while its handshake runs, so a cancel can cut
    /// the handshake short instead of waiting out its deadlines.
    stream: Mutex<Option<TcpStream>>,
}

impl AcceptShared {
    fn interrupt(&self, reason: u8, port: u16) {
        if self
            .state
            .compare_exchange(WAITING, reason, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let _ = TcpStream::connect_timeout(
                &SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
                WAKE_CONNECT_TIMEOUT,
            );
        }
    }
}

/// `None` when the owner cancelled and nobody is waiting for an outcome.
fn accept_one(
    endpoint: QmpEndpoint,
    shared: &AcceptShared,
    timeouts: QmpTimeouts,
) -> Option<Result<QmpClient, QmpError>> {
    let accepted = endpoint.listener.accept();
    // Later connects to this port are refused from here on.
    drop(endpoint.listener);
    match shared
        .state
        .compare_exchange(WAITING, CLAIMED, Ordering::SeqCst, Ordering::SeqCst)
    {
        Ok(_) => {}
        Err(CANCELLED) => return None,
        Err(_) => {
            return Some(Err(QmpError::AcceptTimeout {
                waited: timeouts.connect,
            }))
        }
    }
    let (stream, peer) = match accepted {
        Ok(accepted) => accepted,
        Err(source) => {
            return Some(Err(QmpError::Io {
                context: "accept".to_owned(),
                source,
            }))
        }
    };
    if !peer.ip().is_loopback() {
        let _ = stream.shutdown(Shutdown::Both);
        return Some(Err(QmpError::PeerNotLoopback { peer }));
    }
    if let (Ok(clone), Ok(mut slot)) = (stream.try_clone(), shared.stream.lock()) {
        if shared.cancel_requested.load(Ordering::SeqCst) {
            let _ = clone.shutdown(Shutdown::Both);
        }
        *slot = Some(clone);
    }
    let outcome = QmpClient::handshake(stream, timeouts)
        .and_then(|client| verify_peer_name(client, &endpoint.nonce, timeouts));
    if let Ok(mut slot) = shared.stream.lock() {
        slot.take();
    }
    Some(outcome)
}

fn verify_peer_name(
    mut client: QmpClient,
    nonce: &str,
    timeouts: QmpTimeouts,
) -> Result<QmpClient, QmpError> {
    let reply = client.execute("query-name", None, timeouts.command)?;
    let name = reply.get("name").and_then(JsonValue::as_str).unwrap_or("");
    if name != nonce {
        client.close();
        return Err(QmpError::PeerMismatch {
            expected: nonce.to_owned(),
            got: name.to_owned(),
        });
    }
    Ok(client)
}

/// An in-flight accept. Dropping it cancels the accept, closes the endpoint
/// and joins both helper threads.
pub(crate) struct PendingSession {
    port: u16,
    shared: Arc<AcceptShared>,
    result: mpsc::Receiver<Result<QmpClient, QmpError>>,
    accept_thread: Option<JoinHandle<()>>,
    timer_thread: Option<JoinHandle<()>>,
}

impl PendingSession {
    /// The outcome if the accept has finished, without blocking.
    pub(crate) fn try_take(&mut self) -> Option<Result<QmpClient, QmpError>> {
        let outcome = self.result.try_recv().ok()?;
        self.join();
        Some(outcome)
    }

    /// Blocks until the accept finishes; bounded by the connect deadline plus
    /// the handshake deadlines.
    #[cfg(test)]
    pub(crate) fn wait(mut self) -> Result<QmpClient, QmpError> {
        let outcome = self.result.recv().unwrap_or_else(|_| {
            Err(QmpError::Protocol {
                context: "accept".to_owned(),
                detail: "accept thread ended without an outcome".to_owned(),
            })
        });
        self.join();
        outcome
    }

    /// Abandons the accept; the endpoint is closed when this returns.
    pub(crate) fn cancel(&mut self) {
        self.shared.cancel_requested.store(true, Ordering::SeqCst);
        self.shared.interrupt(CANCELLED, self.port);
        if let Ok(slot) = self.shared.stream.lock() {
            if let Some(stream) = slot.as_ref() {
                let _ = stream.shutdown(Shutdown::Both);
            }
        }
        self.join();
    }

    fn join(&mut self) {
        if let Some(handle) = self.accept_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.timer_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for PendingSession {
    fn drop(&mut self) {
        self.cancel();
    }
}
