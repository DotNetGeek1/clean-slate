//! Headless QMP control channel for acceptance lanes (#197).
//!
//! xtask listens on a per-run loopback port and QEMU connects out to it with
//! `-qmp tcp:`, so the port is held from bind until accept and no other QEMU
//! can claim it. [`QmpClient`] is independent of process launch: host tests
//! drive it through the same accept path with a fake peer.

mod client;
mod endpoint;
#[cfg(test)]
mod fake;
pub(crate) mod image;
pub(crate) mod inject;
pub(crate) mod input;
pub(crate) mod json;
pub(crate) mod lane;
mod script;
pub(crate) mod smoke;
#[cfg(test)]
mod tests;

use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

pub(crate) use client::{QemuVersion, QmpClient, QmpEvent};
pub(crate) use endpoint::{PendingSession, QmpEndpoint};
pub(crate) use input::{InputAction, MouseButton, QCode};
pub(crate) use script::{QmpScriptDriver, ScriptStep};

/// Deadlines for one QMP connection. Every blocking read, write and accept is
/// bounded by one of these.
#[derive(Clone, Copy, Debug)]
pub(crate) struct QmpTimeouts {
    /// From [`QmpEndpoint::listen`] until QEMU connects.
    pub(crate) connect: Duration,
    /// For the greeting line after the connection is accepted.
    pub(crate) greeting: Duration,
    /// Default for one command, from request write to reply.
    pub(crate) command: Duration,
}

impl QmpTimeouts {
    pub(crate) const DEFAULT: Self = Self {
        connect: Duration::from_secs(15),
        greeting: Duration::from_secs(10),
        command: Duration::from_secs(10),
    };
}

/// Every error names the phase or command it happened in, so a lane failure
/// is diagnosable from the one-line message.
#[derive(Debug)]
pub(crate) enum QmpError {
    Io {
        context: String,
        source: io::Error,
    },
    AcceptTimeout {
        waited: Duration,
    },
    ChildExitedBeforeConnect {
        status: String,
    },
    PeerNotLoopback {
        peer: SocketAddr,
    },
    PeerMismatch {
        expected: String,
        got: String,
    },
    UnsupportedVersion {
        version: QemuVersion,
        minimum: QemuVersion,
    },
    Timeout {
        context: String,
        waited: Duration,
    },
    Disconnected {
        context: String,
        partial_line: bool,
    },
    LineTooLong {
        context: String,
        limit: usize,
    },
    Malformed {
        context: String,
        error: json::JsonError,
    },
    Protocol {
        context: String,
        detail: String,
    },
    IdMismatch {
        context: String,
        expected: String,
        got: Option<String>,
    },
    Command {
        context: String,
        class: String,
        desc: String,
    },
    Image {
        context: String,
        detail: String,
    },
    InvalidRequest {
        detail: String,
    },
}

impl Display for QmpError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            QmpError::Io { context, source } => write!(f, "QMP {context}: {source}"),
            QmpError::AcceptTimeout { waited } => {
                write!(f, "QEMU did not connect to QMP within {waited:?}")
            }
            QmpError::ChildExitedBeforeConnect { status } => {
                write!(f, "QEMU exited before connecting to QMP ({status})")
            }
            QmpError::PeerNotLoopback { peer } => {
                write!(f, "QMP peer {peer} is not loopback; refusing it")
            }
            QmpError::PeerMismatch { expected, got } => write!(
                f,
                "QMP peer reports name `{got}`, expected this run's `{expected}`"
            ),
            QmpError::UnsupportedVersion { version, minimum } => {
                write!(f, "QEMU {version} is older than the minimum {minimum}")
            }
            QmpError::Timeout { context, waited } => {
                write!(f, "QMP {context}: no reply within {waited:?}")
            }
            QmpError::Disconnected {
                context,
                partial_line,
            } => {
                let partial = if *partial_line { " mid-line" } else { "" };
                write!(f, "QMP {context}: peer disconnected{partial}")
            }
            QmpError::LineTooLong { context, limit } => {
                write!(f, "QMP {context}: line exceeds {limit} bytes")
            }
            QmpError::Malformed { context, error } => {
                write!(f, "QMP {context}: malformed JSON: {error}")
            }
            QmpError::Protocol { context, detail } => write!(f, "QMP {context}: {detail}"),
            QmpError::IdMismatch {
                context,
                expected,
                got,
            } => match got {
                Some(got) => write!(f, "QMP {context}: reply id `{got}`, expected `{expected}`"),
                None => write!(f, "QMP {context}: reply without id, expected `{expected}`"),
            },
            QmpError::Command {
                context,
                class,
                desc,
            } => write!(f, "QMP {context} failed: {class}: {desc}"),
            QmpError::Image { context, detail } => write!(f, "QMP {context}: {detail}"),
            QmpError::InvalidRequest { detail } => write!(f, "QMP request rejected: {detail}"),
        }
    }
}
