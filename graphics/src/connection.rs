//! Per-connection sequencing gate (wire §4): Hello first, exactly once.

use crate::protocol::{
    negotiate, DisconnectReason, Event, Features, ProtocolError, ProtocolVersion, Request, Tagged,
    FRAME_BYTES, M10_SERVER_FEATURES, OP_HELLO, SERVER_VERSION,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionPhase {
    AwaitingHello,
    Established {
        version: ProtocolVersion,
        features: Features,
    },
    Closed,
}

/// Everything the compositor needs to post `Event::Error` for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestError {
    pub tag: u32,
    pub object: u32,
    pub opcode: u16,
    pub code: ProtocolError,
}

impl RequestError {
    pub fn event(&self) -> Tagged<Event> {
        Tagged {
            tag: self.tag,
            message: Event::Error {
                object: self.object,
                request_opcode: self.opcode,
                code: self.code,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Hello accepted: post `Welcome` with this tag.
    Welcome {
        tag: u32,
        version: ProtocolVersion,
        features: Features,
    },
    /// Established connection: hand the request to its handler.
    Dispatch {
        tag: u32,
        object: u32,
        request: Request,
    },
    /// Recoverable: post `error.event()`; the connection stays open.
    Reject(RequestError),
    /// Fatal: post `error.event()` best-effort, then disconnect with `reason`.
    Disconnect {
        error: RequestError,
        reason: DisconnectReason,
    },
    /// Connection already closed: drop the frame silently.
    Discard,
}

impl Default for ConnectionPhase {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionPhase {
    pub const fn new() -> Self {
        Self::AwaitingHello
    }

    pub fn negotiated(&self) -> Option<(ProtocolVersion, Features)> {
        match *self {
            Self::Established { version, features } => Some((version, features)),
            _ => None,
        }
    }

    pub fn is_closed(&self) -> bool {
        *self == Self::Closed
    }

    /// Marks the connection closed (non-protocol disconnects: exit, revoke, overflow).
    pub fn close(&mut self) {
        *self = Self::Closed;
    }

    /// Decodes and gates one raw request frame.
    pub fn admit(&mut self, frame: &[u8]) -> Admission {
        if self.is_closed() {
            return Admission::Discard;
        }
        let decoded = match Request::decode(frame) {
            Ok(decoded) => decoded,
            Err(e) => {
                let code = if matches!(self, Self::AwaitingHello) && !e.code.is_fatal() {
                    ProtocolError::UnsupportedVersion
                } else {
                    e.code
                };
                return self.fail(RequestError {
                    tag: e.tag,
                    object: e.object,
                    opcode: e.opcode,
                    code,
                });
            }
        };
        let tag = decoded.tag;
        let object = if frame.len() == FRAME_BYTES {
            u32::from_le_bytes([frame[8], frame[9], frame[10], frame[11]])
        } else {
            0
        };
        let request = decoded.message;
        match (*self, request) {
            (Self::AwaitingHello, Request::Hello { version, features }) => {
                match negotiate(version, features, SERVER_VERSION, M10_SERVER_FEATURES) {
                    Ok((version, features)) => {
                        *self = Self::Established { version, features };
                        Admission::Welcome {
                            tag,
                            version,
                            features,
                        }
                    }
                    Err(_code) => self.fail(RequestError {
                        tag,
                        object,
                        opcode: OP_HELLO,
                        code: ProtocolError::UnsupportedVersion,
                    }),
                }
            }
            (Self::AwaitingHello, other)
            | (Self::Established { .. }, other @ Request::Hello { .. }) => {
                self.fail(RequestError {
                    tag,
                    object,
                    opcode: other.opcode(),
                    code: ProtocolError::UnsupportedVersion,
                })
            }
            (Self::Established { .. }, request) => Admission::Dispatch {
                tag,
                object,
                request,
            },
            (Self::Closed, _) => Admission::Discard,
        }
    }

    /// Routes a handler's error: fatal codes close the connection.
    pub fn fail(&mut self, error: RequestError) -> Admission {
        if self.is_closed() {
            return Admission::Discard;
        }
        if error.code.is_fatal() {
            *self = Self::Closed;
            Admission::Disconnect {
                error,
                reason: DisconnectReason::ProtocolViolation(error.code),
            }
        } else {
            Admission::Reject(error)
        }
    }
}

#[cfg(test)]
mod tests;
