//! One QMP connection: greeting, capability negotiation and id-matched
//! commands, with every read bounded in time and size.

use std::collections::VecDeque;
use std::fmt::{self, Display, Formatter};
use std::fs;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant};

use super::image::{self, Screenshot, MAX_PPM_FILE_BYTES};
use super::json::{self, JsonValue};
use super::{QmpError, QmpTimeouts};

/// Longest QMP line accepted, excluding its terminator.
pub(crate) const MAX_LINE_BYTES: usize = 256 * 1024;
/// Events kept between [`QmpClient::take_events`] calls; older ones are dropped.
pub(crate) const EVENT_RING_CAPACITY: usize = 64;
/// `input-send-event` is the newest command the harness relies on.
pub(crate) const MIN_QEMU_VERSION: QemuVersion = QemuVersion {
    major: 2,
    minor: 6,
    micro: 0,
};
const READ_CHUNK_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct QemuVersion {
    pub(crate) major: u64,
    pub(crate) minor: u64,
    pub(crate) micro: u64,
}

impl Display for QemuVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.micro)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct QmpEvent {
    pub(crate) name: String,
    pub(crate) data: Option<JsonValue>,
}

pub(crate) struct QmpClient {
    stream: TcpStream,
    buffer: Vec<u8>,
    /// Prefix of `buffer` already searched for a line terminator.
    scanned: usize,
    next_id: u64,
    version: QemuVersion,
    package: String,
    events: VecDeque<QmpEvent>,
    dropped_events: u64,
}

impl QmpClient {
    /// Reads the greeting and leaves capabilities negotiation mode. OOB is
    /// not enabled, so replies arrive in request order.
    pub(crate) fn handshake(stream: TcpStream, timeouts: QmpTimeouts) -> Result<Self, QmpError> {
        stream.set_nodelay(true).map_err(|source| QmpError::Io {
            context: "set_nodelay".to_owned(),
            source,
        })?;
        let mut client = Self {
            stream,
            buffer: Vec::new(),
            scanned: 0,
            next_id: 1,
            version: QemuVersion {
                major: 0,
                minor: 0,
                micro: 0,
            },
            package: String::new(),
            events: VecDeque::new(),
            dropped_events: 0,
        };
        let deadline = Instant::now() + timeouts.greeting;
        let line = client.read_line("greeting", deadline, timeouts.greeting)?;
        let greeting = json::parse(&line).map_err(|error| QmpError::Malformed {
            context: "greeting".to_owned(),
            error,
        })?;
        let (version, package) = parse_greeting(&greeting)?;
        if version < MIN_QEMU_VERSION {
            return Err(QmpError::UnsupportedVersion {
                version,
                minimum: MIN_QEMU_VERSION,
            });
        }
        client.version = version;
        client.package = package;
        let negotiated = client.execute("qmp_capabilities", None, timeouts.command)?;
        if negotiated != JsonValue::Object(Vec::new()) {
            return Err(QmpError::Protocol {
                context: "qmp_capabilities".to_owned(),
                detail: format!("unexpected return {}", negotiated.to_json()),
            });
        }
        Ok(client)
    }

    pub(crate) fn version(&self) -> QemuVersion {
        self.version
    }

    pub(crate) fn package(&self) -> &str {
        &self.package
    }

    /// Sends one command and waits for the reply carrying its id. Events that
    /// arrive first are queued; any other reply is a protocol violation.
    pub(crate) fn execute(
        &mut self,
        command: &str,
        arguments: Option<JsonValue>,
        timeout: Duration,
    ) -> Result<JsonValue, QmpError> {
        let id = format!("xtask-{}", self.next_id);
        self.next_id += 1;
        let context = format!("{command} (id {id})");
        let mut request = vec![("execute", JsonValue::str(command))];
        if let Some(arguments) = arguments {
            request.push(("arguments", arguments));
        }
        request.push(("id", JsonValue::str(id.as_str())));
        let mut text = JsonValue::object(request).to_json();
        text.push('\n');

        let deadline = Instant::now() + timeout;
        self.write_all(text.as_bytes(), &context, deadline, timeout)?;
        loop {
            let line = self.read_line(&context, deadline, timeout)?;
            let reply = json::parse(&line).map_err(|error| QmpError::Malformed {
                context: context.clone(),
                error,
            })?;
            if reply.get("event").is_some() {
                self.queue_event(reply, &context)?;
                continue;
            }
            return take_reply(reply, &context, &id);
        }
    }

    /// Events received so far, oldest first.
    pub(crate) fn take_events(&mut self) -> Vec<QmpEvent> {
        self.events.drain(..).collect()
    }

    pub(crate) fn dropped_events(&self) -> u64 {
        self.dropped_events
    }

    /// Captures the primary console as PPM (the one format every supported
    /// QEMU writes; `format` needs 7.1+ and PNG needs a libpng build).
    pub(crate) fn screendump(
        &mut self,
        path: &Path,
        timeout: Duration,
    ) -> Result<Screenshot, QmpError> {
        if !path.is_absolute() {
            return Err(QmpError::InvalidRequest {
                detail: format!("screendump path {} is not absolute", path.display()),
            });
        }
        let Some(filename) = path.to_str() else {
            return Err(QmpError::InvalidRequest {
                detail: format!("screendump path {} is not UTF-8", path.display()),
            });
        };
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(QmpError::Io {
                    context: format!("screendump clearing {filename}"),
                    source,
                })
            }
        }
        self.execute(
            "screendump",
            Some(JsonValue::object([("filename", JsonValue::str(filename))])),
            timeout,
        )?;
        let context = format!("screendump {filename}");
        let bytes = read_bounded(path, MAX_PPM_FILE_BYTES).map_err(|error| match error {
            ReadBoundedError::Io(source) => QmpError::Io {
                context: context.clone(),
                source,
            },
            ReadBoundedError::TooLarge => QmpError::Image {
                context: context.clone(),
                detail: image::ImageError::TooLarge {
                    limit: MAX_PPM_FILE_BYTES,
                }
                .to_string(),
            },
        })?;
        image::parse_ppm(&bytes).map_err(|error| QmpError::Image {
            context,
            detail: error.to_string(),
        })
    }

    /// Reads until the peer closes, queueing events; used after `quit`, whose
    /// `SHUTDOWN` event QEMU may send before or after the reply.
    pub(crate) fn wait_for_close(&mut self, timeout: Duration) -> Result<(), QmpError> {
        let context = "waiting for QEMU to close QMP";
        let deadline = Instant::now() + timeout;
        loop {
            let line = match self.read_line(context, deadline, timeout) {
                Ok(line) => line,
                Err(QmpError::Disconnected { .. }) => return Ok(()),
                Err(error) => return Err(error),
            };
            let message = json::parse(&line).map_err(|error| QmpError::Malformed {
                context: context.to_owned(),
                error,
            })?;
            if message.get("event").is_none() {
                return Err(QmpError::Protocol {
                    context: context.to_owned(),
                    detail: format!("unsolicited message {}", message.to_json()),
                });
            }
            self.queue_event(message, context)?;
        }
    }

    pub(crate) fn try_clone_stream(&self) -> io::Result<TcpStream> {
        self.stream.try_clone()
    }

    /// Closes both directions now rather than when the client is dropped.
    pub(crate) fn close(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }

    fn queue_event(&mut self, event: JsonValue, context: &str) -> Result<(), QmpError> {
        let Some(name) = event.get("event").and_then(JsonValue::as_str) else {
            return Err(QmpError::Protocol {
                context: context.to_owned(),
                detail: "event name is not a string".to_owned(),
            });
        };
        let name = name.to_owned();
        let data = event.get("data").cloned();
        if self.events.len() == EVENT_RING_CAPACITY {
            self.events.pop_front();
            self.dropped_events += 1;
        }
        self.events.push_back(QmpEvent { name, data });
        Ok(())
    }

    fn write_all(
        &mut self,
        bytes: &[u8],
        context: &str,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<(), QmpError> {
        let remaining = remaining(deadline).ok_or_else(|| QmpError::Timeout {
            context: context.to_owned(),
            waited: timeout,
        })?;
        self.stream
            .set_write_timeout(Some(remaining))
            .and_then(|()| self.stream.write_all(bytes))
            .map_err(|source| match source.kind() {
                ErrorKind::WouldBlock | ErrorKind::TimedOut => QmpError::Timeout {
                    context: context.to_owned(),
                    waited: timeout,
                },
                ErrorKind::BrokenPipe
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted => QmpError::Disconnected {
                    context: context.to_owned(),
                    partial_line: false,
                },
                _ => QmpError::Io {
                    context: context.to_owned(),
                    source,
                },
            })
    }

    fn read_line(
        &mut self,
        context: &str,
        deadline: Instant,
        timeout: Duration,
    ) -> Result<String, QmpError> {
        let mut chunk = [0u8; READ_CHUNK_BYTES];
        loop {
            if let Some(end) = self.buffer[self.scanned..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|offset| self.scanned + offset)
            {
                let mut line: Vec<u8> = self.buffer.drain(..=end).collect();
                self.scanned = 0;
                line.pop();
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if line.len() > MAX_LINE_BYTES {
                    return Err(QmpError::LineTooLong {
                        context: context.to_owned(),
                        limit: MAX_LINE_BYTES,
                    });
                }
                return String::from_utf8(line).map_err(|_| QmpError::Protocol {
                    context: context.to_owned(),
                    detail: "line is not UTF-8".to_owned(),
                });
            }
            self.scanned = self.buffer.len();
            // One byte of slack for a trailing `\r`.
            if self.buffer.len() > MAX_LINE_BYTES + 1 {
                return Err(QmpError::LineTooLong {
                    context: context.to_owned(),
                    limit: MAX_LINE_BYTES,
                });
            }
            let timed_out = || QmpError::Timeout {
                context: context.to_owned(),
                waited: timeout,
            };
            let remaining = remaining(deadline).ok_or_else(timed_out)?;
            if let Err(source) = self.stream.set_read_timeout(Some(remaining)) {
                return Err(QmpError::Io {
                    context: context.to_owned(),
                    source,
                });
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => {
                    return Err(QmpError::Disconnected {
                        context: context.to_owned(),
                        partial_line: !self.buffer.is_empty(),
                    })
                }
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error)
                    if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                {
                    return Err(timed_out());
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                    ) =>
                {
                    return Err(QmpError::Disconnected {
                        context: context.to_owned(),
                        partial_line: !self.buffer.is_empty(),
                    })
                }
                Err(source) => {
                    return Err(QmpError::Io {
                        context: context.to_owned(),
                        source,
                    })
                }
            }
        }
    }
}

/// Time left before `deadline`; `None` once it has passed, because a zero
/// socket timeout means "block forever".
fn remaining(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
}

fn parse_greeting(greeting: &JsonValue) -> Result<(QemuVersion, String), QmpError> {
    let protocol = |detail: &str| QmpError::Protocol {
        context: "greeting".to_owned(),
        detail: detail.to_owned(),
    };
    let qmp = greeting
        .get("QMP")
        .filter(|qmp| qmp.as_object().is_some())
        .ok_or_else(|| protocol("missing QMP object"))?;
    let version = qmp
        .get("version")
        .ok_or_else(|| protocol("missing QMP.version"))?;
    let qemu = version
        .get("qemu")
        .ok_or_else(|| protocol("missing QMP.version.qemu"))?;
    let field = |name: &str| {
        qemu.get(name)
            .and_then(JsonValue::as_u64)
            .ok_or_else(|| protocol("QMP.version.qemu needs integer major, minor, micro"))
    };
    let parsed = QemuVersion {
        major: field("major")?,
        minor: field("minor")?,
        micro: field("micro")?,
    };
    if qmp
        .get("capabilities")
        .and_then(JsonValue::as_array)
        .is_none()
    {
        return Err(protocol("missing QMP.capabilities array"));
    }
    let package = version
        .get("package")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .trim()
        .to_owned();
    Ok((parsed, package))
}

fn take_reply(reply: JsonValue, context: &str, expected_id: &str) -> Result<JsonValue, QmpError> {
    let got_id = reply
        .get("id")
        .and_then(JsonValue::as_str)
        .map(str::to_owned);
    let JsonValue::Object(entries) = reply else {
        return Err(QmpError::Protocol {
            context: context.to_owned(),
            detail: "reply is not an object".to_owned(),
        });
    };
    let mut returned = None;
    let mut error = None;
    for (key, value) in entries {
        match key.as_str() {
            "return" => returned = Some(value),
            "error" => error = Some(value),
            _ => {}
        }
    }
    if returned.is_some() == error.is_some() {
        return Err(QmpError::Protocol {
            context: context.to_owned(),
            detail: "reply needs exactly one of `return` and `error`".to_owned(),
        });
    }
    if got_id.as_deref() != Some(expected_id) {
        return Err(QmpError::IdMismatch {
            context: context.to_owned(),
            expected: expected_id.to_owned(),
            got: got_id,
        });
    }
    if let Some(value) = returned {
        return Ok(value);
    }
    let error = error.unwrap_or(JsonValue::Null);
    let text = |key: &str| {
        error
            .get(key)
            .and_then(JsonValue::as_str)
            .unwrap_or("<missing>")
            .to_owned()
    };
    Err(QmpError::Command {
        context: context.to_owned(),
        class: text("class"),
        desc: text("desc"),
    })
}

enum ReadBoundedError {
    Io(io::Error),
    TooLarge,
}

fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>, ReadBoundedError> {
    let file = fs::File::open(path).map_err(ReadBoundedError::Io)?;
    let len = file.metadata().map_err(ReadBoundedError::Io)?.len();
    if len > limit as u64 {
        return Err(ReadBoundedError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ReadBoundedError::Io)?;
    if bytes.len() > limit {
        return Err(ReadBoundedError::TooLarge);
    }
    Ok(bytes)
}
