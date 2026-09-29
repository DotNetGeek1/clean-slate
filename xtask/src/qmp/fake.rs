//! Scripted QMP peer for host tests. It connects to an endpoint the way
//! QEMU does and plays a fixed sequence of acts.

use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use super::json::{self, JsonValue};

/// Bounds every blocking read in the fake so a broken test fails instead of
/// hanging.
const PEER_READ_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) type Responder = Box<dyn FnOnce(&str, &JsonValue) -> String + Send>;

pub(crate) enum Act {
    /// Raw bytes, written as one chunk.
    Send(Vec<u8>),
    /// Raw text, one byte per write.
    SendBytewise(String),
    /// Reads one request, checks its command, and writes what `respond`
    /// returns for the request's id; `None` records it without answering.
    Expect {
        command: &'static str,
        respond: Option<Responder>,
    },
    /// Signals the test that the peer has connected and reached this act.
    Notify(mpsc::Sender<()>),
    /// Reads until the client closes the connection.
    WaitEof,
}

impl Act {
    pub(crate) fn send(text: impl Into<Vec<u8>>) -> Self {
        Act::Send(text.into())
    }

    pub(crate) fn reply(
        command: &'static str,
        respond: impl FnOnce(&str, &JsonValue) -> String + Send + 'static,
    ) -> Self {
        Act::Expect {
            command,
            respond: Some(Box::new(respond)),
        }
    }

    /// Answers `command` with `{"return": <value>}` and the request's id.
    pub(crate) fn returns(command: &'static str, value: &'static str) -> Self {
        Act::reply(command, move |id, _| {
            format!("{{\"return\": {value}, \"id\": \"{id}\"}}\r\n")
        })
    }

    pub(crate) fn silent(command: &'static str) -> Self {
        Act::Expect {
            command,
            respond: None,
        }
    }
}

pub(crate) fn greeting(major: u32, minor: u32, micro: u32) -> String {
    format!(
        "{{\"QMP\": {{\"version\": {{\"qemu\": {{\"micro\": {micro}, \"minor\": {minor}, \"major\": {major}}}, \"package\": \" fake \"}}, \"capabilities\": [\"oob\"]}}}}\r\n"
    )
}

/// The acts a well-behaved QEMU plays before any test-specific command.
pub(crate) fn handshake(nonce: &str) -> Vec<Act> {
    let nonce = nonce.to_owned();
    vec![
        Act::send(greeting(8, 2, 2)),
        Act::returns("qmp_capabilities", "{}"),
        Act::reply("query-name", move |id, _| {
            format!("{{\"return\": {{\"name\": \"{nonce}\"}}, \"id\": \"{id}\"}}\r\n")
        }),
    ]
}

/// Connects to `port` and plays `acts`; the thread returns every request it
/// read, or the first way the client deviated from the script.
pub(crate) fn spawn(port: u16, acts: Vec<Act>) -> JoinHandle<Result<Vec<JsonValue>, String>> {
    thread::spawn(move || {
        let stream = TcpStream::connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|error| format!("fake connect: {error}"))?;
        play(stream, acts)
    })
}

fn play(stream: TcpStream, acts: Vec<Act>) -> Result<Vec<JsonValue>, String> {
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(PEER_READ_TIMEOUT))
        .map_err(|e| e.to_string())?;
    let mut writer = stream.try_clone().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(stream);
    let mut requests = Vec::new();
    for act in acts {
        match act {
            Act::Send(text) => {
                // The client may already have given up on an oversize line.
                let _ = writer.write_all(&text);
            }
            Act::SendBytewise(text) => {
                for byte in text.as_bytes() {
                    writer
                        .write_all(std::slice::from_ref(byte))
                        .map_err(|e| format!("fake bytewise write: {e}"))?;
                }
            }
            Act::Expect { command, respond } => {
                let mut line = String::new();
                reader
                    .read_line(&mut line)
                    .map_err(|e| format!("fake waiting for `{command}`: {e}"))?;
                if line.is_empty() {
                    return Err(format!("client closed before sending `{command}`"));
                }
                let request =
                    json::parse(line.trim_end()).map_err(|e| format!("request {line:?}: {e}"))?;
                let got = request.get("execute").and_then(JsonValue::as_str);
                if got != Some(command) {
                    return Err(format!("expected `{command}`, got {line:?}"));
                }
                let id = request
                    .get("id")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_owned();
                if let Some(respond) = respond {
                    let reply = respond(&id, &request);
                    let _ = writer.write_all(reply.as_bytes());
                }
                requests.push(request);
            }
            Act::Notify(signal) => {
                let _ = signal.send(());
            }
            Act::WaitEof => {
                let mut sink = [0u8; 256];
                loop {
                    match reader.read(&mut sink) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(error)
                            if matches!(
                                error.kind(),
                                ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted
                            ) =>
                        {
                            break
                        }
                        Err(error) => return Err(format!("fake waiting for EOF: {error}")),
                    }
                }
            }
        }
    }
    Ok(requests)
}
