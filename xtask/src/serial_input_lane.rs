//! `test-serial-input` (#218 S4): COM1 receive, the canonical line discipline and its echo,
//! driven by bytes the host sends to the guest's serial port.
//!
//! COM1 is a TCP socket for this lane only (`-serial tcp:127.0.0.1:PORT`, QEMU connecting out
//! to a loopback listener xtask binds on port 0, as the QMP endpoint does). Piped stdin is not
//! usable: QEMU's Windows stdio backend drops every `\r` it reads from a pipe, and discards a
//! byte whenever the guest's receive FIFO is full instead of applying backpressure. The socket
//! backend only reads the socket while the FIFO has room.
//!
//! The kernel prints `[TTY ] ready`, then one `[TTY ] read len=N hex=…` record per console read.
//! [`script`] is the oracle: each step's bytes are sent once every record of the steps before
//! it has arrived, and at the end the bytes outside the records (the echo) and the records
//! themselves must equal the script's exactly.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::{ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::{
    announce_qemu_version, prepare_vm, xtask_artifact_root, ReapOnDrop, VmLaunchConfig, XtaskError,
    QEMU_DEBUG_EXIT_SUCCESS,
};

pub(crate) const FEATURES: &[&str] = &["serial-input-self-test"];
const READY: &[u8] = b"[TTY ] ready\n";
const RECORD_PREFIX: &[u8] = b"[TTY ] ";
const ENABLED_PREFIX: &str = "[TTY ] receive enabled irq=4 vector=0x";
const ENABLED_SUFFIX: &str = " stale=0\n";
const DONE: &str = "[TTY ] done";
/// Sent once the whole `done` line has arrived; the guest exits only after receiving it, so a
/// socket reset at QEMU exit cannot discard transcript bytes. BEL is dropped without echo.
const DONE_ACK: u8 = 0x07;
/// Boot to `ready` plus the script; the kernel build before it is not counted.
const TIMEOUT: Duration = Duration::from_secs(120);
const EXIT_WAIT: Duration = Duration::from_secs(10);
/// The guest's read buffer: longer lines arrive as several reads.
const GUEST_READ_BYTES: usize = 128;
const LINE_MAX_CONTENT: usize = 256;
const COMMITTED_CAPACITY: usize = 1024;
/// Bytes the guest reads per receive interrupt at most (`uart::DRAIN_BUDGET`).
const DRAIN_BUDGET: u32 = 16;

/// One expected `[TTY ]` record, newline excluded.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Record {
    Exact(String),
    /// `[TTY ] irq irqs=… spurious=… rearms=… max_drained=M wakes=W notified=N`: interrupt
    /// counts depend on timing, so only `W == N`, `1 <= W <= wake_bound` and
    /// `2 <= M <= DRAIN_BUDGET` are required. The bursts cannot all arrive one byte per
    /// interrupt, so `M >= 2` shows one interrupt drained several bytes.
    Irq {
        wake_bound: u32,
    },
}

#[derive(Clone, Debug)]
struct Step {
    name: &'static str,
    send: Vec<u8>,
    echo: Vec<u8>,
    records: Vec<Record>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, byte| {
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// The records the guest prints for one committed line, split into reads of at most
/// [`GUEST_READ_BYTES`].
fn reads(line: &[u8]) -> Vec<Record> {
    line.chunks(GUEST_READ_BYTES)
        .map(|chunk| {
            Record::Exact(format!(
                "[TTY ] read len={} hex={}",
                chunk.len(),
                hex(chunk)
            ))
        })
        .collect()
}

fn exact(text: &str) -> Record {
    Record::Exact(text.to_owned())
}

const ERASE: &[u8] = b"\x08 \x08";

/// Eight lines of 127 bytes plus newline fill the committed buffer exactly.
fn filling_lines() -> Vec<Vec<u8>> {
    (b'A'..=b'H').map(|letter| vec![letter; 127]).collect()
}

fn script() -> Vec<Step> {
    let mut steps = vec![
        Step {
            name: "plain line",
            send: b"hello\r".to_vec(),
            echo: b"hello\r\n".to_vec(),
            records: reads(b"hello\n"),
        },
        Step {
            name: "backspace and delete",
            send: b"\x08cat\x7f\x08ow\r".to_vec(),
            echo: [&b"cat"[..], ERASE, ERASE, b"ow\r\n"].concat(),
            records: reads(b"cow\n"),
        },
        Step {
            name: "ctrl-u and dropped control bytes",
            send: b"junk\x15o\x01\x1bk\r".to_vec(),
            echo: [&b"junk"[..], ERASE, ERASE, ERASE, ERASE, b"ok\r\n"].concat(),
            records: reads(b"ok\n"),
        },
    ];

    let mut overlong = vec![b'x'; 300];
    overlong.push(b'\r');
    let mut kept = vec![b'x'; LINE_MAX_CONTENT];
    let mut overlong_echo = kept.clone();
    overlong_echo.extend_from_slice(b"\r\n");
    kept.push(b'\n');
    steps.push(Step {
        name: "overlong line",
        send: overlong,
        echo: overlong_echo,
        records: reads(&kept),
    });

    let burst = ["one", "two", "three", "four", "five", "six"];
    steps.push(Step {
        name: "burst of lines",
        send: burst
            .iter()
            .flat_map(|w| [w.as_bytes(), b"\r"].concat())
            .collect(),
        echo: burst
            .iter()
            .flat_map(|w| [w.as_bytes(), b"\r\n"].concat())
            .collect(),
        records: burst
            .iter()
            .flat_map(|w| reads(&[w.as_bytes(), b"\n"].concat()))
            .collect(),
    });

    let mut hold_records = reads(b"hold\n");
    hold_records.push(exact("[TTY ] hold"));
    steps.push(Step {
        name: "hold the reader",
        send: b"hold\r".to_vec(),
        echo: b"hold\r\n".to_vec(),
        records: hold_records,
    });

    let mut fill_send = Vec::new();
    let mut fill_echo = Vec::new();
    let mut fill_records = vec![exact(&format!(
        "[TTY ] resume committed={COMMITTED_CAPACITY} deferred_line=1 refused=4"
    ))];
    for line in filling_lines() {
        fill_send.extend_from_slice(&line);
        fill_send.push(b'\r');
        fill_echo.extend_from_slice(&line);
        fill_echo.extend_from_slice(b"\r\n");
        fill_records.extend(reads(&[&line[..], b"\n"].concat()));
    }
    fill_send.extend_from_slice(b"ninth\rlost");
    fill_echo.extend_from_slice(b"ninth\r\n");
    fill_records.extend(reads(b"ninth\n"));
    steps.push(Step {
        name: "committed buffer full",
        send: fill_send,
        echo: fill_echo,
        records: fill_records,
    });

    steps.push(Step {
        name: "ctrl-d on a non-empty line",
        send: b"part\x04".to_vec(),
        echo: b"part".to_vec(),
        records: reads(b"part"),
    });

    let lines = 21;
    let eofs = 1;
    let bytes: usize = steps.iter().map(|step| step.send.len()).sum::<usize>() + 1;
    steps.push(Step {
        name: "ctrl-d on an empty line",
        send: b"\x04".to_vec(),
        echo: Vec::new(),
        records: vec![
            exact("[TTY ] eof"),
            Record::Exact(format!(
                "[TTY ] stats lines={lines} eofs={eofs} deferred=1 edit_overflow=44 refused=4 \
                 eof_dropped=0 control_dropped=2 bytes={bytes} line_errors=0 overruns=0 \
                 stale=0 woken=0"
            )),
            Record::Irq {
                wake_bound: lines + eofs,
            },
            exact(DONE),
        ],
    });
    steps
}

/// Splits serial output after `ready` into the echo (everything outside records) and the
/// complete `[TTY ]` records, newline excluded. Records are written with interrupts masked, so
/// echo can sit between records but never inside one; an unfinished record at the end is left
/// out of both.
fn split_records(stream: &[u8]) -> (Vec<u8>, Vec<String>) {
    let mut echo = Vec::new();
    let mut records = Vec::new();
    let mut rest = stream;
    while !rest.is_empty() {
        match find(rest, RECORD_PREFIX) {
            Some(start) => {
                echo.extend_from_slice(&rest[..start]);
                let Some(len) = rest[start..].iter().position(|byte| *byte == b'\n') else {
                    break;
                };
                records.push(String::from_utf8_lossy(&rest[start..start + len]).into_owned());
                rest = &rest[start + len + 1..];
            }
            None => {
                let keep = partial_prefix_len(rest);
                echo.extend_from_slice(&rest[..rest.len() - keep]);
                break;
            }
        }
    }
    (echo, records)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Length of the longest tail of `bytes` that could still grow into a record prefix.
fn partial_prefix_len(bytes: &[u8]) -> usize {
    (1..RECORD_PREFIX.len())
        .rev()
        .find(|len| bytes.ends_with(&RECORD_PREFIX[..*len]))
        .unwrap_or(0)
}

fn irq_field(line: &str, name: &str) -> Option<u32> {
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(name)?.strip_prefix('='))
        .and_then(|value| value.parse().ok())
}

fn check_record(expected: &Record, got: &str) -> Result<(), String> {
    match expected {
        Record::Exact(text) if text == got => Ok(()),
        Record::Exact(text) => Err(format!("expected {text:?}, got {got:?}")),
        Record::Irq { wake_bound } => {
            let fields = [
                "irqs",
                "spurious",
                "rearms",
                "max_drained",
                "wakes",
                "notified",
            ];
            let values: Option<Vec<u32>> =
                fields.iter().map(|field| irq_field(got, field)).collect();
            match values.as_deref() {
                Some([_, _, _, max_drained, wakes, notified])
                    if got.starts_with("[TTY ] irq ")
                        && (2..=DRAIN_BUDGET).contains(max_drained)
                        && wakes == notified
                        && (1..=*wake_bound).contains(wakes) =>
                {
                    Ok(())
                }
                _ => Err(format!(
                    "expected an irq record with 2 <= max_drained <= {DRAIN_BUDGET} and \
                     1 <= wakes == notified <= {wake_bound}, got {got:?}"
                )),
            }
        }
    }
}

/// Checks everything after `ready` against the script, byte for byte.
fn validate(after_ready: &[u8], steps: &[Step]) -> Result<(), String> {
    let (echo, records) = split_records(after_ready);
    let expected: Vec<&Record> = steps.iter().flat_map(|step| &step.records).collect();
    for (index, (want, got)) in expected.iter().zip(&records).enumerate() {
        check_record(want, got).map_err(|reason| format!("record {index}: {reason}"))?;
    }
    if records.len() != expected.len() {
        return Err(format!(
            "expected {} records, got {}",
            expected.len(),
            records.len()
        ));
    }
    let expected_echo: Vec<u8> = steps.iter().flat_map(|step| step.echo.clone()).collect();
    if echo != expected_echo {
        let at = echo
            .iter()
            .zip(&expected_echo)
            .position(|(got, want)| got != want)
            .unwrap_or(echo.len().min(expected_echo.len()));
        return Err(format!(
            "echo differs at byte {at} of {} (expected {}): got {:?}, expected {:?}",
            echo.len(),
            expected_echo.len(),
            String::from_utf8_lossy(&echo[at..echo.len().min(at + 40)]),
            String::from_utf8_lossy(&expected_echo[at..expected_echo.len().min(at + 40)])
        ));
    }
    Ok(())
}

fn validate_boot(before_ready: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(before_ready);
    let line = text
        .split_inclusive('\n')
        .find(|line| line.starts_with(ENABLED_PREFIX))
        .ok_or_else(|| format!("missing {ENABLED_PREFIX:?}"))?;
    match line
        .strip_prefix(ENABLED_PREFIX)
        .and_then(|rest| rest.strip_suffix(ENABLED_SUFFIX))
    {
        Some(vector) if u8::from_str_radix(vector, 16).is_ok() => Ok(()),
        _ => Err(format!("unexpected enable line {line:?}")),
    }
}

enum SerialEvent {
    Bytes(Vec<u8>),
    Closed,
    Failed(std::io::Error),
}

fn spawn_serial_reader(
    mut stream: TcpStream,
    tx: mpsc::Sender<SerialEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match stream.read(&mut buffer) {
                Ok(0) => {
                    let _ = tx.send(SerialEvent::Closed);
                    return;
                }
                Ok(read) => {
                    if tx
                        .send(SerialEvent::Bytes(buffer[..read].to_vec()))
                        .is_err()
                    {
                        return;
                    }
                }
                Err(error) => {
                    let _ = tx.send(SerialEvent::Failed(error));
                    return;
                }
            }
        }
    })
}

/// QEMU connects to the listener while it starts; it exits if the connection fails.
fn accept_serial(
    listener: &TcpListener,
    child: &mut ReapOnDrop,
    deadline: Instant,
) -> Result<TcpStream, XtaskError> {
    listener.set_nonblocking(true)?;
    loop {
        match listener.accept() {
            Ok((stream, peer)) => {
                if !peer.ip().is_loopback() {
                    return Err(XtaskError::Validation(format!(
                        "serial input: peer {peer} is not loopback"
                    )));
                }
                stream.set_nonblocking(false)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(XtaskError::Io(error)),
        }
        if let Some(status) = child.try_wait()? {
            return Err(XtaskError::Validation(format!(
                "serial input: QEMU exited with {status} before connecting its serial port"
            )));
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::Validation(
                "serial input: QEMU did not connect its serial port".to_owned(),
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_exit(child: &mut ReapOnDrop) -> Result<ExitStatus, XtaskError> {
    let deadline = Instant::now() + EXIT_WAIT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(XtaskError::Validation(format!(
                "serial input: QEMU still running {}s after {DONE}",
                EXIT_WAIT.as_secs()
            )));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn tail(transcript: &[u8]) -> String {
    let start = transcript.len().saturating_sub(400);
    String::from_utf8_lossy(&transcript[start..]).into_owned()
}

fn save_transcript(transcript: &[u8]) -> Result<(), XtaskError> {
    let dir = xtask_artifact_root().join("serial-input");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("serial.log");
    std::fs::write(&path, transcript)?;
    println!("[TTY ] serial transcript: {}", path.display());
    Ok(())
}

pub(crate) fn run() -> Result<(), XtaskError> {
    let steps = script();
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let config = VmLaunchConfig {
        serial_tcp_port: Some(listener.local_addr()?.port()),
        ..VmLaunchConfig::default()
    };
    let mut vm = prepare_vm(false, false, FEATURES, config)?;
    announce_qemu_version(&vm.qemu);
    vm.qemu.stdin(Stdio::null());
    let deadline = Instant::now() + TIMEOUT;
    let mut child = ReapOnDrop(vm.qemu.spawn()?);
    let stream = accept_serial(&listener, &mut child, deadline)?;
    drop(listener);
    let mut writer = stream.try_clone()?;
    let (tx, rx) = mpsc::channel();
    let reader = spawn_serial_reader(stream, tx);

    let mut transcript = Vec::new();
    let mut ready_end: Option<usize> = None;
    let mut sent = 0usize;
    let result = loop {
        if Instant::now() >= deadline {
            let pending = steps
                .get(sent.saturating_sub(1))
                .map_or("ready", |step| step.name);
            break Err(XtaskError::Validation(format!(
                "serial input: timed out after {}s in step {pending:?}; tail {:?}",
                TIMEOUT.as_secs(),
                tail(&transcript)
            )));
        }
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(SerialEvent::Bytes(bytes)) => {
                print!("{}", String::from_utf8_lossy(&bytes));
                let _ = std::io::stdout().flush();
                transcript.extend_from_slice(&bytes);
            }
            Ok(SerialEvent::Closed) => {
                break Err(XtaskError::Validation(format!(
                    "serial input: QEMU closed the serial port early; tail {:?}",
                    tail(&transcript)
                )))
            }
            Ok(SerialEvent::Failed(error)) => break Err(XtaskError::Io(error)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(XtaskError::Validation(
                    "serial input: serial reader stopped".to_owned(),
                ))
            }
        }
        if find(&transcript, b"[FAIL]").is_some() {
            break Err(XtaskError::Validation(format!(
                "serial input: guest failed; tail {:?}",
                tail(&transcript)
            )));
        }
        if ready_end.is_none() {
            ready_end = find(&transcript, READY).map(|start| start + READY.len());
        }
        let Some(start) = ready_end else {
            continue;
        };
        let (_, records) = split_records(&transcript[start..]);
        while sent < steps.len() {
            let owed: usize = steps[..sent].iter().map(|step| step.records.len()).sum();
            if records.len() < owed {
                break;
            }
            writer.write_all(&steps[sent].send)?;
            writer.flush()?;
            sent += 1;
        }
        if records.iter().any(|record| record == DONE) {
            writer.write_all(&[DONE_ACK])?;
            writer.flush()?;
            break Ok(start);
        }
    };
    let start = match result {
        Ok(start) => start,
        Err(error) => {
            let _ = save_transcript(&transcript);
            return Err(error);
        }
    };
    let status = wait_for_exit(&mut child)?;
    drop(writer);
    let _ = reader.join();
    while let Ok(SerialEvent::Bytes(bytes)) = rx.try_recv() {
        transcript.extend_from_slice(&bytes);
    }
    save_transcript(&transcript)?;
    if status.code() != Some(QEMU_DEBUG_EXIT_SUCCESS) {
        return Err(XtaskError::Validation(format!(
            "serial input: QEMU exited with {status}, expected debug-exit success"
        )));
    }
    validate_boot(&transcript[..start])
        .and_then(|()| validate(&transcript[start..], &steps))
        .map_err(|reason| XtaskError::Validation(format!("serial input: {reason}")))?;
    let records: usize = steps.iter().map(|step| step.records.len()).sum();
    println!(
        "\n[TTY ] PASS host validated {} sent bytes, their echo and {records} records",
        steps.iter().map(|step| step.send.len()).sum::<usize>()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a correct guest prints for `steps`, with each step's echo split around its
    /// records the way an interrupt can split it.
    fn transcript(steps: &[Step]) -> Vec<u8> {
        let mut out = Vec::new();
        for step in steps {
            let half = step.echo.len() / 2;
            out.extend_from_slice(&step.echo[..half]);
            for (index, record) in step.records.iter().enumerate() {
                let line = match record {
                    Record::Exact(text) => text.clone(),
                    Record::Irq { .. } => {
                        "[TTY ] irq irqs=40 spurious=3 rearms=1 max_drained=16 wakes=9 notified=9"
                            .to_owned()
                    }
                };
                out.extend_from_slice(line.as_bytes());
                out.push(b'\n');
                if index == 0 {
                    out.extend_from_slice(&step.echo[half..]);
                }
            }
            if step.records.is_empty() {
                out.extend_from_slice(&step.echo[half..]);
            }
        }
        out
    }

    #[test]
    fn a_correct_transcript_validates() {
        let steps = script();
        assert_eq!(validate(&transcript(&steps), &steps), Ok(()));
    }

    #[test]
    fn one_changed_echo_byte_fails() {
        let steps = script();
        let mut out = transcript(&steps);
        let at = find(&out, b"cat").expect("echo present") + 1;
        out[at] = b'u';
        assert!(validate(&out, &steps).unwrap_err().contains("echo differs"));
    }

    #[test]
    fn a_missing_or_extra_echo_byte_fails() {
        let steps = script();
        let mut out = transcript(&steps);
        let at = find(&out, b"hel").expect("echo present");
        out.remove(at);
        assert!(validate(&out, &steps).is_err());
        let mut out = transcript(&steps);
        out.insert(0, b'z');
        assert!(validate(&out, &steps).is_err());
    }

    #[test]
    fn a_changed_or_missing_record_fails() {
        let steps = script();
        let out = transcript(&steps);
        let changed =
            String::from_utf8(out.clone())
                .expect("ascii")
                .replacen("hex=6f6b0a", "hex=6f6b", 1);
        assert!(validate(changed.as_bytes(), &steps)
            .unwrap_err()
            .contains("record"));
        let missing = String::from_utf8(out)
            .expect("ascii")
            .replacen("[TTY ] hold\n", "", 1);
        assert!(validate(missing.as_bytes(), &steps).is_err());
    }

    #[test]
    fn the_irq_record_needs_matching_wakes_and_notifications() {
        let bound = Record::Irq { wake_bound: 22 };
        let line = "[TTY ] irq irqs=40 spurious=3 rearms=1 max_drained=16 wakes=9 notified=9";
        assert_eq!(check_record(&bound, line), Ok(()));
        assert!(check_record(&bound, &line.replace("notified=9", "notified=8")).is_err());
        assert!(check_record(&bound, &line.replace("=9", "=0")).is_err());
        assert!(check_record(&bound, &line.replace("=9", "=23")).is_err());
        assert!(check_record(&bound, "[TTY ] irq wakes=1").is_err());
        assert!(
            check_record(&bound, &line.replace("max_drained=16", "max_drained=1")).is_err(),
            "one byte per interrupt is not a drain"
        );
        assert!(check_record(&bound, &line.replace("max_drained=16", "max_drained=17")).is_err());
    }

    #[test]
    fn split_records_keeps_echo_between_records_and_holds_back_an_unfinished_one() {
        let (echo, records) = split_records(b"ab[TTY ] one\ncd[TTY ] two\ne[TTY ] thr");
        assert_eq!(echo, b"abcde");
        assert_eq!(records, ["[TTY ] one", "[TTY ] two"]);
        let (echo, records) = split_records(b"xy[TT");
        assert_eq!(echo, b"xy", "a possible prefix is held back");
        assert!(records.is_empty());
    }

    #[test]
    fn the_script_covers_every_rule_with_exact_bytes() {
        let steps = script();
        let sent: Vec<u8> = steps.iter().flat_map(|step| step.send.clone()).collect();
        for byte in [b'\r', 0x08, 0x7f, 0x15, 0x04, 0x01, 0x1b] {
            assert!(sent.contains(&byte), "script sends {byte:#04x}");
        }
        assert!(sent
            .windows(301)
            .any(|w| w[..300].iter().all(|b| *b == b'x') && w[300] == b'\r'));
        let burst = steps
            .iter()
            .find(|step| step.name == "burst of lines")
            .expect("burst");
        assert_eq!(burst.send.iter().filter(|byte| **byte == b'\r').count(), 6);
        let full = steps
            .iter()
            .find(|step| step.name == "committed buffer full")
            .expect("fill");
        assert_eq!(full.send.len(), COMMITTED_CAPACITY + b"ninth\rlost".len());
        let last = steps.last().expect("steps");
        assert_eq!(last.send, b"\x04");
    }

    #[test]
    fn the_stats_record_counts_every_sent_byte() {
        let steps = script();
        let total: usize = steps.iter().map(|step| step.send.len()).sum();
        let stats = steps
            .last()
            .and_then(|step| step.records.get(1))
            .expect("stats record");
        assert!(matches!(stats, Record::Exact(text) if text.contains(&format!(" bytes={total} "))));
    }

    #[test]
    fn validate_boot_requires_the_enable_line_with_no_stale_bytes() {
        assert_eq!(
            validate_boot(b"[BOOT] x\n[TTY ] receive enabled irq=4 vector=0x30 stale=0\n"),
            Ok(())
        );
        assert!(validate_boot(b"[TTY ] receive enabled irq=4 vector=0x30 stale=2\n").is_err());
        assert!(validate_boot(b"[BOOT] x\n").is_err());
    }
}
