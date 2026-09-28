//! Host tests for the QMP client, endpoint and script driver against the
//! scripted fake peer.

use std::fs;
use std::io::Read;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::ExitStatus;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use super::client::{EVENT_RING_CAPACITY, MAX_LINE_BYTES};
use super::fake::{self, Act};
use super::image::Screenshot;
use super::input::MAX_EVENTS_PER_COMMAND;
use super::json::JsonValue;
use super::{InputAction, MouseButton, QCode, QmpClient, QmpEndpoint, QmpError, QmpTimeouts};
use super::{QmpScriptDriver, ScriptStep};
use crate::{AcceptanceDriver, DriverWake, OutputEvent, XtaskError};

const GENEROUS: QmpTimeouts = QmpTimeouts {
    connect: Duration::from_secs(10),
    greeting: Duration::from_secs(10),
    command: Duration::from_secs(10),
};
const SHORT: Duration = Duration::from_millis(250);

type Peer = JoinHandle<Result<Vec<JsonValue>, String>>;

/// Binds an endpoint, lets `acts` script the fake QEMU (given this run's
/// nonce), and accepts it.
fn session(
    timeouts: QmpTimeouts,
    acts: impl FnOnce(&str) -> Vec<Act>,
) -> (Result<QmpClient, QmpError>, Peer) {
    let endpoint = QmpEndpoint::bind().expect("bind");
    let peer = fake::spawn(endpoint.port(), acts(endpoint.nonce()));
    (endpoint.accept(timeouts), peer)
}

/// A handshaken client whose peer then plays `acts`.
fn connected(acts: Vec<Act>) -> (QmpClient, Peer) {
    let (client, peer) = session(GENEROUS, |nonce| {
        let mut all = fake::handshake(nonce);
        all.extend(acts);
        all
    });
    (
        client.unwrap_or_else(|error| panic!("handshake: {error}")),
        peer,
    )
}

fn error_of<T>(result: Result<T, QmpError>) -> QmpError {
    match result {
        Ok(_) => panic!("expected a QMP error"),
        Err(error) => error,
    }
}

fn requests(peer: Peer) -> Vec<JsonValue> {
    peer.join()
        .expect("fake thread")
        .unwrap_or_else(|error| panic!("fake peer: {error}"))
}

fn commands(requests: &[JsonValue]) -> Vec<&str> {
    requests
        .iter()
        .filter_map(|request| request.get("execute").and_then(JsonValue::as_str))
        .collect()
}

fn assert_refused(port: u16) {
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    assert!(
        TcpStream::connect_timeout(&address, Duration::from_secs(2)).is_err(),
        "127.0.0.1:{port} still accepts connections"
    );
}

fn assert_within(started: Instant, limit: Duration) {
    let elapsed = started.elapsed();
    assert!(elapsed < limit * 3, "took {elapsed:?}, limit {limit:?}");
}

fn temp_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("xtask-qmp-{}-{name}", std::process::id()))
}

#[test]
fn handshake_negotiates_capabilities_and_verifies_the_run_nonce() {
    let (client, peer) = connected(Vec::new());
    assert_eq!(client.version().to_string(), "8.2.2");
    assert_eq!(client.package(), "fake");
    drop(client);
    let requests = requests(peer);
    assert_eq!(commands(&requests), ["qmp_capabilities", "query-name"]);
    // OOB stays off: capabilities are negotiated without `enable`.
    assert!(requests[0].get("arguments").is_none());
    let ids: Vec<_> = requests
        .iter()
        .map(|request| request.get("id").and_then(JsonValue::as_str).unwrap())
        .collect();
    assert_eq!(ids, ["xtask-1", "xtask-2"]);
}

#[test]
fn greeting_without_a_qmp_object_is_a_protocol_error() {
    let (client, _peer) = session(GENEROUS, |_| {
        vec![Act::send("{\"hello\": {}}\n"), Act::WaitEof]
    });
    let error = error_of(client);
    assert!(
        matches!(&error, QmpError::Protocol { context, .. } if context == "greeting"),
        "{error}"
    );
}

#[test]
fn malformed_greeting_names_the_phase() {
    let (client, _peer) = session(GENEROUS, |_| vec![Act::send("{\"QMP\": \n"), Act::WaitEof]);
    let error = error_of(client);
    assert!(matches!(error, QmpError::Malformed { .. }), "{error}");
    assert!(
        error
            .to_string()
            .starts_with("QMP greeting: malformed JSON"),
        "{error}"
    );
}

#[test]
fn peer_closing_before_the_greeting_is_a_disconnect() {
    let (client, _peer) = session(GENEROUS, |_| Vec::new());
    let error = error_of(client);
    assert!(
        matches!(
            error,
            QmpError::Disconnected {
                partial_line: false,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn silent_peer_hits_the_greeting_deadline() {
    let timeouts = QmpTimeouts {
        greeting: SHORT,
        ..GENEROUS
    };
    let started = Instant::now();
    let (client, _peer) = session(timeouts, |_| vec![Act::WaitEof]);
    let error = error_of(client);
    assert!(matches!(error, QmpError::Timeout { .. }), "{error}");
    assert_within(started, SHORT);
}

#[test]
fn qemu_older_than_the_minimum_is_rejected() {
    let (client, _peer) = session(GENEROUS, |_| {
        vec![Act::send(fake::greeting(2, 5, 0)), Act::WaitEof]
    });
    let error = error_of(client);
    assert!(
        matches!(error, QmpError::UnsupportedVersion { .. }),
        "{error}"
    );
}

#[test]
fn capabilities_error_carries_class_and_description() {
    let (client, _peer) = session(GENEROUS, |_| {
        vec![
            Act::send(fake::greeting(8, 2, 0)),
            Act::reply("qmp_capabilities", |id, _| {
                format!("{{\"error\": {{\"class\": \"GenericError\", \"desc\": \"nope\"}}, \"id\": \"{id}\"}}\n")
            }),
            Act::WaitEof,
        ]
    });
    let error = error_of(client);
    assert_eq!(
        error.to_string(),
        "QMP qmp_capabilities (id xtask-1) failed: GenericError: nope"
    );
}

#[test]
fn peer_reporting_another_name_is_refused() {
    let (client, _peer) = session(GENEROUS, |_| {
        vec![
            Act::send(fake::greeting(8, 2, 0)),
            Act::returns("qmp_capabilities", "{}"),
            Act::returns("query-name", "{\"name\": \"someone-else\"}"),
            Act::WaitEof,
        ]
    });
    let error = error_of(client);
    assert!(
        matches!(&error, QmpError::PeerMismatch { got, .. } if got == "someone-else"),
        "{error}"
    );
}

#[test]
fn command_error_names_command_id_class_and_description() {
    let (mut client, _peer) = connected(vec![Act::reply("no-such-command", |id, _| {
        format!("{{\"id\": \"{id}\", \"error\": {{\"desc\": \"The command no-such-command has not been found\", \"class\": \"CommandNotFound\"}}}}\n")
    })]);
    let error = error_of(client.execute("no-such-command", None, SHORT * 20));
    assert_eq!(
        error.to_string(),
        "QMP no-such-command (id xtask-3) failed: CommandNotFound: The command no-such-command has not been found"
    );
}

#[test]
fn reply_with_another_id_is_an_id_mismatch() {
    let (mut client, _peer) = connected(vec![Act::reply("query-status", |_, _| {
        "{\"return\": {}, \"id\": \"xtask-99\"}\n".to_owned()
    })]);
    let error = error_of(client.execute("query-status", None, GENEROUS.command));
    assert!(
        matches!(&error, QmpError::IdMismatch { got: Some(got), expected, .. }
            if got == "xtask-99" && expected == "xtask-3"),
        "{error}"
    );
}

#[test]
fn reply_without_an_id_is_an_id_mismatch() {
    let (mut client, _peer) = connected(vec![Act::reply("query-status", |_, _| {
        "{\"return\": {}}\n".to_owned()
    })]);
    let error = error_of(client.execute("query-status", None, GENEROUS.command));
    assert!(
        matches!(error, QmpError::IdMismatch { got: None, .. }),
        "{error}"
    );
}

#[test]
fn reply_with_both_return_and_error_is_a_protocol_error() {
    let (mut client, _peer) = connected(vec![Act::reply("query-status", |id, _| {
        format!("{{\"return\": {{}}, \"error\": {{}}, \"id\": \"{id}\"}}\n")
    })]);
    let error = error_of(client.execute("query-status", None, GENEROUS.command));
    assert!(matches!(error, QmpError::Protocol { .. }), "{error}");
}

#[test]
fn malformed_reply_names_the_command() {
    let (mut client, _peer) = connected(vec![Act::reply("query-status", |_, _| {
        "{\"return\": {\"running\": tru}}\n".to_owned()
    })]);
    let error = error_of(client.execute("query-status", None, GENEROUS.command));
    assert!(matches!(error, QmpError::Malformed { .. }), "{error}");
    assert!(
        error.to_string().contains("query-status (id xtask-3)"),
        "{error}"
    );
}

#[test]
fn unanswered_command_times_out_at_its_deadline() {
    let (mut client, _peer) = connected(vec![Act::silent("query-status"), Act::WaitEof]);
    let started = Instant::now();
    let error = error_of(client.execute("query-status", None, SHORT));
    assert!(
        matches!(&error, QmpError::Timeout { waited, .. } if *waited == SHORT),
        "{error}"
    );
    assert_within(started, SHORT);
}

#[test]
fn disconnect_mid_reply_is_reported_as_a_partial_line() {
    let (mut client, _peer) = connected(vec![Act::reply("query-status", |_, _| {
        "{\"return\": {\"runn".to_owned()
    })]);
    let error = error_of(client.execute("query-status", None, GENEROUS.command));
    assert!(
        matches!(
            error,
            QmpError::Disconnected {
                partial_line: true,
                ..
            }
        ),
        "{error}"
    );
}

#[test]
fn reply_arriving_one_byte_at_a_time_is_reassembled() {
    let (endpoint, nonce) = {
        let endpoint = QmpEndpoint::bind().expect("bind");
        let nonce = endpoint.nonce().to_owned();
        (endpoint, nonce)
    };
    let mut acts = vec![Act::SendBytewise(fake::greeting(9, 0, 1))];
    acts.extend(fake::handshake(&nonce).into_iter().skip(1));
    acts.push(Act::silent("query-status"));
    acts.push(Act::SendBytewise(
        "{\"return\": {\"status\": \"running\", \"running\": true}, \"id\": \"xtask-3\"}\r\n"
            .to_owned(),
    ));
    let peer = fake::spawn(endpoint.port(), acts);
    let mut client = endpoint.accept(GENEROUS).expect("accept");
    assert_eq!(client.version().to_string(), "9.0.1");
    let reply = client
        .execute("query-status", None, GENEROUS.command)
        .expect("status");
    assert_eq!(
        reply.get("status").and_then(JsonValue::as_str),
        Some("running")
    );
    drop(client);
    requests(peer);
}

#[test]
fn events_before_a_reply_are_kept_in_a_bounded_ring() {
    let total = EVENT_RING_CAPACITY + 6;
    let (mut client, _peer) = connected(vec![Act::reply("query-status", move |id, _| {
        let mut text = String::new();
        for n in 0..total {
            text.push_str(&format!(
                "{{\"timestamp\": {{\"seconds\": 1, \"microseconds\": 2}}, \"event\": \"TICK\", \"data\": {{\"n\": {n}}}}}\n"
            ));
        }
        text.push_str(&format!("{{\"return\": {{}}, \"id\": \"{id}\"}}\n"));
        text
    })]);
    client
        .execute("query-status", None, GENEROUS.command)
        .expect("reply after events");
    let events = client.take_events();
    assert_eq!(events.len(), EVENT_RING_CAPACITY);
    assert_eq!(client.dropped_events(), 6);
    let first = events[0].data.as_ref().and_then(|data| data.get("n"));
    assert_eq!(first.and_then(JsonValue::as_u64), Some(6));
    assert!(events.iter().all(|event| event.name == "TICK"));
    assert!(client.take_events().is_empty());
}

#[test]
fn oversize_line_is_rejected_without_unbounded_buffering() {
    let (mut client, _peer) = connected(vec![Act::reply("query-status", |_, _| {
        "x".repeat(MAX_LINE_BYTES + 16)
    })]);
    let error = error_of(client.execute("query-status", None, GENEROUS.command));
    assert!(
        matches!(error, QmpError::LineTooLong { limit, .. } if limit == MAX_LINE_BYTES),
        "{error}"
    );
}

#[test]
fn quit_waits_for_close_and_keeps_the_shutdown_event() {
    let (mut client, peer) = connected(vec![Act::reply("quit", |id, _| {
        format!("{{\"return\": {{}}, \"id\": \"{id}\"}}\n{{\"event\": \"SHUTDOWN\", \"data\": {{\"guest\": false}}}}\n")
    })]);
    client
        .execute("quit", None, GENEROUS.command)
        .expect("quit");
    client
        .wait_for_close(GENEROUS.command)
        .expect("peer closes");
    let names: Vec<_> = client.take_events().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["SHUTDOWN"]);
    requests(peer);
}

#[test]
fn no_connection_times_out_and_releases_the_port() {
    let endpoint = QmpEndpoint::bind().expect("bind");
    let port = endpoint.port();
    let started = Instant::now();
    let error = error_of(endpoint.accept(QmpTimeouts {
        connect: SHORT,
        ..GENEROUS
    }));
    assert!(matches!(error, QmpError::AcceptTimeout { .. }), "{error}");
    assert_within(started, SHORT);
    assert_refused(port);
}

#[test]
fn cancel_before_connect_releases_the_port_promptly() {
    let endpoint = QmpEndpoint::bind().expect("bind");
    let port = endpoint.port();
    let (woke_tx, woke_rx) = mpsc::channel();
    let mut pending = endpoint.listen(GENEROUS, move || {
        let _ = woke_tx.send(());
    });
    let started = Instant::now();
    pending.cancel();
    assert_within(started, SHORT);
    assert!(pending.try_take().is_none());
    assert!(
        woke_rx.try_recv().is_err(),
        "a cancelled accept must not notify"
    );
    assert_refused(port);
}

#[test]
fn cancel_during_the_handshake_does_not_wait_for_its_deadline() {
    let endpoint = QmpEndpoint::bind().expect("bind");
    let (connected_tx, connected_rx) = mpsc::channel();
    let peer = fake::spawn(
        endpoint.port(),
        vec![Act::Notify(connected_tx), Act::WaitEof],
    );
    let mut pending = endpoint.listen(GENEROUS, || {});
    connected_rx
        .recv_timeout(GENEROUS.connect)
        .expect("fake connected");
    let started = Instant::now();
    pending.cancel();
    assert_within(started, SHORT * 4);
    requests(peer);
}

#[test]
fn only_one_connection_is_ever_accepted() {
    let endpoint = QmpEndpoint::bind().expect("bind");
    let port = endpoint.port();
    let peer = fake::spawn(port, fake::handshake(endpoint.nonce()));
    let client = endpoint.accept(GENEROUS).expect("accept");
    assert_refused(port);
    drop(client);
    requests(peer);
}

#[test]
fn closing_the_client_closes_the_socket() {
    let (client, peer) = connected(vec![Act::WaitEof]);
    client.close();
    requests(peer);
}

#[test]
fn input_events_use_the_qmp_input_event_schema() {
    let (mut client, peer) = connected(vec![Act::returns("input-send-event", "{}")]);
    let mut actions = InputAction::tap(QCode::A).to_vec();
    actions.extend(InputAction::move_rel(5, -5));
    actions.push(InputAction::Button {
        button: MouseButton::WheelUp,
        down: true,
    });
    client
        .send_input(&actions, GENEROUS.command)
        .expect("input");
    drop(client);
    let requests = requests(peer);
    let input = requests[2].get("arguments").expect("arguments").to_json();
    assert_eq!(
        input,
        concat!(
            r#"{"events":["#,
            r#"{"type":"key","data":{"down":true,"key":{"type":"qcode","data":"a"}}},"#,
            r#"{"type":"key","data":{"down":false,"key":{"type":"qcode","data":"a"}}},"#,
            r#"{"type":"rel","data":{"axis":"x","value":5}},"#,
            r#"{"type":"rel","data":{"axis":"y","value":-5}},"#,
            r#"{"type":"btn","data":{"down":true,"button":"wheel-up"}}"#,
            r#"]}"#
        )
    );
}

#[test]
fn input_batches_outside_the_bound_are_rejected_before_sending() {
    let (mut client, peer) = connected(vec![Act::returns("query-status", "{}")]);
    let too_many = vec![InputAction::tap(QCode::B)[0]; MAX_EVENTS_PER_COMMAND + 1];
    for batch in [&[][..], &too_many[..]] {
        let error = error_of(client.send_input(batch, GENEROUS.command));
        assert!(matches!(error, QmpError::InvalidRequest { .. }), "{error}");
    }
    client
        .execute("query-status", None, GENEROUS.command)
        .expect("stream still in sync");
    drop(client);
    assert_eq!(
        commands(&requests(peer)),
        ["qmp_capabilities", "query-name", "query-status"]
    );
}

#[test]
fn qcode_names_are_unique() {
    let mut names: Vec<_> = QCode::ALL.iter().map(|qcode| qcode.name()).collect();
    let count = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), count);
}

fn write_ppm_reply(pixels: &'static [u8]) -> Act {
    Act::reply("screendump", move |id, request| {
        let filename = request
            .get("arguments")
            .and_then(|arguments| arguments.get("filename"))
            .and_then(JsonValue::as_str)
            .expect("screendump filename");
        let mut ppm = b"P6\n2 1\n255\n".to_vec();
        ppm.extend_from_slice(pixels);
        fs::write(filename, ppm).expect("fake writes ppm");
        format!("{{\"return\": {{}}, \"id\": \"{id}\"}}\n")
    })
}

#[test]
fn screendump_reads_back_the_ppm_qemu_wrote() {
    let path = temp_path("screendump.ppm");
    let (mut client, _peer) = connected(vec![write_ppm_reply(&[1, 2, 3, 250, 251, 252])]);
    let shot = client
        .screendump(&path, GENEROUS.command)
        .expect("screendump");
    assert_eq!((shot.width(), shot.height()), (2, 1));
    assert_eq!(shot.pixel(1, 0), Some([250, 251, 252]));
    let _ = fs::remove_file(path);
}

#[test]
fn screendump_never_reads_a_stale_file() {
    let path = temp_path("stale.ppm");
    fs::write(&path, b"P6\n1 1\n255\n\0\0\0").expect("stale file");
    let (mut client, _peer) = connected(vec![Act::returns("screendump", "{}")]);
    let error = error_of(client.screendump(&path, GENEROUS.command));
    assert!(matches!(error, QmpError::Io { .. }), "{error}");
}

#[test]
fn screendump_of_a_truncated_ppm_is_an_image_error() {
    let path = temp_path("truncated.ppm");
    let (mut client, _peer) = connected(vec![write_ppm_reply(&[1, 2, 3])]);
    let error = error_of(client.screendump(&path, GENEROUS.command));
    assert!(matches!(error, QmpError::Image { .. }), "{error}");
    let _ = fs::remove_file(path);
}

#[test]
fn screendump_requires_an_absolute_path() {
    let (mut client, peer) = connected(Vec::new());
    let error = error_of(client.screendump("relative.ppm".as_ref(), GENEROUS.command));
    assert!(matches!(error, QmpError::InvalidRequest { .. }), "{error}");
    drop(client);
    assert_eq!(
        commands(&requests(peer)),
        ["qmp_capabilities", "query-name"]
    );
}

struct DriverHarness {
    driver: QmpScriptDriver,
    wake: mpsc::Receiver<OutputEvent>,
    deadline: Instant,
}

impl DriverHarness {
    fn start(lane: &'static str, steps: Vec<ScriptStep>) -> Self {
        let root = std::env::temp_dir().join(format!("xtask-qmp-driver-{}", std::process::id()));
        let mut driver =
            QmpScriptDriver::with_timeouts(lane, steps, &root, GENEROUS).expect("driver");
        let (tx, wake) = mpsc::channel();
        driver.start(DriverWake(tx)).expect("start");
        Self {
            driver,
            wake,
            deadline: Instant::now() + Duration::from_secs(30),
        }
    }

    fn nonce(&self) -> String {
        self.driver.qemu_args()[1].clone()
    }

    /// Plays the fake handshake plus `acts`, then delivers the wake the
    /// acceptance loop would.
    fn connect(&mut self, acts: Vec<Act>) -> Peer {
        let mut all = fake::handshake(&self.nonce());
        all.extend(acts);
        let peer = fake::spawn(self.driver.port(), all);
        match self.wake.recv_timeout(GENEROUS.connect) {
            Ok(OutputEvent::DriverWake) => {}
            _ => panic!("no driver wake after connect"),
        }
        self.driver.on_wake(self.deadline).expect("on_wake");
        peer
    }

    fn serial(&mut self, text: &str) -> Result<(), XtaskError> {
        self.driver.on_serial(text, self.deadline)
    }
}

#[test]
fn qemu_args_point_qemu_at_the_endpoint_with_the_nonce() {
    let harness = DriverHarness::start("args", Vec::new());
    let args = harness.driver.qemu_args();
    assert_eq!(args[0], "-name");
    assert!(args[1].starts_with("clean-slate-"));
    assert_eq!(args[2], "-qmp");
    assert_eq!(args[3], format!("tcp:127.0.0.1:{}", harness.driver.port()));
}

#[test]
fn stimuli_wait_for_a_complete_matching_line() {
    let mut harness = DriverHarness::start(
        "complete-lines",
        vec![
            ScriptStep::AwaitLine("[T] go"),
            ScriptStep::Input(InputAction::tap(QCode::A).to_vec()),
        ],
    );
    let peer = harness.connect(vec![Act::returns("input-send-event", "{}")]);
    harness.serial("[T] g").unwrap();
    harness.serial("o").unwrap();
    assert!(!harness.driver.is_complete(), "acted on a partial line");
    harness.serial("\r\n").unwrap();
    assert!(harness.driver.is_complete());
    harness.driver.shutdown();
    assert_eq!(
        commands(&requests(peer)),
        ["qmp_capabilities", "query-name", "input-send-event"]
    );
}

#[test]
fn one_serial_line_satisfies_one_await() {
    let mut harness = DriverHarness::start(
        "one-line-one-await",
        vec![ScriptStep::AwaitLine("tick"), ScriptStep::AwaitLine("tick")],
    );
    harness.serial("tick\nother\n").unwrap();
    assert!(!harness.driver.is_complete());
    harness.serial("tick\n").unwrap();
    assert!(harness.driver.is_complete());
}

#[test]
fn lines_seen_before_qemu_connects_are_replayed() {
    let mut harness = DriverHarness::start(
        "buffer-before-connect",
        vec![
            ScriptStep::AwaitLine("ready"),
            ScriptStep::Command {
                command: "query-status",
                arguments: None,
                check: |_| Ok(()),
            },
        ],
    );
    harness.serial("ready\n").unwrap();
    assert!(!harness.driver.is_complete());
    let peer = harness.connect(vec![Act::returns("query-status", "{}")]);
    assert!(harness.driver.is_complete());
    harness.driver.shutdown();
    requests(peer);
}

#[test]
fn capture_runs_before_teardown_on_an_unterminated_final_marker() {
    let mut harness = DriverHarness::start(
        "capture-before-teardown",
        vec![
            ScriptStep::AwaitLine("[T] presented"),
            ScriptStep::Screendump {
                name: "frame",
                check: |shot| match shot.pixel(0, 0) {
                    Some([9, 8, 7]) => Ok(()),
                    other => Err(format!("{other:?}")),
                },
            },
        ],
    );
    let peer = harness.connect(vec![write_ppm_reply(&[9, 8, 7, 0, 0, 0])]);
    harness.serial("[T] presented").unwrap();
    assert!(harness.driver.captures().is_empty());
    harness
        .driver
        .before_teardown(harness.deadline)
        .expect("script completes at teardown");
    let [capture] = harness.driver.captures() else {
        panic!("one capture expected");
    };
    let mut signature = [0u8; 8];
    fs::File::open(&capture.png)
        .and_then(|mut file| file.read_exact(&mut signature))
        .expect("png written");
    assert_eq!(&signature, b"\x89PNG\r\n\x1a\n");
    assert!(!harness.driver.run_dir().join("frame.ppm").exists());
    harness.driver.shutdown();
    requests(peer);
}

#[test]
fn failed_screenshot_check_keeps_both_images() {
    let mut harness = DriverHarness::start(
        "failed-check",
        vec![ScriptStep::Screendump {
            name: "bad",
            check: |_: &Screenshot| Err("wrong colour".to_owned()),
        }],
    );
    let peer_acts = vec![write_ppm_reply(&[0; 6])];
    let mut all = fake::handshake(&harness.nonce());
    all.extend(peer_acts);
    let peer = fake::spawn(harness.driver.port(), all);
    let _ = harness.wake.recv_timeout(GENEROUS.connect);
    let error = harness.driver.on_wake(harness.deadline).unwrap_err();
    assert!(error.to_string().contains("wrong colour"), "{error}");
    assert!(harness.driver.run_dir().join("bad.png").exists());
    assert!(harness.driver.run_dir().join("bad.ppm").exists());
    harness.driver.shutdown();
    requests(peer);
}

fn command_not_found(command: &'static str) -> Act {
    Act::reply(command, |id, _| {
        format!("{{\"error\": {{\"class\": \"CommandNotFound\", \"desc\": \"missing\"}}, \"id\": \"{id}\"}}\n")
    })
}

#[test]
fn expected_command_error_passes_only_for_its_class() {
    let steps = || {
        vec![ScriptStep::CommandError {
            command: "no-such-command",
            class: "CommandNotFound",
        }]
    };
    let mut harness = DriverHarness::start("expected-error", steps());
    let peer = harness.connect(vec![command_not_found("no-such-command")]);
    assert!(harness.driver.is_complete());
    harness.driver.shutdown();
    requests(peer);

    for (lane, reply) in [
        (
            "wrong-error-class",
            Act::reply("no-such-command", |id, _| {
                format!("{{\"error\": {{\"class\": \"GenericError\", \"desc\": \"x\"}}, \"id\": \"{id}\"}}\n")
            }),
        ),
        ("unexpected-success", Act::returns("no-such-command", "{}")),
    ] {
        let mut harness = DriverHarness::start(lane, steps());
        let mut all = fake::handshake(&harness.nonce());
        all.push(reply);
        let peer = fake::spawn(harness.driver.port(), all);
        let _ = harness.wake.recv_timeout(GENEROUS.connect);
        let error = harness.driver.on_wake(harness.deadline).unwrap_err();
        assert!(
            error.to_string().contains("no-such-command"),
            "{lane}: {error}"
        );
        harness.driver.shutdown();
        requests(peer);
    }
}

#[test]
fn teardown_with_an_unfinished_script_names_the_step() {
    let mut harness = DriverHarness::start(
        "unfinished",
        vec![ScriptStep::AwaitLine("a"), ScriptStep::AwaitLine("b")],
    );
    let peer = harness.connect(Vec::new());
    harness.serial("a\n").unwrap();
    let error = harness
        .driver
        .before_teardown(harness.deadline)
        .unwrap_err();
    assert!(
        error.to_string().contains("step 2/2 (await line `b`)"),
        "{error}"
    );
    harness.driver.shutdown();
    requests(peer);
}

#[test]
fn teardown_before_qemu_connects_is_an_error() {
    let mut harness = DriverHarness::start("never-connected", vec![ScriptStep::Quit]);
    let error = harness
        .driver
        .before_teardown(harness.deadline)
        .unwrap_err();
    assert!(error.to_string().contains("never connected"), "{error}");
}

#[test]
fn qemu_exiting_before_it_connects_is_reported_and_releases_the_port() {
    let mut harness = DriverHarness::start("exited-early", vec![ScriptStep::Quit]);
    let port = harness.driver.port();
    let error = harness.driver.after_exit(failed_exit()).unwrap_err();
    assert!(
        error.to_string().contains("exited before connecting"),
        "{error}"
    );
    assert_refused(port);
}

#[test]
fn shutdown_cancels_a_pending_accept() {
    let mut harness = DriverHarness::start("shutdown-pending", vec![ScriptStep::Quit]);
    let port = harness.driver.port();
    let started = Instant::now();
    harness.driver.shutdown();
    assert_within(started, SHORT);
    assert_refused(port);
}

#[test]
fn peer_probe_sees_qemu_close_after_shutdown() {
    let mut harness = DriverHarness::start("peer-probe", Vec::new());
    harness.driver.keep_peer_probe();
    let peer = harness.connect(Vec::new());
    requests(peer);
    harness.driver.shutdown();
    assert!(harness.driver.peer_closed_within(GENEROUS.command).unwrap());
}

#[cfg(windows)]
fn failed_exit() -> ExitStatus {
    std::os::windows::process::ExitStatusExt::from_raw(1)
}

#[cfg(unix)]
fn failed_exit() -> ExitStatus {
    std::os::unix::process::ExitStatusExt::from_raw(1 << 8)
}
