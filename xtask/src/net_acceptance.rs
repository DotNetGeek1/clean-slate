//! #221 acceptance lane (`cargo xtask test-net-acceptance`, #355): the network stack on QEMU's
//! user-mode network instead of the hermetic M7 fixture peer, with a CA of the lane's own.
//!
//! - The guest NIC is `-netdev user,restrict=on`: slirp leases the guest an address with DHCP
//!   and drops everything else the guest sends, UDP included, except the two `guestfwd` rules.
//!   Those forward TCP to [`GUEST_SERVER`] port 53 and 443 through [`RELAY_COMMAND`] (this
//!   binary, one process per connection) to a DNS-over-TCP server and an HTTPS server the lane
//!   runs on host loopback.
//! - The kernel is `net-acceptance-self-test`: the M7.8 converged lane, launched like production
//!   (no `cfg(clean_slate_fixture_network)`): a DHCP network whose resolver is
//!   `dns=tcp:` [`GUEST_SERVER`], and as its only trust anchor the lane CA (generated once into
//!   `target/net-acceptance`, never the M7 test CA). Its probe resolves [`SERVER_NAME`] and
//!   fetches `/` over HTTPS twice.
//! - The server certificate is issued at each run and valid only from ten minutes before the run
//!   to a day after, so the guest's certificate check needs the wall clock.
//! - Before the boot: the production network service's feature set must not include
//!   `clean-slate-network/fixture`. After it: the kernel image must hold the lane CA and not the
//!   M7 test CA, and the servers must have answered one query and two fetches.

use std::fs;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Shutdown, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use time::{macros::datetime, OffsetDateTime};

use crate::marker_spec::MarkerSet;
use crate::{
    kernel_artifact, run_vm_inner_with_config, workspace_root, VmLaunchConfig, XtaskError,
    M7_QEMU_NET_DEVICE, RDRAND_CPU_MODEL,
};

const LANE: &str = "test-net-acceptance";
const FEATURE: &str = "net-acceptance-self-test";
const TIMEOUT: Duration = Duration::from_secs(90);

/// The name the guest resolves and the server certificate names.
pub(crate) const SERVER_NAME: &str = "net.acceptance.test";
/// The address the guest reaches the lane's servers at: slirp's guest-forward address, not on
/// the host. [`SERVER_NAME`] resolves to it.
const GUEST_SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 100);
const DNS_PORT: u16 = 53;
const HTTPS_PORT: u16 = 443;
const DNS_TTL_SECS: u32 = 60;
/// slirp's gateway: the in-flight phase parks a receive on a UDP port of it that, under
/// `restrict=on`, never answers.
const SILENT_PEER: &str = "10.0.2.2:9";

const HTTP_REQUEST: &[u8] = b"GET / HTTP/1.0\r\nHost: net.acceptance.test\r\n\r\n";
const HTTP_RESPONSE: &[u8] = b"HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nok\n";
/// The converged client fetches twice over TLS and resolves once (the second fetch reuses the
/// answer).
const EXPECTED_FETCHES: usize = 2;
const EXPECTED_QUERIES: usize = 1;

/// The hidden subcommand QEMU runs for each forwarded connection: `<exe> RELAY_COMMAND <port>`.
pub(crate) const RELAY_COMMAND: &str = "net-acceptance-relay";

const M7_TEST_CA: &str = "xtask/fixtures/m7/ca.crt";

/// The M7.8 markers, ending in this lane's own PASS.
const MARKERS: [&str; 20] = [
    "[NET ] raw backend=virtio mac=",
    "[NET ] service started pid=",
    "[AUD ] net op=resolve actor=",
    "outcome=allow resource=20992 generation=",
    "[AUD ] net op=connect actor=",
    "outcome=allow resource=20992 generation=",
    "[NET ] session open id=",
    "[NET ] tls reuse ok pid=",
    "[NET ] converged dns+tls ok len=",
    "[NET ] holder exit reclaimed sessions=",
    "[NET ] denied pid=",
    "[AUD ] net op=connect actor=",
    "outcome=deny resource=20992 generation=",
    "reason=no-authority",
    "[NET ] service restarted pid=",
    "[NET ] inflight failed count=1",
    "[NET ] stale-session denied generation=",
    "[NET ] capacity baseline ok",
    "[NET ] capacity loop left no request wakes pending",
    "[NET ] acceptance PASS",
];

pub(crate) fn run() -> Result<(), XtaskError> {
    check_service_has_no_fixture()?;
    let dir = workspace_root().join("target").join("net-acceptance");
    let ca = LaneCa::load_or_create(&dir)?;
    let server_config = Arc::new(ca.server_config()?);

    let dns = Server::start("dns", serve_dns)?;
    let https = Server::start("https", move |stream| serve_https(stream, &server_config))?;

    let _env = BuildEnv::set(&[
        ("CLEAN_SLATE_NET_STATIC", None),
        (
            "CLEAN_SLATE_NET_DHCP",
            Some(format!(
                "on,dns=tcp:{GUEST_SERVER}:{DNS_PORT},tls_name={SERVER_NAME}"
            )),
        ),
        (
            "CLEAN_SLATE_TRUST_ANCHORS_DIR",
            Some(ca.anchors_dir.display().to_string()),
        ),
        ("CLEAN_SLATE_NET_PROBE", Some(probe_spec())),
    ]);
    let relay = std::env::current_exe()?;
    let netdev = netdev_arg(&relay, dns.port, https.port)?;
    let result = run_vm_inner_with_config(
        false,
        false,
        &[FEATURE],
        Some((MarkerSet::Ordered(&MARKERS), TIMEOUT)),
        VmLaunchConfig {
            kernel_release: true,
            cpu_model: Some(RDRAND_CPU_MODEL),
            extra_args: vec![
                "-netdev".to_owned(),
                netdev,
                "-device".to_owned(),
                M7_QEMU_NET_DEVICE.to_owned(),
            ],
            ..VmLaunchConfig::default()
        },
    );
    let queries = dns.served();
    let fetches = https.served();
    result?;
    if queries != EXPECTED_QUERIES || fetches != EXPECTED_FETCHES {
        return Err(XtaskError::Validation(format!(
            "{LANE}: servers answered {queries} DNS quer(ies) and {fetches} HTTPS fetch(es); \
             expected {EXPECTED_QUERIES} and {EXPECTED_FETCHES}"
        )));
    }
    check_image_trust(&ca.anchor_der)?;
    println!("[NET ] {LANE}: {queries} DNS-over-TCP query and {fetches} HTTPS fetches through restricted slirp");
    println!("[NET ] {LANE} PASS");
    Ok(())
}

/// `-netdev user,…`: DHCP from slirp, nothing out but the two forwards.
fn netdev_arg(relay: &Path, dns_port: u16, https_port: u16) -> Result<String, XtaskError> {
    let relay = relay.display().to_string();
    // QEMU splits `-netdev` on commas and runs `cmd:` through `/bin/sh -c`.
    if relay.contains([',', '\'', ' ']) {
        return Err(XtaskError::Validation(format!(
            "{LANE}: the xtask path {relay:?} has a comma, quote or space, which guestfwd cannot carry"
        )));
    }
    let forward = |guest_port: u16, host_port: u16| {
        format!("guestfwd=tcp:{GUEST_SERVER}:{guest_port}-cmd:{relay} {RELAY_COMMAND} {host_port}")
    };
    Ok(format!(
        "user,id=n0,restrict=on,{},{}",
        forward(DNS_PORT, dns_port),
        forward(HTTPS_PORT, https_port)
    ))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `CLEAN_SLATE_NET_PROBE` for the acceptance kernel (see `kernel/build.rs`).
fn probe_spec() -> String {
    format!(
        "name={SERVER_NAME},ipv4={GUEST_SERVER},ttl={DNS_TTL_SECS},tls_port={HTTPS_PORT},\
         silent={SILENT_PEER},request={},response={}",
        hex(HTTP_REQUEST),
        hex(HTTP_RESPONSE)
    )
}

/// Sets (or, for `None`, removes) process environment variables for the kernel build, and puts
/// the old values back on drop.
pub(crate) struct BuildEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);

impl BuildEnv {
    pub(crate) fn set(vars: &[(&'static str, Option<String>)]) -> Self {
        let saved = vars
            .iter()
            .map(|(name, value)| {
                let old = std::env::var_os(name);
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
                (*name, old)
            })
            .collect();
        Self(saved)
    }
}

impl Drop for BuildEnv {
    fn drop(&mut self) {
        for (name, old) in &self.0 {
            match old {
                Some(value) => std::env::set_var(name, value),
                None => std::env::remove_var(name),
            }
        }
    }
}

/// The production network service is built without `network::fixture` (#355): the M7 lab
/// network's names, addresses and test peers are not in its dependency graph.
fn check_service_has_no_fixture() -> Result<(), XtaskError> {
    let output = Command::new("cargo")
        .current_dir(workspace_root())
        .args([
            "tree",
            "-p",
            "clean-slate-net-service",
            "--features",
            "userspace",
            "--target",
            "x86_64-unknown-none",
            "-e",
            "features",
            "--prefix",
            "none",
        ])
        .output()?;
    if !output.status.success() {
        return Err(XtaskError::Validation(format!(
            "{LANE}: cargo tree failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let tree = String::from_utf8_lossy(&output.stdout);
    if let Some(line) = fixture_feature_line(&tree) {
        return Err(XtaskError::Validation(format!(
            "{LANE}: the production network service enables the fixture vocabulary: {line}"
        )));
    }
    if !tree.contains("clean-slate-network feature \"tls\"") {
        return Err(XtaskError::Validation(format!(
            "{LANE}: cargo tree of clean-slate-net-service does not show clean-slate-network; \
             the fixture check would prove nothing"
        )));
    }
    println!("[NET ] net-service feature set has no clean-slate-network/fixture");
    Ok(())
}

pub(crate) fn fixture_feature_line(tree: &str) -> Option<&str> {
    tree.lines()
        .map(str::trim)
        .find(|line| line.starts_with("clean-slate-network feature \"fixture\""))
}

/// The kernel image trusts the lane CA, and the M7 test CA is not in it at all.
fn check_image_trust(anchor_der: &[u8]) -> Result<(), XtaskError> {
    let kernel = kernel_artifact(true);
    let image = fs::read(&kernel)?;
    let m7_ca = fs::read(workspace_root().join(M7_TEST_CA))?;
    if contains(&image, &m7_ca) {
        return Err(XtaskError::Validation(format!(
            "{LANE}: {} carries the M7 test CA",
            kernel.display()
        )));
    }
    if !contains(&image, anchor_der) {
        return Err(XtaskError::Validation(format!(
            "{LANE}: {} does not carry the lane CA",
            kernel.display()
        )));
    }
    println!("[NET ] kernel image holds the lane CA and not the M7 test CA");
    Ok(())
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// The lane's CA: its key is kept in `target/net-acceptance` so the kernel's trust anchor (and
/// so the kernel build) stays the same from run to run.
struct LaneCa {
    key: KeyPair,
    cert: rcgen::Certificate,
    anchor_der: Vec<u8>,
    anchors_dir: PathBuf,
}

impl LaneCa {
    fn params() -> Result<CertificateParams, XtaskError> {
        let mut params = CertificateParams::new(vec![]).map_err(cert_error)?;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Clean-Slate Network Acceptance Lane CA");
        params.not_before = datetime!(2020-01-01 0:00 UTC);
        params.not_after = datetime!(2120-01-01 0:00 UTC);
        Ok(params)
    }

    fn load_or_create(dir: &Path) -> Result<Self, XtaskError> {
        let anchors_dir = dir.join("trust-anchors");
        let key_path = dir.join("ca.key.pem");
        let anchor_path = anchors_dir.join("net-acceptance-ca.der");
        let existing = fs::read_to_string(&key_path)
            .ok()
            .and_then(|pem| KeyPair::from_pem(&pem).ok())
            .zip(fs::read(&anchor_path).ok());
        let (key, anchor_der) = match existing {
            Some(pair) => pair,
            None => {
                let key =
                    KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
                let cert = Self::params()?.self_signed(&key).map_err(cert_error)?;
                // Only the lane CA: the build trusts every `*.der` in the directory.
                let _ = fs::remove_dir_all(&anchors_dir);
                fs::create_dir_all(&anchors_dir)?;
                fs::write(&key_path, key.serialize_pem())?;
                fs::write(&anchor_path, cert.der().as_ref())?;
                println!("[NET ] generated the lane CA in {}", dir.display());
                (key, cert.der().to_vec())
            }
        };
        // Signing needs the CA's name and key, which match the stored anchor.
        let cert = Self::params()?.self_signed(&key).map_err(cert_error)?;
        Ok(Self {
            key,
            cert,
            anchor_der,
            anchors_dir,
        })
    }

    /// A TLS 1.3 server for [`SERVER_NAME`] with a certificate issued now.
    fn server_config(&self) -> Result<ServerConfig, XtaskError> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(cert_error)?;
        let mut params =
            CertificateParams::new(vec![SERVER_NAME.to_owned()]).map_err(cert_error)?;
        params.is_ca = IsCa::NoCa;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, SERVER_NAME);
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(10);
        params.not_after = now + time::Duration::days(1);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let leaf = params
            .signed_by(&key, &self.cert, &self.key)
            .map_err(cert_error)?;
        let chain = vec![CertificateDer::from(leaf.der().to_vec())];
        let key = PrivateKeyDer::Pkcs8(key.serialize_der().into());
        let provider = rustls::crypto::ring::default_provider();
        let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(cert_error)?
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .map_err(cert_error)?;
        // One application record and the close; no session tickets to skip.
        config.send_tls13_tickets = 0;
        Ok(config)
    }
}

fn cert_error(error: impl std::fmt::Display) -> XtaskError {
    XtaskError::Validation(format!("{LANE}: certificate: {error}"))
}

/// A loopback listener that serves each connection on its own thread and counts the ones that
/// were answered.
struct Server {
    port: u16,
    served: Arc<AtomicUsize>,
}

impl Server {
    fn start<F>(name: &'static str, serve: F) -> Result<Self, XtaskError>
    where
        F: Fn(&mut TcpStream) -> io::Result<()> + Send + Sync + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        let served = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&served);
        let serve = Arc::new(serve);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let serve = Arc::clone(&serve);
                let counter = Arc::clone(&counter);
                thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
                    match serve(&mut stream) {
                        Ok(()) => {
                            counter.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(error) => println!("[NET ] {LANE} {name} connection failed: {error}"),
                    }
                });
            }
        });
        Ok(Self { port, served })
    }

    fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

/// One DNS-over-TCP exchange: an A record for [`SERVER_NAME`], NXDOMAIN for anything else.
fn serve_dns(stream: &mut TcpStream) -> io::Result<()> {
    let mut prefix = [0u8; 2];
    stream.read_exact(&mut prefix)?;
    let mut query = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
    stream.read_exact(&mut query)?;
    let reply = dns_reply(&query).ok_or_else(|| io::Error::other("malformed DNS query"))?;
    let mut message = (reply.len() as u16).to_be_bytes().to_vec();
    message.extend_from_slice(&reply);
    stream.write_all(&message)?;
    let _ = stream.shutdown(Shutdown::Write);
    // Wait for the guest's close so the reply is not cut off by a reset.
    let _ = stream.read(&mut [0u8; 1]);
    println!("[NET ] {LANE} dns answered over tcp");
    Ok(())
}

/// The reply to a one-question query: the question echoed, and one A record for
/// [`SERVER_NAME`] (by compression pointer) or NXDOMAIN.
pub(crate) fn dns_reply(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*query.get(offset)?);
        offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        labels.push(std::str::from_utf8(query.get(offset..offset + len)?).ok()?);
        offset += len;
    }
    let question_end = offset + 4;
    let question = query.get(12..question_end)?;
    let qtype = u16::from_be_bytes([query[offset], query[offset + 1]]);
    let known = labels.join(".").eq_ignore_ascii_case(SERVER_NAME) && qtype == 1;
    let mut reply = Vec::with_capacity(question_end + 16);
    reply.extend_from_slice(&query[..2]);
    // QR, RD copied, RA; NXDOMAIN for an unknown name.
    let rd = query[2] & 0x01;
    reply.push(0x80 | rd);
    reply.push(if known { 0x80 } else { 0x83 });
    reply.extend_from_slice(&[0, 1, 0, u8::from(known), 0, 0, 0, 0]);
    reply.extend_from_slice(question);
    if known {
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        reply.extend_from_slice(&DNS_TTL_SECS.to_be_bytes());
        reply.extend_from_slice(&[0, 4]);
        reply.extend_from_slice(&GUEST_SERVER.octets());
    }
    Some(reply)
}

/// One HTTPS fetch: the request must be [`HTTP_REQUEST`]; the answer is [`HTTP_RESPONSE`] in a
/// single record, then the close.
fn serve_https(stream: &mut TcpStream, config: &Arc<ServerConfig>) -> io::Result<()> {
    let conn = ServerConnection::new(Arc::clone(config)).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(conn, stream.try_clone()?);
    let mut request = Vec::new();
    let mut buf = [0u8; 256];
    while !request.ends_with(b"\r\n\r\n") {
        let n = tls.read(&mut buf)?;
        if n == 0 || request.len() > 1024 {
            return Err(io::Error::other("request cut short"));
        }
        request.extend_from_slice(&buf[..n]);
    }
    if request != HTTP_REQUEST {
        return Err(io::Error::other(format!(
            "unexpected request {:?}",
            String::from_utf8_lossy(&request)
        )));
    }
    tls.write_all(HTTP_RESPONSE)?;
    tls.conn.send_close_notify();
    tls.flush()?;
    // Drain until the guest's own close_notify or FIN.
    let _ = tls.read(&mut buf);
    println!("[NET ] {LANE} https served {SERVER_NAME}");
    Ok(())
}

/// `xtask net-acceptance-relay <port>`: what QEMU runs for one forwarded guest connection. It
/// joins the connection (stdin, stdout) to `127.0.0.1:<port>` until either side closes.
pub(crate) fn run_relay(port: &str) -> Result<(), XtaskError> {
    let port: u16 = port
        .parse()
        .map_err(|_| XtaskError::InvalidOption(port.to_owned()))?;
    let upstream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))?;
    let mut to_server = upstream.try_clone()?;
    let mut from_server = upstream;
    let inbound = thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut to_server);
        let _ = to_server.shutdown(Shutdown::Write);
    });
    // Not `io::copy`: stdout is line-buffered, and a TLS flight has no newline to flush it.
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 16 * 1024];
    loop {
        match from_server.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if stdout
                    .write_all(&buf[..n])
                    .and_then(|()| stdout.flush())
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    // The server closed: the guest connection ends with this process, whether or not the guest
    // has finished sending.
    drop(inbound);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    #[test]
    fn dns_reply_answers_the_server_name_and_refuses_others() {
        let known = dns_reply(&query(SERVER_NAME, 1)).unwrap();
        assert_eq!(&known[..2], &[0x12, 0x34]);
        assert_eq!(known[3] & 0x0f, 0);
        assert_eq!(&known[6..8], &[0, 1]);
        assert_eq!(&known[known.len() - 4..], &GUEST_SERVER.octets());
        let other = dns_reply(&query("example.com", 1)).unwrap();
        assert_eq!(other[3] & 0x0f, 3);
        assert_eq!(&other[6..8], &[0, 0]);
        assert!(dns_reply(&[0; 5]).is_none());
    }

    #[test]
    fn the_probe_fits_the_launch_block() {
        let max = clean_slate_network::limits::MAX_REQUEST_HOSTNAME_LEN;
        assert!(SERVER_NAME.len() <= max);
        assert!(HTTP_REQUEST.len() <= 64 && HTTP_RESPONSE.len() <= 64);
        assert!(probe_spec().contains("request=474554"));
    }

    #[test]
    fn netdev_forwards_only_to_the_relay() {
        let netdev = netdev_arg(Path::new("/x/xtask"), 1000, 2000).unwrap();
        assert_eq!(
            netdev,
            "user,id=n0,restrict=on,\
             guestfwd=tcp:10.0.2.100:53-cmd:/x/xtask net-acceptance-relay 1000,\
             guestfwd=tcp:10.0.2.100:443-cmd:/x/xtask net-acceptance-relay 2000"
        );
        assert!(netdev_arg(Path::new("/a b/xtask"), 1, 2).is_err());
    }

    #[test]
    fn fixture_feature_is_spotted_in_a_feature_tree() {
        let clean = "clean-slate-net-service v0.1.0\nclean-slate-network feature \"tls\"\n";
        assert_eq!(fixture_feature_line(clean), None);
        let tainted = format!("{clean}clean-slate-network feature \"fixture\"\n");
        assert_eq!(
            fixture_feature_line(&tainted),
            Some("clean-slate-network feature \"fixture\"")
        );
    }
}
