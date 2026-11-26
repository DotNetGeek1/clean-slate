//! #219: every function that reaches a capability table records its decision, or says why not.
//!
//! The kernel holds authority in three tables: the capability space (`capability_space_mut`,
//! `with_capability_space`), the lifecycle-control and block-device tables
//! (`lifecycle_capabilities_mut`), and the port engine's view of the capability space
//! (`with_ports`). This test finds every non-test function outside `selftest/` that calls one
//! of those, and requires it to appear in [`COVERAGE`]:
//!
//! - [`Coverage::Records`]: its body calls an audit recorder;
//! - [`Coverage::RecordedBy`]: a named function in the same file calls it and records;
//! - [`Coverage::Via`]: it calls a named function that records;
//! - [`Coverage::NoDecision`]: it looks up, counts or resets, so its body calls no table
//!   primitive that grants, derives, revokes or authorizes.
//!
//! A new function that touches a table, a recorder removed from a listed function, or a
//! `NoDecision` function that starts deciding fails this test. Per-path record contents are
//! checked by the behavioural tests in `audit.rs`. Self-test fixtures (`selftest/`) are out of
//! scope: they run only in their own lane images.

use std::collections::BTreeSet;
use std::path::Path;
use std::string::{String, ToString};
use std::vec::Vec;

#[derive(Clone, Copy, Debug)]
enum Coverage {
    Records,
    RecordedBy(&'static str),
    Via(&'static str, &'static str),
    NoDecision(&'static str),
}

use Coverage::{NoDecision, RecordedBy, Records, Via};

const THIS_FILE: &str = "capability/audit_coverage.rs";
const LOOKUP: &str = "finds the caller's handle; the use is authorized and recorded";
const COUNT: &str = "counts live records";

/// Calls that reach an authority table.
const GATEWAYS: [&str; 4] = [
    "capability_space_mut(",
    "with_capability_space(",
    "lifecycle_capabilities_mut(",
    "with_ports(",
];

/// Calls that put a record in the audit ring, and the local helpers that wrap them.
const RECORDERS: [&str; 9] = [
    "audit::record(",
    "record_decision(",
    "record_kernel_revoke(",
    "record_network_audit(",
    "record_allowed(",
    "record_denied(",
    "record_client_grant(",
    "record_lifecycle_decision(",
    "record_port_decision(",
];

/// `(file, helper)`: every recorder in [`RECORDERS`] that is not `audit.rs`'s own.
const RECORDER_HELPERS: [(&str, &str); 6] = [
    ("capability/network.rs", "record_network_audit"),
    ("capability/network.rs", "record_client_grant"),
    ("capability/process_control.rs", "record_allowed"),
    ("capability/process_control.rs", "record_denied"),
    ("service/capability.rs", "record_lifecycle_decision"),
    ("service/port.rs", "record_port_decision"),
];

/// Table primitives that grant, derive, revoke or authorize. A `ReadOnly` function calls none.
const DECIDING_PRIMITIVES: [&str; 11] = [
    ".grant(",
    "grant_",
    ".install(",
    ".revoke(",
    ".revoke_slot(",
    "revoke_",
    "delegate(",
    "drop_own(",
    ".authorize(",
    ".authorize_class(",
    "authorize_",
];

const COVERAGE: &[(&str, &str, Coverage)] = &[
    ("capability/delegation.rs", "handle_delegate", Records),
    (
        "capability/delegation.rs",
        "delegate_checked",
        RecordedBy("handle_delegate"),
    ),
    (
        "capability/delegation.rs",
        "rollback_installed_child",
        RecordedBy("delegate_checked"),
    ),
    (
        "capability/delegation.rs",
        "handle_list",
        NoDecision("lists the caller's own records"),
    ),
    (
        "capability/display.rs",
        "find_display_handle",
        NoDecision(LOOKUP),
    ),
    ("capability/display.rs", "authorize_display_query", Records),
    (
        "capability/display.rs",
        "authorize_display_present",
        Records,
    ),
    (
        "capability/mod.rs",
        "live_capability_count",
        NoDecision(COUNT),
    ),
    ("capability/mod.rs", "authorize_current", Records),
    ("capability/mod.rs", "authorize_current_class", Records),
    ("capability/mod.rs", "grant_root", Records),
    ("capability/mod.rs", "revoke_for_holder", Records),
    (
        "capability/mod.rs",
        "set_slot_allowance",
        NoDecision(
            "sets a launched instance's quota from its manifest row; the launch record \
             (`audit_service_authority`) carries the allowance",
        ),
    ),
    ("capability/mod.rs", "holder_has_resource_rights", Records),
    (
        "capability/mod.rs",
        "copy_capabilities_for_fork",
        RecordedBy("inherit_capabilities_for_fork"),
    ),
    (
        "capability/mod.rs",
        "rollback_fork_inherited",
        RecordedBy("copy_capabilities_for_fork"),
    ),
    ("capability/mod.rs", "revoke_for_resource", Records),
    ("capability/mod.rs", "revoke_for_process_resource", Records),
    ("capability/network.rs", "authorize_network_op", Records),
    ("capability/network.rs", "on_revoked", Records),
    (
        "capability/network.rs",
        "revoke_network_capabilities_for_holder",
        Via("capability/network.rs", "on_revoked"),
    ),
    (
        "capability/network.rs",
        "grant_network_client_entitlement",
        Via("capability/network.rs", "grant_entitlement_in"),
    ),
    (
        "capability/network.rs",
        "on_network_instance_registered",
        Via("capability/network.rs", "reissue_client_capabilities_in"),
    ),
    (
        "capability/network.rs",
        "on_network_instance_gone",
        Via(
            "capability/network.rs",
            "revoke_entitled_client_capabilities_in",
        ),
    ),
    ("capability/network.rs", "on_holder_exit", NoDecision(COUNT)),
    (
        "capability/object.rs",
        "holder_holds_object_service_role",
        NoDecision("teardown asks which role the exiting holder had"),
    ),
    (
        "capability/object.rs",
        "rollback_installed_capability",
        Records,
    ),
    (
        "capability/process_control.rs",
        "target_for_denied_log",
        NoDecision("names the target in the denial record"),
    ),
    ("capability/process_control.rs", "handle_syscall", Records),
    ("capability/revocation.rs", "handle_revoke", Records),
    (
        "capability/revocation.rs",
        "revoke_branch",
        RecordedBy("handle_revoke"),
    ),
    ("capability/revocation.rs", "drop_for", Records),
    (
        "capability/revocation.rs",
        "drop_checked",
        RecordedBy("drop_for"),
    ),
    (
        "capability/revocation.rs",
        "handle_probe",
        Via("capability/mod.rs", "authorize_current_class"),
    ),
    (
        "mm/shared_buffer/mod.rs",
        "capability_is_live",
        NoDecision("reconciles buffers against already-recorded revocations"),
    ),
    (
        "mm/shared_buffer/transfer.rs",
        "attest_for_transfer",
        Records,
    ),
    (
        "process/domain.rs",
        "lifecycle_capability_count",
        NoDecision(COUNT),
    ),
    (
        "process/domain.rs",
        "desktop_resource_snapshot",
        NoDecision(COUNT),
    ),
    (
        "process/linux_socket/broker.rs",
        "network_client_handle",
        NoDecision(LOOKUP),
    ),
    (
        "service/capability.rs",
        "on_holder_exit",
        Via("service/capability.rs", "revoke_for_pid"),
    ),
    (
        "service/control.rs",
        "clear",
        NoDecision("boot-time reset, before any grant"),
    ),
    (
        "service/control.rs",
        "grant_lifecycle_control_capability",
        Via(
            "service/capability.rs",
            "grant_lifecycle_control_capability",
        ),
    ),
    (
        "service/control.rs",
        "grant_block_device_capability_for_self_test",
        Via("service/capability.rs", "grant_block_device_capability"),
    ),
    (
        "service/control.rs",
        "acquire_block_device_capability",
        NoDecision(LOOKUP),
    ),
    (
        "service/control.rs",
        "authorize_block_device_request",
        Via("service/capability.rs", "authorize_block_device_access"),
    ),
    (
        "service/control.rs",
        "authorize_lifecycle_control",
        Via("service/capability.rs", "authorize_lifecycle_control"),
    ),
    (
        "service/control.rs",
        "grant_block_device",
        Via("service/capability.rs", "grant_block_device_capability"),
    ),
    (
        "service/console_device.rs",
        "find_handle",
        NoDecision(LOOKUP),
    ),
    (
        "service/input_syscall.rs",
        "find_handle",
        NoDecision(LOOKUP),
    ),
    (
        "service/input_syscall.rs",
        "query_right",
        NoDecision("picks the right the recorded authorization asks for"),
    ),
    (
        "service/net_syscall.rs",
        "find_network_handle",
        NoDecision(LOOKUP),
    ),
    ("service/port.rs", "with_ports", Records),
    (
        "service/port.rs",
        "serve_event",
        NoDecision("names the resource in a port record"),
    ),
    (
        "service/port.rs",
        "attest",
        NoDecision("m10-port-self-test attestation fixture; the send records the outcome"),
    ),
    ("service/port.rs", "kernel_client_connect", Records),
    ("service/port.rs", "kernel_client_send", Records),
    ("service/port.rs", "kernel_client_try_recv_event", Records),
    ("service/port.rs", "kernel_client_close", Records),
    (
        "service/port.rs",
        "connection_port_key",
        NoDecision("maps a connection to its port"),
    ),
    ("service/port.rs", "find_handle", Records),
    ("service/port.rs", "serve_port_key", Records),
    ("service/port.rs", "server_recv", Records),
    ("service/port.rs", "server_post", Records),
    ("service/port.rs", "server_disconnect", Records),
    ("service/port.rs", "server_bind_wake", Records),
    (
        "service/port.rs",
        "on_holder_exit",
        Via("service/port.rs", "with_ports"),
    ),
    ("service/port.rs", "counts_for", NoDecision(COUNT)),
    ("service/port.rs", "global_counts", NoDecision(COUNT)),
    ("service/port.rs", "limit_rejections", NoDecision(COUNT)),
    ("service/system_init.rs", "of", NoDecision(COUNT)),
    (
        "service/system_init.rs",
        "init_lifecycle_scope_is",
        NoDecision("reads the scope launch_init checks against the manifest"),
    ),
    (
        // Split so `system_init`'s test-hook gate check does not match this line.
        concat!("service/system", "_test_hooks.rs"),
        "probe_stale_generation",
        Records,
    ),
];

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// The function a `fn` item on `line` declares, if any.
fn declared_function(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut search_from = 0;
    while let Some(offset) = line[search_from..].find("fn ") {
        let start = search_from + offset;
        search_from = start + 3;
        if start > 0 && is_identifier_byte(bytes[start - 1]) {
            continue;
        }
        let name = &line[start + 3..];
        let len = name
            .bytes()
            .take_while(|byte| is_identifier_byte(*byte))
            .count();
        if len > 0 && matches!(name.as_bytes().get(len), Some(b'(' | b'<')) {
            return Some(&name[..len]);
        }
    }
    None
}

fn calls(code: &str, call: &str) -> bool {
    code.match_indices(call).any(|(offset, _)| {
        let starts_identifier = call.starts_with('.')
            || offset == 0
            || !is_identifier_byte(code.as_bytes()[offset - 1]);
        starts_identifier && !code[..offset].trim_end().ends_with("fn")
    })
}

/// One source file with `#[cfg(test)]` items blanked and comments stripped.
struct SourceFile {
    relative: String,
    lines: Vec<String>,
}

impl SourceFile {
    fn load(root: &Path, path: &Path) -> Self {
        let relative = path
            .strip_prefix(root)
            .expect("source file under kernel/src")
            .to_string_lossy()
            .replace('\\', "/");
        let source = std::fs::read_to_string(path).expect("read kernel source file");
        let mut lines = Vec::new();
        let mut after_cfg_test = false;
        // Brace depth inside a `#[cfg(test)]` item, and whether its body has opened yet.
        let mut skipping: Option<(i64, bool)> = None;
        for line in source.lines() {
            let code = line.split("//").next().unwrap_or_default().to_string();
            let trimmed = code.trim();
            if let Some((depth, opened)) = skipping.as_mut() {
                *depth += brace_delta(&code);
                *opened |= code.contains('{');
                let item_ended = if *opened {
                    *depth <= 0
                } else {
                    trimmed.ends_with(';')
                };
                if item_ended {
                    skipping = None;
                }
                lines.push(String::new());
                continue;
            }
            if trimmed == "#[cfg(test)]" {
                after_cfg_test = true;
                lines.push(String::new());
                continue;
            }
            if after_cfg_test && !trimmed.is_empty() && !trimmed.starts_with("#[") {
                after_cfg_test = false;
                let opened = code.contains('{');
                let depth = brace_delta(&code);
                let item_ended = if opened {
                    depth <= 0
                } else {
                    trimmed.ends_with(';')
                };
                if !item_ended {
                    skipping = Some((depth, opened));
                }
                lines.push(String::new());
                continue;
            }
            lines.push(code);
        }
        Self { relative, lines }
    }

    /// `(function, line index)` of every function declaration.
    fn functions(&self) -> Vec<(String, usize)> {
        self.lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                declared_function(line).map(|name| (name.to_string(), index))
            })
            .collect()
    }

    /// Lines from `function`'s declaration to the next declaration.
    fn body(&self, function: &str) -> Option<String> {
        let functions = self.functions();
        let position = functions.iter().position(|(name, _)| name == function)?;
        let start = functions[position].1;
        let end = functions
            .get(position + 1)
            .map_or(self.lines.len(), |(_, index)| *index);
        Some(self.lines[start..end].join("\n"))
    }
}

fn brace_delta(code: &str) -> i64 {
    let opens = code.matches('{').count() as i64;
    let closes = code.matches('}').count() as i64;
    opens - closes
}

fn kernel_sources(root: &Path) -> Vec<SourceFile> {
    let mut files = Vec::new();
    let mut directories = std::vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(&directory).expect("read kernel source directory") {
            let path = entry.expect("kernel source entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "selftest") {
                    directories.push(path);
                }
            } else if path.extension().is_some_and(|extension| extension == "rs")
                && path.file_name().is_some_and(|name| name != "tests.rs")
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
        .iter()
        .map(|path| SourceFile::load(root, path))
        .filter(|file| file.relative != THIS_FILE)
        .collect()
}

/// Every `(file, enclosing function)` that calls a gateway, with one `file:line` for each.
fn gateway_callers(sources: &[SourceFile]) -> Vec<((String, String), String)> {
    let mut found = Vec::new();
    for file in sources {
        let mut function = String::from("<module>");
        for (index, code) in file.lines.iter().enumerate() {
            if let Some(name) = declared_function(code) {
                function = name.to_string();
            }
            if GATEWAYS.iter().any(|gateway| calls(code, gateway)) {
                let site = (file.relative.clone(), function.clone());
                if !found.iter().any(|(existing, _)| *existing == site) {
                    found.push((site, std::format!("{}:{}", file.relative, index + 1)));
                }
            }
        }
    }
    found
}

fn source<'a>(sources: &'a [SourceFile], relative: &str) -> &'a SourceFile {
    sources
        .iter()
        .find(|file| file.relative == relative)
        .unwrap_or_else(|| panic!("{relative} not found under kernel/src"))
}

fn records(body: &str) -> bool {
    RECORDERS.iter().any(|recorder| calls(body, recorder))
}

fn coverage_of(file: &str, function: &str) -> Option<Coverage> {
    COVERAGE
        .iter()
        .find(|(listed_file, listed, _)| *listed_file == file && *listed == function)
        .map(|(_, _, coverage)| *coverage)
}

/// `caller` records for the functions it calls: directly, or as `RecordedBy` its own caller.
fn caller_records(sources: &[SourceFile], file: &str, caller: &str, hops: usize) -> bool {
    let Some(body) = source(sources, file).body(caller) else {
        return false;
    };
    if records(&body) {
        return true;
    }
    match coverage_of(file, caller) {
        Some(RecordedBy(next)) if hops > 0 => {
            let next_body = source(sources, file).body(next).unwrap_or_default();
            calls(&next_body, &std::format!("{caller}("))
                && caller_records(sources, file, next, hops - 1)
        }
        _ => false,
    }
}

/// `function` records, directly or through a function it calls in the same file.
fn function_records(sources: &[SourceFile], file: &str, function: &str, hops: usize) -> bool {
    let source_file = source(sources, file);
    let Some(body) = source_file.body(function) else {
        return false;
    };
    records(&body)
        || (hops > 0
            && source_file.functions().iter().any(|(callee, _)| {
                callee != function
                    && calls(&body, &std::format!("{callee}("))
                    && function_records(sources, file, callee, hops - 1)
            }))
}

#[test]
fn every_function_that_reaches_an_authority_table_records_or_says_why_not() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let sources = kernel_sources(&root);
    let found = gateway_callers(&sources);
    let listed: BTreeSet<(String, String)> = COVERAGE
        .iter()
        .map(|(file, function, _)| (file.to_string(), function.to_string()))
        .collect();
    let found_sites: BTreeSet<(String, String)> =
        found.iter().map(|(site, _)| site.clone()).collect();

    let mut problems = Vec::new();
    for ((file, function), location) in &found {
        if !listed.contains(&(file.clone(), function.clone())) {
            problems.push(std::format!(
                "{location}: `{function}` reaches an authority table but is not in COVERAGE"
            ));
        }
    }
    for (file, function) in listed.difference(&found_sites) {
        problems.push(std::format!(
            "{file}: COVERAGE lists `{function}`, which no longer reaches a table"
        ));
    }
    for &(file, function, coverage) in COVERAGE {
        let Some(body) = source(&sources, file).body(function) else {
            continue;
        };
        match coverage {
            Records if !records(&body) => problems.push(std::format!(
                "{file}: `{function}` decides but records nothing"
            )),
            Records => {}
            RecordedBy(caller) => {
                let caller_body = source(&sources, file).body(caller).unwrap_or_default();
                if !calls(&caller_body, &std::format!("{function}(")) {
                    problems.push(std::format!(
                        "{file}: `{function}` is RecordedBy `{caller}`, which does not call it"
                    ));
                } else if !caller_records(&sources, file, caller, 3) {
                    problems.push(std::format!(
                        "{file}: `{caller}` (recording for `{function}`) records nothing"
                    ));
                }
            }
            Via(target_file, target) => {
                if !calls(&body, &std::format!("{target}(")) {
                    problems.push(std::format!(
                        "{file}: `{function}` is Via `{target}`, which it does not call"
                    ));
                } else if !function_records(&sources, target_file, target, 2) {
                    problems.push(std::format!(
                        "{target_file}: `{target}` (recording for {file} `{function}`) records \
                         nothing"
                    ));
                }
            }
            NoDecision(reason) => {
                for primitive in DECIDING_PRIMITIVES {
                    if calls(&body, primitive) {
                        problems.push(std::format!(
                            "{file}: `{function}` is NoDecision ({reason}) but calls `{primitive}`"
                        ));
                    }
                }
            }
        }
    }
    for (file, helper) in RECORDER_HELPERS {
        let body = source(&sources, file).body(helper).unwrap_or_default();
        if !calls(&body, "audit::record(") && !calls(&body, "record_decision(") {
            problems.push(std::format!(
                "{file}: recorder `{helper}` puts nothing in the audit ring"
            ));
        }
    }
    assert!(
        problems.is_empty(),
        "audit coverage (#219):\n  {}\nRecord the decision with `capability::audit::record` or \
         classify the function in COVERAGE.",
        problems.join("\n  ")
    );
}
