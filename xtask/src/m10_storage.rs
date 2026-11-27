//! #312 native storage lane (`cargo xtask test-m10-storage`).
//!
//! The native storage host tests (offset ops, commits, rights, epochs, the live-byte budget
//! and `NO_SPACE`, shared-buffer payloads, the directory capability and the probe's stages),
//! then three boots of the `m10-storage-self-test` kernel on one blank data disk. A native
//! app holding only a directory capability creates `big.bin` and writes 1 MiB into it through
//! a shared buffer in offset writes, then commits; after a reboot it reads the file back by
//! name, checks every byte and truncates it to 4 KiB; after another it reads the 4 KiB back
//! and unlinks it.

use std::time::Duration;

use crate::marker_spec::MarkerSet;
use crate::{
    build_m6_fixture_userspace, build_native_userspace_bin, m5_storage_vm_config,
    reset_m5_data_disk_image, run_cargo_package_tests, run_vm_inner_with_config, XtaskError,
};

const FEATURE: &str = "m10-storage-self-test";
const TIMEOUT: Duration = Duration::from_secs(90);

pub(crate) const WRITE_MARKERS: [&str; 9] = [
    "[STOR] object-service started pid=",
    "[M10.storage] probe spawned pid=",
    "[M10.storage] step create",
    "[M10.storage] step allocate buffer",
    "[M10.storage] step write through buffer",
    "[M10.storage] step commit",
    "[M10.storage] step reopen",
    "[M10.storage] stage wrote",
    "[M10.storage] boot PASS",
];

pub(crate) const TRUNCATE_MARKERS: [&str; 10] = [
    "[STOR] object-service started pid=",
    "[M10.storage] probe spawned pid=",
    "[M10.storage] step open",
    "[M10.storage] step read through buffer",
    "[M10.storage] step check bytes",
    "[M10.storage] step truncate",
    "[M10.storage] step record length",
    "[M10.storage] step reopen",
    "[M10.storage] stage truncated",
    "[M10.storage] boot PASS",
];

pub(crate) const REMOVE_MARKERS: [&str; 8] = [
    "[STOR] object-service started pid=",
    "[M10.storage] probe spawned pid=",
    "[M10.storage] step read truncated",
    "[M10.storage] step check bytes",
    "[M10.storage] step unlink",
    "[M10.storage] step reopen",
    "[M10.storage] stage removed",
    "[M10.storage] boot PASS",
];

pub(crate) fn run() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-native-abi", &["object"])?;
    run_cargo_package_tests("clean-slate-native-abi", &["directory"])?;
    run_cargo_package_tests("clean-slate-store", &["service"])?;
    run_cargo_package_tests("clean-slate-runtime", &["--features", "fake", "storage"])?;
    run_cargo_package_tests("clean-slate-storage-probe", &[])?;
    run_cargo_package_tests("clean-slate-kernel", &["--lib", "--", "capability::object"])?;

    build_m6_fixture_userspace(true)?;
    build_native_userspace_bin(
        "clean-slate-storage-probe",
        "clean-slate-storage-probe-userspace",
    )?;
    reset_m5_data_disk_image()?;
    let boots: [(&str, &'static [&'static str]); 3] = [
        (
            "blank disk: create big.bin, write 1 MiB, commit",
            &WRITE_MARKERS,
        ),
        (
            "same disk: read big.bin back by name, truncate to 4 KiB",
            &TRUNCATE_MARKERS,
        ),
        ("same disk: read the 4 KiB back, unlink", &REMOVE_MARKERS),
    ];
    for (index, (what, markers)) in boots.into_iter().enumerate() {
        println!("[M10.storage] boot {}/3: {what}", index + 1);
        run_vm_inner_with_config(
            false,
            false,
            &[FEATURE],
            Some((MarkerSet::Ordered(markers), TIMEOUT)),
            m5_storage_vm_config(),
        )?;
    }
    println!("[M10.storage] lane PASS");
    Ok(())
}
