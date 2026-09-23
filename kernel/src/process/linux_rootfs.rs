//! M9 #104: embedded deterministic BusyBox rootfs image (read-only CSROOTFS blob).

use clean_slate_rootfs::{EntryKind, Image, RootfsError};
use core::sync::atomic::{AtomicBool, Ordering};

/// Pinned BusyBox SHA-256 prefix for boot-time provenance logging (full hash in manifest).
const BUSYBOX_SHA256_PREFIX: &str = "7ba56ace";

const M9_ROOTFS_IMAGE_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/m9-rootfs.img"));

static ROOTFS_LOGGED: AtomicBool = AtomicBool::new(false);

/// Borrowed view over the build-time packed rootfs image.
pub(crate) fn image() -> Result<Image<'static>, RootfsError> {
    Image::parse(M9_ROOTFS_IMAGE_BYTES)
}

/// Parse, validate, and log `[RFS ]` integrity once per boot.
pub(crate) fn ensure_rootfs_integrity_logged() -> Result<(), RootfsError> {
    if ROOTFS_LOGGED.swap(true, Ordering::Relaxed) {
        return Ok(());
    }
    let img = image()?;
    let busybox = img.lookup(b"/bin/busybox").ok_or(RootfsError::BadPath)?;
    if busybox.kind != EntryKind::File {
        return Err(RootfsError::BadEntryKind);
    }
    crate::diagnostics::log::kernel_log_fmt(format_args!(
        "[RFS ] rootfs entries={} busybox_bytes={} sha={}\n",
        img.len(),
        busybox.data.len(),
        BUSYBOX_SHA256_PREFIX
    ));
    Ok(())
}
