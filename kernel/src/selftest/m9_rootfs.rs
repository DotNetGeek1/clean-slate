//! M9 #104: embedded rootfs image parse + layout acceptance.

use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_SUCCESS};
use crate::mm::frame_allocator::PageAllocator;
use crate::process::linux_rootfs;
use clean_slate_rootfs::EntryKind;

const PASS_MARKER: &str = "[M9.K] PASS";
const BUSYBOX_SIZE: usize = 206_712;

pub(crate) fn start_m9_rootfs_self_test(_allocator: PageAllocator) -> ! {
    linux_rootfs::ensure_rootfs_integrity_logged().expect("m9 rootfs: embedded image must parse");

    let img = linux_rootfs::image().expect("m9 rootfs: image");
    let busybox = img.lookup(b"/bin/busybox").expect("busybox entry");
    if busybox.data.len() != BUSYBOX_SIZE {
        panic!("m9 rootfs: busybox size mismatch");
    }
    let sh = img.lookup(b"/bin/sh").expect("/bin/sh");
    if sh.kind != EntryKind::Link || sh.data != b"/bin/busybox" {
        panic!("m9 rootfs: /bin/sh link target");
    }

    let mut count = 0usize;
    let mut has_bin = false;
    let mut has_etc = false;
    let mut has_tmp = false;
    for entry in img.children(b"/") {
        count += 1;
        if entry.path == b"/bin" {
            has_bin = true;
        } else if entry.path == b"/etc" {
            has_etc = true;
        } else if entry.path == b"/tmp" {
            has_tmp = true;
        }
    }
    if count != 3 || !has_bin || !has_etc || !has_tmp {
        panic!("m9 rootfs: root children must be bin/etc/tmp");
    }

    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}
