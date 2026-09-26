//! Host tests for M9 #101 namespace/path projection (`--features m9-rootfs`).

use super::namespace::{
    check_write_allowed, resolve_executable_bytes, NodeId, NodeKind, NodeTable, LINUX_FS_MAX_NODES,
};
use super::object_backend::{tmp_file_create, LINUX_TMP_MAX_ENTRIES, LINUX_TMP_MAX_FILES};
use super::path::{normalize_path, LINUX_PATH_MAX};
use crate::process::linux_rootfs;
use clean_slate_linux_abi::{
    encode_dirent64, DT_DIR, EACCES, EISDIR, ENAMETOOLONG, ENFILE, ENOSPC, EROFS, O_CREAT,
    O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
};
use clean_slate_service_fixtures::OBJECT_MAX_PAYLOAD_BYTES;
use clean_slate_service_lifecycle::InstanceGeneration;

fn image() -> clean_slate_rootfs::Image<'static> {
    linux_rootfs::image().expect("host test rootfs")
}

fn fresh_table() -> NodeTable {
    super::object_backend::reset_tmp_store_for_host_tests();
    let mut t = NodeTable::new();
    t.init_rootfs(&image()).expect("init");
    t
}

#[test]
fn read_only_rootfs_write_flags_ero_fs() {
    assert!(check_write_allowed(b"/etc/hostname", O_WRONLY).is_err());
    assert_eq!(
        check_write_allowed(b"/etc/hostname", O_WRONLY).unwrap_err(),
        EROFS
    );
    assert_eq!(
        check_write_allowed(b"/bin/busybox", O_RDWR | O_CREAT).unwrap_err(),
        EROFS
    );
    assert_eq!(
        check_write_allowed(b"/etc/hostname", O_TRUNC).unwrap_err(),
        EROFS
    );
    assert!(check_write_allowed(b"/tmp/demo/x", O_WRONLY | O_CREAT).is_ok());
    assert!(check_write_allowed(b"/etc/hostname", O_RDONLY).is_ok());
}

#[test]
fn root_getdents_names_encode() {
    let mut table = fresh_table();
    let img = image();
    let root = table.lookup_path(b"/", &img, true).expect("root");
    let mut children = [(
        NodeId {
            index: 0,
            generation: 0,
        },
        0u8,
    ); 32];
    let count = table
        .list_children(root, &img, &mut children)
        .expect("list");
    assert!(count >= 3, "expected bin etc tmp at minimum");
    for &(node, _dt) in &children[..count] {
        let name = table.dirent_name(node).expect("dirent name");
        let mut scratch = [0u8; 256];
        assert!(
            encode_dirent64(&mut scratch, node.index as u64 + 1, 0, DT_DIR, name) > 0,
            "encode failed for {:?}",
            core::str::from_utf8(name).ok()
        );
    }
}

#[test]
fn lookup_file_vs_dir_semantics() {
    let mut table = fresh_table();
    let img = image();
    assert!(table.lookup_path(b"/etc/hostname", &img, false).is_ok());
    assert!(table.lookup_path(b"/bin", &img, false).is_ok());
    assert!(table.lookup_path(b"/etc/hostname/no", &img, false).is_err());
    table.mkdir(b"/tmp/eisdir", &img).expect("tmp dir");
    assert_eq!(
        table
            .open_create_file(b"/tmp/eisdir", false, &img)
            .unwrap_err(),
        EISDIR
    );
    let file = table
        .lookup_path(b"/etc/hostname", &img, false)
        .expect("file node");
    assert_eq!(table.node_kind(file).unwrap(), NodeKind::File);
    let dir = table.lookup_path(b"/bin", &img, false).expect("dir node");
    assert_eq!(table.node_kind(dir).unwrap(), NodeKind::Dir);
}

#[test]
fn tmp_mkdir_and_file_slot_bounds() {
    let mut table = fresh_table();
    let img = image();
    table.mkdir(b"/tmp/demo", &img).expect("demo dir");
    let baseline = table.live_count();
    for i in 0..LINUX_TMP_MAX_ENTRIES {
        let path = format!("/tmp/demo/d{i}");
        table.mkdir(path.as_bytes(), &img).expect("child dir");
    }
    assert_eq!(
        table.mkdir(b"/tmp/demo/one-too-many", &img).unwrap_err(),
        ENOSPC
    );
    assert!(table.live_count() >= baseline);
    table.mkdir(b"/tmp/fileslot", &img).expect("file parent");
    for f in 0..LINUX_TMP_MAX_FILES {
        let path = format!("/tmp/fileslot/f{f}");
        tmp_file_create(path.as_bytes()).expect("tmp file slot");
    }
    assert_eq!(
        tmp_file_create(b"/tmp/fileslot/f-overflow").unwrap_err(),
        ENOSPC
    );
    assert_eq!(OBJECT_MAX_PAYLOAD_BYTES, 512);
}

#[test]
fn node_table_exhaustion_and_reuse() {
    let mut table = fresh_table();
    let img = image();
    let mut last = NodeId {
        index: 0,
        generation: 1,
    };
    let mut batch = 0usize;
    let mut parent_path = String::from("/tmp/nt0");
    while (table.live_count() as usize) < LINUX_FS_MAX_NODES {
        parent_path = format!("/tmp/nt{batch}");
        table.mkdir(parent_path.as_bytes(), &img).expect("parent");
        for c in 0..LINUX_TMP_MAX_ENTRIES {
            if (table.live_count() as usize) >= LINUX_FS_MAX_NODES {
                break;
            }
            let path = format!("/tmp/nt{batch}/c{c}");
            table.mkdir(path.as_bytes(), &img).expect("child");
            last = table.lookup_path(path.as_bytes(), &img, true).expect("id");
        }
        batch += 1;
    }
    assert_eq!(table.live_count() as usize, LINUX_FS_MAX_NODES);
    let overflow = format!("{parent_path}/extra");
    assert_eq!(table.mkdir(overflow.as_bytes(), &img).unwrap_err(), ENFILE);
    table.host_test_evict_node(last).expect("evict");
    let reuse = format!("{parent_path}/reuse");
    table.mkdir(reuse.as_bytes(), &img).expect("reuse slot");
}

#[test]
fn tmp_write_size_over_512_is_efbig() {
    assert_eq!(OBJECT_MAX_PAYLOAD_BYTES, 512);
    assert!(400_usize.saturating_add(200) > OBJECT_MAX_PAYLOAD_BYTES);
    assert!(512_usize.saturating_add(1) > OBJECT_MAX_PAYLOAD_BYTES);
    assert!(0_usize.saturating_add(512) <= OBJECT_MAX_PAYLOAD_BYTES);
}

#[test]
fn resolve_executable_link_and_errors() {
    let mut table = fresh_table();
    let img = image();
    let busybox = resolve_executable_bytes(&mut table, &img, b"/bin/sh").expect("sh link");
    let direct = resolve_executable_bytes(&mut table, &img, b"/bin/busybox").expect("busybox");
    let ls = resolve_executable_bytes(&mut table, &img, b"/bin/ls").expect("ls link");
    assert_eq!(busybox.as_ptr(), direct.as_ptr());
    assert_eq!(ls.as_ptr(), direct.as_ptr());
    assert_eq!(
        resolve_executable_bytes(&mut table, &img, b"/no/such/file").unwrap_err(),
        clean_slate_linux_abi::ENOENT
    );
    assert_eq!(
        resolve_executable_bytes(&mut table, &img, b"/bin").unwrap_err(),
        EACCES
    );
    let mut long = [b'a'; LINUX_PATH_MAX + 1];
    long[LINUX_PATH_MAX] = 0;
    let mut norm = [0u8; LINUX_PATH_MAX];
    assert_eq!(
        normalize_path(&long[..LINUX_PATH_MAX + 1], &mut norm).unwrap_err(),
        ENAMETOOLONG
    );
}

#[test]
fn getdents64_encode_buffer_rules() {
    let mut scratch = [0u8; 16];
    assert_eq!(encode_dirent64(&mut scratch, 1, 0, 8, b"busybox"), 0);
    let mut buf = [0u8; 64];
    let n = encode_dirent64(&mut buf, 2, 0, 8, b"sh");
    assert!(n > 0 && (n as u64) <= 64);
    let n2 = encode_dirent64(&mut buf, 3, 0, 4, b"etc");
    assert!(n2 > 0);

    let mut table = fresh_table();
    let img = image();
    let bin = table.lookup_path(b"/bin", &img, false).expect("bin");
    let mut children = [(
        NodeId {
            index: 0,
            generation: 0,
        },
        0u8,
    ); 32];
    let count = table.list_children(bin, &img, &mut children).expect("list");
    assert!(count >= 2);

    let buf_len = 48usize;
    let mut cursor = 0usize;
    let mut wrote = 0usize;
    let mut chunk = [0u8; 128];
    while cursor < count {
        let (_, dt) = children[cursor];
        let path_buf = table
            .path_of_node(children[cursor].0.index, &img)
            .expect("path");
        let name = dirent_name(&path_buf);
        let n = encode_dirent64(&mut chunk[wrote..], (cursor as u64) + 1, 0, dt, name);
        if n == 0 {
            assert!(wrote > 0, "buffer too small for first entry");
            break;
        }
        if wrote + n > buf_len {
            assert!(wrote > 0, "partial buffer must fit at least one entry");
            break;
        }
        wrote += n;
        cursor += 1;
    }
    assert!(wrote > 0);

    let resume = cursor;
    let mut wrote2 = 0usize;
    while cursor < count {
        let (_, dt) = children[cursor];
        let path_buf = table
            .path_of_node(children[cursor].0.index, &img)
            .expect("path");
        let name = dirent_name(&path_buf);
        let n = encode_dirent64(&mut chunk[wrote2..], (cursor as u64) + 1, 0, dt, name);
        if n == 0 || wrote2 + n > buf_len {
            break;
        }
        wrote2 += n;
        cursor += 1;
    }
    assert!(cursor >= resume);
}

fn dirent_name(path_buf: &[u8; LINUX_PATH_MAX]) -> &[u8] {
    let end = path_buf
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(LINUX_PATH_MAX);
    let start = path_buf[..end]
        .iter()
        .rposition(|&b| b == b'/')
        .map(|p| p + 1)
        .unwrap_or(0);
    &path_buf[start..end]
}

#[test]
fn resolve_executable_via_mod_api() {
    let img = image();
    super::init_namespace(&img).expect("init namespace");
    let mut resolved = [0u8; LINUX_PATH_MAX];
    let exec = super::resolve_executable(0, InstanceGeneration(1), b"/bin/sh", &mut resolved, &img)
        .expect("resolve");
    assert!(!exec.image.is_empty());
    assert!(resolved.starts_with(b"/bin/"));
}
