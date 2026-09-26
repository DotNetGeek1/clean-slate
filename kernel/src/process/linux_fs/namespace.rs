//! Bounded Linux namespace node table (#101).

use super::object_backend::{
    tmp_file_by_object_id, tmp_file_create, tmp_file_lookup_by_path, LINUX_TMP_MAX_ENTRIES,
};
use super::path::{normalize_path, LINUX_PATH_MAX};
use clean_slate_linux_abi::{
    LinuxErrno, LinuxStatFields, EACCES, EEXIST, EISDIR, ELOOP, ENFILE, ENOENT, ENOSPC, ENOTDIR,
    EROFS, S_IFDIR, S_IFLNK, S_IFREG,
};
use clean_slate_rootfs::{EntryKind, Image};

pub const LINUX_FS_MAX_NODES: usize = 64;
pub const LINUX_FS_MAX_LINK_DEPTH: usize = 2;
const NAME_MAX: usize = 64;

pub(crate) use crate::process::linux_fd::open_description::LinuxFsNodeId as NodeId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeKind {
    Dir,
    File,
    Link,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NodeBackend {
    Rootfs { entry_index: u16 },
    Object { object_id: u64 },
    TmpDir,
}

#[derive(Clone, Copy)]
struct Node {
    live: bool,
    generation: u32,
    kind: NodeKind,
    backend: NodeBackend,
    name: [u8; NAME_MAX],
    name_len: u8,
    parent: u16,
}

pub(crate) struct NodeTable {
    nodes: [Node; LINUX_FS_MAX_NODES],
    live_count: u16,
    root_index: u16,
}

impl NodeTable {
    pub const fn new() -> Self {
        const EMPTY: Node = Node {
            live: false,
            generation: 1,
            kind: NodeKind::Dir,
            backend: NodeBackend::Rootfs { entry_index: 0 },
            name: [0; NAME_MAX],
            name_len: 0,
            parent: 0,
        };
        Self {
            nodes: [EMPTY; LINUX_FS_MAX_NODES],
            live_count: 0,
            root_index: 0,
        }
    }

    pub fn init_rootfs(&mut self, _image: &Image<'_>) -> Result<(), &'static str> {
        self.nodes[0] = Node {
            live: true,
            generation: 1,
            kind: NodeKind::Dir,
            backend: NodeBackend::Rootfs { entry_index: 0 },
            name: [0; NAME_MAX],
            name_len: 1,
            parent: 0,
        };
        self.nodes[0].name[0] = b'/';
        self.live_count = 1;
        self.root_index = 0;
        Ok(())
    }

    pub fn lookup_path(
        &mut self,
        path: &[u8],
        image: &Image<'_>,
        follow_final_link: bool,
    ) -> Result<NodeId, LinuxErrno> {
        let mut norm = [0u8; LINUX_PATH_MAX];
        let len = normalize_path(path, &mut norm)?;
        let norm = &norm[..len];
        if norm == b"/" {
            return Ok(NodeId {
                index: self.root_index,
                generation: self.nodes[self.root_index as usize].generation,
            });
        }
        self.walk(norm, image, follow_final_link, 0)
    }

    fn walk(
        &mut self,
        path: &[u8],
        image: &Image<'_>,
        follow_final_link: bool,
        depth: usize,
    ) -> Result<NodeId, LinuxErrno> {
        let mut current = NodeId {
            index: self.root_index,
            generation: self.nodes[self.root_index as usize].generation,
        };
        let mut rest = path;
        if rest.starts_with(b"/") {
            rest = &rest[1..];
        }
        while !rest.is_empty() {
            let (seg, tail) = split_component(rest);
            rest = tail;
            let is_last = rest.is_empty();
            current = self.descend(current, seg, image)?;
            if is_last && follow_final_link {
                current = self.maybe_follow_link(current, image, depth)?;
            } else if !is_last {
                let node = &self.nodes[current.index as usize];
                if node.kind != NodeKind::Dir {
                    return Err(ENOTDIR);
                }
            }
        }
        Ok(current)
    }

    fn descend(
        &mut self,
        parent: NodeId,
        name: &[u8],
        image: &Image<'_>,
    ) -> Result<NodeId, LinuxErrno> {
        self.check_node(parent)?;
        let parent_node = &self.nodes[parent.index as usize];
        if parent_node.kind != NodeKind::Dir {
            return Err(ENOTDIR);
        }
        for index in 0..LINUX_FS_MAX_NODES {
            let node = &self.nodes[index];
            if !node.live || node.parent != parent.index {
                continue;
            }
            if node.name_len as usize == name.len() && &node.name[..name.len()] == name {
                return Ok(NodeId {
                    index: index as u16,
                    generation: node.generation,
                });
            }
        }
        let parent_path = self.path_of(parent.index, image)?;
        let parent_len = path_buf_len(&parent_path);
        let mut child_path = [0u8; LINUX_PATH_MAX];
        let mut pos = parent_len;
        child_path[..pos].copy_from_slice(&parent_path[..parent_len]);
        if child_path[pos - 1] != b'/' {
            child_path[pos] = b'/';
            pos += 1;
        }
        if pos + name.len() >= LINUX_PATH_MAX {
            return Err(clean_slate_linux_abi::ENAMETOOLONG);
        }
        child_path[pos..pos + name.len()].copy_from_slice(name);
        pos += name.len();
        let child_path = &child_path[..pos];
        if let Some(tmp) = tmp_file_lookup_by_path(child_path) {
            return self.attach_tmp_file_node(parent.index, name, tmp);
        }
        if let Some(entry) = image.lookup(child_path) {
            return self.materialize_rootfs_node(parent.index, name, child_path, entry, image);
        }
        Err(ENOENT)
    }

    fn materialize_rootfs_node(
        &mut self,
        parent_index: u16,
        name: &[u8],
        path: &[u8],
        entry: clean_slate_rootfs::Entry<'_>,
        image: &Image<'_>,
    ) -> Result<NodeId, LinuxErrno> {
        let index = self.alloc_node()?;
        let kind = match entry.kind {
            EntryKind::Dir => NodeKind::Dir,
            EntryKind::File => NodeKind::File,
            EntryKind::Link => NodeKind::Link,
        };
        let backend = NodeBackend::Rootfs {
            entry_index: find_entry_index(image, path).ok_or(ENOENT)?,
        };
        self.fill_node(index, parent_index, name, kind, backend);
        Ok(node_id(self, index))
    }

    fn attach_tmp_file_node(
        &mut self,
        parent_index: u16,
        name: &[u8],
        object_id: u64,
    ) -> Result<NodeId, LinuxErrno> {
        for index in 0..LINUX_FS_MAX_NODES {
            let node = &self.nodes[index];
            if node.live
                && node.parent == parent_index
                && node.name_len as usize == name.len()
                && &node.name[..name.len()] == name
            {
                return Ok(NodeId {
                    index: index as u16,
                    generation: node.generation,
                });
            }
        }
        let index = self.alloc_node()?;
        self.fill_node(
            index,
            parent_index,
            name,
            NodeKind::File,
            NodeBackend::Object { object_id },
        );
        Ok(node_id(self, index))
    }

    fn maybe_follow_link(
        &mut self,
        node: NodeId,
        image: &Image<'_>,
        depth: usize,
    ) -> Result<NodeId, LinuxErrno> {
        let n = &self.nodes[node.index as usize];
        if n.kind != NodeKind::Link {
            return Ok(node);
        }
        if depth >= LINUX_FS_MAX_LINK_DEPTH {
            return Err(ELOOP);
        }
        let path = self.path_of(node.index, image)?;
        let path_len = path_buf_len(&path);
        let entry = image.lookup(&path[..path_len]).ok_or(ENOENT)?;
        let target = entry.data;
        self.walk(target, image, true, depth + 1)
    }

    pub fn mkdir(&mut self, path: &[u8], image: &Image<'_>) -> Result<(), LinuxErrno> {
        let mut norm = [0u8; LINUX_PATH_MAX];
        let len = normalize_path(path, &mut norm)?;
        let norm = &norm[..len];
        if norm == b"/" {
            return Err(EEXIST);
        }
        if !norm.starts_with(b"/tmp/") && norm != b"/tmp" {
            return Err(EROFS);
        }
        if norm == b"/tmp" {
            return Err(EEXIST);
        }
        let (parent_path, name) = split_parent(norm)?;
        let parent = self.lookup_path(parent_path, image, true)?;
        let parent_node = &self.nodes[parent.index as usize];
        if parent_node.kind != NodeKind::Dir {
            return Err(ENOTDIR);
        }
        if self.child_exists(parent.index, name) {
            return Err(EEXIST);
        }
        if tmp_children_count(parent.index, &self.nodes) >= LINUX_TMP_MAX_ENTRIES {
            return Err(ENOSPC);
        }
        let index = self.alloc_node()?;
        self.fill_node(
            index,
            parent.index,
            name,
            NodeKind::Dir,
            NodeBackend::TmpDir,
        );
        Ok(())
    }

    pub fn open_create_file(
        &mut self,
        path: &[u8],
        truncate: bool,
        image: &Image<'_>,
    ) -> Result<NodeId, LinuxErrno> {
        let mut norm = [0u8; LINUX_PATH_MAX];
        let len = normalize_path(path, &mut norm)?;
        let norm = &norm[..len];
        if !norm.starts_with(b"/tmp/") {
            return Err(EROFS);
        }
        let (parent_path, name) = split_parent(norm)?;
        let parent = self.lookup_path(parent_path, image, true)?;
        if let Some(existing) = self.find_child(parent.index, name) {
            let node = &self.nodes[existing as usize];
            if node.kind != NodeKind::File {
                return Err(EISDIR);
            }
            if truncate {
                if let NodeBackend::Object { object_id } = node.backend {
                    super::object_backend::tmp_file_truncate_local(object_id)?;
                }
            }
            return Ok(NodeId {
                index: existing,
                generation: node.generation,
            });
        }
        if tmp_children_count(parent.index, &self.nodes) >= LINUX_TMP_MAX_ENTRIES {
            return Err(ENOSPC);
        }
        let object_id = tmp_file_create(norm)?;
        let index = self.alloc_node()?;
        self.fill_node(
            index,
            parent.index,
            name,
            NodeKind::File,
            NodeBackend::Object { object_id },
        );
        if truncate {
            super::object_backend::tmp_file_truncate_local(object_id)?;
        }
        Ok(NodeId {
            index,
            generation: self.nodes[index as usize].generation,
        })
    }

    pub fn check_node(&self, id: NodeId) -> Result<(), LinuxErrno> {
        let node = &self.nodes[id.index as usize];
        if !node.live || node.generation != id.generation {
            return Err(clean_slate_linux_abi::EBADF);
        }
        Ok(())
    }

    pub fn stat_fields(
        &mut self,
        id: NodeId,
        image: &Image<'_>,
        for_lstat: bool,
    ) -> Result<LinuxStatFields, LinuxErrno> {
        self.check_node(id)?;
        let node = &self.nodes[id.index as usize];
        let path = self.path_of(id.index, image)?;
        let path_len = path.iter().position(|&b| b == 0).unwrap_or(LINUX_PATH_MAX);
        let path = &path[..path_len];
        if for_lstat && node.kind == NodeKind::Link {
            let entry = image.lookup(path).ok_or(ENOENT)?;
            return Ok(LinuxStatFields {
                st_dev: 1,
                st_ino: (id.index as u64) + 1,
                st_nlink: 1,
                st_mode: S_IFLNK | 0o777,
                st_uid: 0,
                st_gid: 0,
                st_rdev: 0,
                st_size: entry.data.len() as i64,
                st_blksize: 4096,
                st_blocks: entry.data.len().div_ceil(512) as i64,
            });
        }
        let mut effective = id;
        if !for_lstat && node.kind == NodeKind::Link {
            let entry = image.lookup(path).ok_or(ENOENT)?;
            effective = self.lookup_path(entry.data, image, true)?;
        }
        let node = &self.nodes[effective.index as usize];
        let full = self.path_of(effective.index, image)?;
        let full_len = full.iter().position(|&b| b == 0).unwrap_or(LINUX_PATH_MAX);
        let full = &full[..full_len];
        let (size, mode) = match node.backend {
            NodeBackend::Rootfs { entry_index: _ } => {
                let entry = image.lookup(full).ok_or(ENOENT)?;
                let mode = mode_for_path(full, node.kind);
                (entry.data.len() as i64, mode)
            }
            NodeBackend::Object { object_id } => {
                let len = tmp_file_by_object_id(object_id).map(|f| f.len).unwrap_or(0);
                (len as i64, S_IFREG | 0o644)
            }
            NodeBackend::TmpDir => (0, S_IFDIR | 0o755),
        };
        Ok(LinuxStatFields {
            st_dev: 1,
            st_ino: (effective.index as u64) + 1,
            st_nlink: 1,
            st_mode: mode,
            st_uid: 0,
            st_gid: 0,
            st_rdev: 0,
            st_size: size,
            st_blksize: 4096,
            st_blocks: (size as usize).div_ceil(512) as i64,
        })
    }

    pub fn rootfs_entry_data<'a>(
        &self,
        id: NodeId,
        image: &'a Image<'a>,
    ) -> Result<&'a [u8], LinuxErrno> {
        self.check_node(id)?;
        let node = &self.nodes[id.index as usize];
        match node.backend {
            NodeBackend::Rootfs { entry_index } => {
                let entry = image.entry(entry_index as usize).ok_or(ENOENT)?;
                Ok(entry.data)
            }
            _ => Err(clean_slate_linux_abi::EINVAL),
        }
    }

    pub fn node_kind(&self, id: NodeId) -> Result<NodeKind, LinuxErrno> {
        self.check_node(id)?;
        Ok(self.nodes[id.index as usize].kind)
    }

    pub fn object_id_for_node(&self, id: NodeId) -> Result<u64, LinuxErrno> {
        self.check_node(id)?;
        match self.nodes[id.index as usize].backend {
            NodeBackend::Object { object_id } => Ok(object_id),
            _ => Err(clean_slate_linux_abi::EINVAL),
        }
    }

    pub fn list_children(
        &mut self,
        dir: NodeId,
        image: &Image<'_>,
        out: &mut [(NodeId, u8); 32],
    ) -> Result<usize, LinuxErrno> {
        self.check_node(dir)?;
        if self.nodes[dir.index as usize].kind != NodeKind::Dir {
            return Err(ENOTDIR);
        }
        let mut count = 0usize;
        let dir_path = self.path_of(dir.index, image)?;
        let dir_len = dir_path
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(LINUX_PATH_MAX);
        let dir_path = &dir_path[..dir_len];
        for child in image.children(dir_path) {
            if count >= out.len() {
                break;
            }
            let id = self.lookup_path(child.path, image, false)?;
            let kind = self.nodes[id.index as usize].kind;
            let dt = dirent_type(kind);
            out[count] = (id, dt);
            count += 1;
        }
        for index in 0..LINUX_FS_MAX_NODES {
            if count >= out.len() {
                break;
            }
            if index as u16 == dir.index {
                continue;
            }
            let node = &self.nodes[index];
            if !node.live || node.parent != dir.index {
                continue;
            }
            let id = NodeId {
                index: index as u16,
                generation: node.generation,
            };
            if out[..count].iter().any(|(n, _)| n.index == id.index) {
                continue;
            }
            out[count] = (id, dirent_type(node.kind));
            count += 1;
        }
        Ok(count)
    }

    pub fn live_count(&self) -> u16 {
        self.live_count
    }

    fn alloc_node(&mut self) -> Result<u16, LinuxErrno> {
        for index in 1..LINUX_FS_MAX_NODES {
            if !self.nodes[index].live {
                return Ok(index as u16);
            }
        }
        Err(ENFILE)
    }

    #[cfg(all(test, feature = "m9-rootfs"))]
    pub(crate) fn host_test_evict_node(&mut self, id: NodeId) -> Result<(), LinuxErrno> {
        self.check_node(id)?;
        if id.index == self.root_index {
            return Err(EACCES);
        }
        let slot = &mut self.nodes[id.index as usize];
        slot.live = false;
        slot.generation = slot.generation.wrapping_add(1);
        self.live_count = self.live_count.saturating_sub(1);
        Ok(())
    }

    fn fill_node(
        &mut self,
        index: u16,
        parent: u16,
        name: &[u8],
        kind: NodeKind,
        backend: NodeBackend,
    ) {
        let slot = &mut self.nodes[index as usize];
        if !slot.live {
            self.live_count += 1;
        }
        slot.live = true;
        slot.generation = slot.generation.max(1);
        slot.kind = kind;
        slot.backend = backend;
        slot.parent = parent;
        slot.name_len = name.len() as u8;
        slot.name[..name.len()].copy_from_slice(name);
    }

    fn child_exists(&self, parent: u16, name: &[u8]) -> bool {
        self.find_child(parent, name).is_some()
    }

    fn find_child(&self, parent: u16, name: &[u8]) -> Option<u16> {
        for index in 0..LINUX_FS_MAX_NODES {
            let node = &self.nodes[index];
            if node.live
                && node.parent == parent
                && node.name_len as usize == name.len()
                && &node.name[..name.len()] == name
            {
                return Some(index as u16);
            }
        }
        None
    }

    pub(crate) fn path_of_node(
        &self,
        index: u16,
        image: &Image<'_>,
    ) -> Result<[u8; LINUX_PATH_MAX], LinuxErrno> {
        self.path_of(index, image)
    }

    /// Final path component for `getdents64` (not the full normalized path).
    pub(crate) fn dirent_name(&self, id: NodeId) -> Result<&[u8], LinuxErrno> {
        self.check_node(id)?;
        let node = &self.nodes[id.index as usize];
        let len = node.name_len as usize;
        if len == 0 || (len == 1 && node.name[0] == b'/') {
            return Err(clean_slate_linux_abi::EINVAL);
        }
        Ok(&node.name[..len])
    }

    fn path_of(&self, index: u16, _image: &Image<'_>) -> Result<[u8; LINUX_PATH_MAX], LinuxErrno> {
        let mut buf = [0u8; LINUX_PATH_MAX];
        let mut stack = [0u16; 16];
        let mut depth = 0usize;
        let mut cur = index;
        while depth < stack.len() {
            stack[depth] = cur;
            depth += 1;
            let parent = self.nodes[cur as usize].parent;
            if parent == cur {
                break;
            }
            cur = parent;
        }
        let mut pos = 0usize;
        for level in (0..depth).rev() {
            let node = &self.nodes[stack[level] as usize];
            let name_len = node.name_len as usize;
            if name_len == 1 && node.name[0] == b'/' {
                if pos == 0 {
                    buf[pos] = b'/';
                    pos += 1;
                }
                continue;
            }
            if pos > 0 && buf[pos - 1] != b'/' {
                buf[pos] = b'/';
                pos += 1;
            }
            if pos + name_len > LINUX_PATH_MAX {
                return Err(clean_slate_linux_abi::ENAMETOOLONG);
            }
            buf[pos..pos + name_len].copy_from_slice(&node.name[..name_len]);
            pos += name_len;
        }
        if pos == 0 {
            buf[0] = b'/';
        }
        Ok(buf)
    }
}

fn mode_for_path(path: &[u8], kind: NodeKind) -> u32 {
    match kind {
        NodeKind::Dir => S_IFDIR | 0o755,
        NodeKind::Link => S_IFLNK | 0o777,
        NodeKind::File if path.starts_with(b"/etc/") => S_IFREG | 0o644,
        NodeKind::File => S_IFREG | 0o755,
    }
}

fn find_entry_index(image: &Image<'_>, path: &[u8]) -> Option<u16> {
    for index in 0..image.len() {
        if let Some(entry) = image.entry(index) {
            if entry.path == path {
                return Some(index as u16);
            }
        }
    }
    None
}

fn path_buf_len(buf: &[u8; LINUX_PATH_MAX]) -> usize {
    buf.iter().position(|&b| b == 0).unwrap_or(LINUX_PATH_MAX)
}

fn split_component(path: &[u8]) -> (&[u8], &[u8]) {
    match path.iter().position(|&b| b == b'/') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (path, b""),
    }
}

fn final_component(path: &[u8]) -> Result<&[u8], LinuxErrno> {
    let mut p = path;
    if p.ends_with(b"/") && p.len() > 1 {
        p = &p[..p.len() - 1];
    }
    match p.rsplit(|&b| b == b'/').next() {
        Some(name) if !name.is_empty() => Ok(name),
        _ => Err(ENOENT),
    }
}

fn parent_path_bytes(path: &[u8]) -> Result<&[u8], LinuxErrno> {
    if path == b"/" {
        return Ok(b"/");
    }
    let mut p = path;
    if p.ends_with(b"/") {
        p = &p[..p.len() - 1];
    }
    match p.iter().rposition(|&b| b == b'/') {
        None => Err(ENOENT),
        Some(0) => Ok(b"/"),
        Some(pos) => Ok(&p[..pos]),
    }
}

fn split_parent(path: &[u8]) -> Result<(&[u8], &[u8]), LinuxErrno> {
    let name = final_component(path)?;
    let parent = parent_path_bytes(path)?;
    Ok((parent, name))
}

fn tmp_children_count(parent: u16, nodes: &[Node]) -> usize {
    nodes
        .iter()
        .filter(|n| n.live && n.parent == parent)
        .count()
}

pub(crate) fn check_write_allowed(path: &[u8], flags: u32) -> Result<(), LinuxErrno> {
    let mut norm = [0u8; LINUX_PATH_MAX];
    let len = normalize_path(path, &mut norm)?;
    let norm = &norm[..len];
    let write_intent = (flags
        & (clean_slate_linux_abi::O_WRONLY
            | clean_slate_linux_abi::O_RDWR
            | clean_slate_linux_abi::O_CREAT
            | clean_slate_linux_abi::O_TRUNC
            | clean_slate_linux_abi::O_APPEND))
        != 0;
    if write_intent && !norm.starts_with(b"/tmp") {
        return Err(EROFS);
    }
    Ok(())
}

fn node_id(table: &NodeTable, index: u16) -> NodeId {
    NodeId {
        index,
        generation: table.nodes[index as usize].generation,
    }
}

fn dirent_type(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Dir => clean_slate_linux_abi::DT_DIR,
        NodeKind::File => clean_slate_linux_abi::DT_REG,
        NodeKind::Link => clean_slate_linux_abi::DT_LNK,
    }
}

pub(crate) fn resolve_executable_bytes<'a>(
    table: &mut NodeTable,
    image: &'a Image<'a>,
    path: &[u8],
) -> Result<&'a [u8], LinuxErrno> {
    let id = table.lookup_path(path, image, true)?;
    let node = &table.nodes[id.index as usize];
    if node.kind != NodeKind::File {
        return Err(EACCES);
    }
    match node.backend {
        NodeBackend::Rootfs { .. } => {
            let full = table.path_of(id.index, image)?;
            let len = full.iter().position(|&b| b == 0).unwrap_or(LINUX_PATH_MAX);
            let entry = image.lookup(&full[..len]).ok_or(ENOENT)?;
            Ok(entry.data)
        }
        NodeBackend::Object { .. } => Err(EACCES),
        NodeBackend::TmpDir => Err(EACCES),
    }
}
