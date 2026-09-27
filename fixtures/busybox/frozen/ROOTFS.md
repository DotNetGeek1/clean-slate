# M9 #104 — deterministic BusyBox rootfs fixture

## Provenance chain

1. **Container/toolchain** — pinned in `toolchain.txt` and `M9_DEPENDENCY_MATRIX.md` (BusyBox 1.37.0 musl-static).
2. **Binary** — `busybox` rebuilt via `build.sh` / Dockerfile; SHA-256 in `busybox.sha256` and `commands.toml` meta.
3. **Manifest** — `rootfs.toml` lists dirs, the pinned `busybox` file, `/bin/<applet>` links, and inline `/etc/*` bytes.
4. **Image** — `clean-slate-rootfs` packs the manifest into `CSROOTFS` v1 (`cargo xtask verify-m9-fixture` prints the entry table and image SHA-256).

No host `/etc`, resolver, network, or timestamps participate in the image bytes.

## Read-only vs writable

| Path | Kind | Notes |
|------|------|-------|
| `/` | dir | implicit root |
| `/bin`, `/etc` | dir | read-only in the image |
| `/bin/busybox` | file | frozen ELF bytes |
| `/bin/<applet>` | link → `/bin/busybox` | BusyBox applet selection uses the **original** path (`argv[0]` / `AT_EXECFN`), not the link target |
| `/etc/hostname` | file | `m9-fixture\n` |
| `/etc/resolv.conf` | file | `nameserver 10.77.0.1\n` (matches `nslookup-fixture.strace`) |
| `/tmp` | dir | `writable` flag — projected writable root for #101 (M5/M6-backed persistence) |

## Verification

```bash
cargo xtask verify-m9-fixture
```

Checks BusyBox SHA-256 (`busybox.sha256`, `commands.toml` meta and the manifest pin agree), ELF metadata (ET_EXEC, x86-64, first PT_LOAD at `0x400000`, no interpreter/dynamic), that `commands.toml` matches `run-traces.sh` (command order, the `/tmp/script.sh` heredoc byte-for-byte, a trace per command), that every applet a command uses has a `/bin/<applet>` link, manifest link names vs `applets.txt`, deterministic double-pack equality, and the pinned image SHA-256 (`ROOTFS_IMAGE_SHA256` in `xtask/src/m9_fixture.rs` and `kernel/build.rs`).

## Kernel embed

With `m9-rootfs`, `kernel/build.rs` packs `rootfs.toml` into `$OUT_DIR/m9-rootfs.img` after verifying the BusyBox hash and the pinned image hash, and generates the command matrix and BusyBox CRC/length pins that `test-m9-userspace` uses (see [docs/M9.md](../../../docs/M9.md)). `process::linux_rootfs::image()` parses the embedded bytes via `clean-slate-rootfs` (no_std reader).
