# M9 dependency matrix (Phase B frozen — post to #99)

**Binary:** `fixtures/busybox/frozen/busybox` SHA-256 `7ba56acec9fb89deace4ebfab6f4baaa8d1b778754b8f7ae3dbd7cf7990fe380`  
**Evidence:** `fixtures/busybox/frozen/traces/*.strace`, `fixtures/busybox/syscall-matrix.toml` (`meta.candidate = "frozen"`).

| Issue | Owns (required syscalls) | Frozen commands | Blocking / readiness (#145) | Notes |
|-------|--------------------------|-----------------|-----------------------------|-------|
| **#146** | `execve` | all | — | Static ET_EXEC @ ~`0x400000`; `argv[0]` basename selects applet (`grep-via-symlink`). |
| **#147** | `read`, `write`, `writev`, `close`, `fstat`, `dup2`, `fcntl`, `lseek`; `open` secondary | I/O-heavy commands | `read` may-block (pipe 1024); `fcntl` dup | fd table ≥ **12** (0..11). Kinds: file, pipe, TCP client, UDP client, stdio. |
| **#101** | `open`, `stat`, `lstat`, `getcwd`, `chdir`, `mkdir`, `getdents64` | path / ls / tmp-file | — | Paths are bytes; `getcwd("/",4096)`; no `openat` in matrix. |
| **#102** | `fork`, `pipe`, `wait4`, `getppid`, `exit_group` | `pipe-grep*`, `tmp-file-io`, `exit-3`, `script-sh` | `wait4` blocking reap | `fork` only (no `clone`/`vfork`). |
| **#103** | `mmap`, `munmap`, `brk`, `mprotect`, `rt_sig*`, `ioctl`, `poll`, `nanosleep`, `getpid`, `getuid`, `arch_prctl`, `set_tid_address`, `uname` | startup + DNS + `sleep-0` | `poll` 2500ms DNS; `nanosleep` zero timeout | `ioctl` `TIOCGWINSZ` → `ENOTTY`; SIGCHLD delivery only. |
| **#105** | `socket`, `connect`, `sendto`, `bind` | `nslookup-fixture`, `wget-fixture-http` | `connect` may-block; `poll` on UDP | Fixture DNS **10.77.0.1**; HTTP **10.77.0.50:4001**; AAAA **empty answer** policy. |

**Explicit non-owners / not required:** `sendfile`, `accept`, `listen`, `recvfrom` (not observed), `kill`, `futex`, `clone`, `epoll`, `socketpair`, in-process `httpd`.

**#104 / M7 fixture:** implement `fixture-responder.py` behaviour (DNS A → `10.77.0.50`, AAAA NOERROR zero answers, HTTP `M9-FIXTURE-HTTP\n`).

**#xtask (#104):** `cargo xtask` must verify `busybox.sha256` equals `7ba56acec9fb89deace4ebfab6f4baaa8d1b778754b8f7ae3dbd7cf7990fe380` after `fixtures/busybox/frozen/build.sh` (or CI Docker build) before bundling the M9 rootfs.
