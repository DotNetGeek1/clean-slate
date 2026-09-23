# M9 BusyBox ABI inventory (Phase A — #100, revised)

Draft contract from **Linux strace evidence** (Docker linux/amd64, `strace -f -tt -s 200`). Phase B freezes the binary; this document does **not** freeze the artifact.

**Attribution:** `fixtures/busybox/gen-syscall-matrix.py` parses each trace with `-f` PIDs, maps `execve("/bin/…")` → applet name, and classifies **`harness_only`** vs **`required`**. The M9 fixture command matrix never runs **`busybox httpd`**; `wget-local-httpd.strace` is a local success-path harness only.

Machine-readable matrix: `fixtures/busybox/syscall-matrix.toml` (`syscall_count` = required syscalls only; `harness_only_count` separate).

**Highest fd observed:** **11** (`fcntl(F_DUPFD_CLOEXEC, 10)` → fd 11 in `script-sh.strace:245`; `#147` should size fd table ≥ **12** slots for 0..11).

---

## Candidate comparison

| | **musl-minimal** (recommended) | **alpine-static** (package) |
|---|----------------|----------------|
| Version | BusyBox **1.37.0** | **1.37.0-r14** |
| SHA-256 | `2877cefa6ac0b1c755c477845b646e0733e5ab4501cdfd3a048974abcbf4164c` | `aa1e1f4214ec2489ed373f3c5b92b7a7c665821a1decaa9685e5363886a93c7c` |
| `e_type` / entry | **ET_EXEC** @ `0x41798d` | **ET_DYN** + **PT_INTERP** |
| Link region | **0x400000** (see `musl-minimal/readelf.txt`) | PIE low VA |

**Recommendation (not frozen):** **musl-minimal** — static ET_EXEC, reproducible build, no dynamic loader.

---

## Harness-only (NOT M9 fixture)

From **`wget-local-httpd.strace`** only (local `httpd -p 18080` + `wget http://127.0.0.1/` + `kill`):

| nr | syscall | PIDs / applets | evidence |
|----|---------|----------------|----------|
| 43 | `accept` | httpd worker | `wget-local-httpd.strace:174` |
| 50 | `listen` | httpd | `wget-local-httpd.strace:169` |
| 62 | `kill` | outer sh | `wget-local-httpd.strace:314` |
| 80 | `chdir` | httpd `-h /var/www` | `wget-local-httpd.strace:164` |
| 41 | `socket(AF_INET6,…)` | httpd listen | `wget-local-httpd.strace:166` |
| 40 | `sendfile` | httpd → TCP (not file→stdout) | `wget-local-httpd.strace:260` |
| 42 | `connect` | wget → **127.0.0.1:18080** | `wget-local-httpd.strace:212` |
| 49 | `bind` | **:18080** | `wget-local-httpd.strace:168` |

Also harness-only in that trace: **`sleep`** applet (`sleep 0.2`), **`wget`** client to 127.0.0.1. Fixture HTTP/TCP success path for M7 port **4001** is **`wget-fixture-fail.strace`** (DNS + connect shape; connect fails after name resolution failure).

**Removed from fixture blocking/kinds lists:** `accept`, TCP **listening** socket kind, httpd `chdir`/`kill`.

---

## Command matrix → syscall closure (fixture only)

Distinct **required** syscalls each frozen command needs (see matrix for line evidence):

| Command trace | Syscall closure (nr / name) |
|---------------|----------------------------|
| `true` / `sh-c-minimal` | 158 arch_prctl, 218 set_tid_address, 12 brk, 9 mmap (anon), 39 getpid, 110 getppid, 79 getcwd, 4 stat, 13/14 rt_sig*, 102 getuid, 231 exit_group, 59 execve |
| `busybox-list` | above + 1 write, 2 open, 33 dup2 |
| `pwd`, `uname` | ash + 1 writev, 16 ioctl TIOCGWINSZ ENOTTY, 63 uname |
| `ls-root`, `script-sh` (ls lines) | + 6 lstat, 217 getdents64, 2 open dir |
| `cat-hostname`, script cat | + 2 open file, 0 read/sendfile* or read path, 40 sendfile optional |
| `tmp-file-io` | + 57 fork, 61 wait4, 83 mkdir, 2 O_CREAT, 72 fcntl dup, 33 dup2 |
| `pipe-grep` | + 22 pipe, 57 fork×2, 61 wait4 block+WNOHANG, 59 execve `/bin/grep` (`pipe-grep.strace:179`) |
| `nslookup-fixture` | + 2 open resolv.conf, 0 read, 41/49/42 UDP, 1 write×2 (A+AAAA), 7 poll timeout, 63 uname |
| `wget-fixture-fail` | + 41 SOCK_DGRAM\|CLOEXEC\|NONBLOCK, 44 sendto×2, 7 poll ignore fd=-1, 1 write stderr |
| `sleep-1` | + 35 nanosleep 1s |
| `exit-3` | + 57 fork, 61 wait4 status 3 (`exit-3.strace:136`) |
| `script-sh` | sequential closure of pwd/ls/cat/mkdir/printf/pipe/uname/sleep |

\* **`sendfile`:** observed file→stdout (`cat-hostname.strace:125`) but **`required = false`** pending Phase B config (see below).

Supplement traces (same fixture policy): `pipe-grep-env-i`, `pipe-grep-path-only`, `grep-via-busybox`, `grep-via-symlink`.

---

## Process primitive (#102)

- **`fork(57)`** only — e.g. pipeline: `pipe-grep.strace:122` (echo side), `:148` (grep side); child **`execve("/bin/grep", …)`** at `:179`.
- **`wait4(61)`:** blocking `wait4(-1, …, 0, NULL)` returns child status (`pipe-grep.strace:168`, `:197`; `exit-3.strace:136` status **3**); then **`wait4(-1, …, WNOHANG, NULL)` → `-1 ECHILD`** (`pipe-grep.strace:200`).
- **`exit_group(231)` → #102** (not #103): all applets (`true.strace:98`).

---

## Flag / arg enumeration (lane inputs)

### Sockets (#105)

**nslookup** (`nslookup-fixture.strace`):

1. `open("/etc/resolv.conf", O_RDONLY|O_LARGEFILE)` `:124`
2. `read` nameserver line `:129`
3. `socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)` `:136`
4. `bind(0.0.0.0:0)` `:137`
5. `connect(10.77.0.1:53)` `:138`
6. `fcntl F_GETFL` / `F_SETFL O_NONBLOCK` `:139-140`
7. **`write`×2** DNS wire: **A (type 1)** `:141` and **AAAA (type 28 / `\034`)** `:142` — M7 fixture must tolerate AAAA **NXDOMAIN/no-answer** without breaking **A** answer for `#104`/`#105`.
8. `poll([{fd=3,POLLIN}], 1, 2500)` timeout `:143-146`
9. **Phase B gap:** no **`read`/`recvfrom`** after reply (no server in Docker).

**wget / musl DNS** (`wget-fixture-fail.strace`):

1. `socket(AF_INET, SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK)` `:137`
2. `bind` ephemeral `:138`
3. `sendto(..., MSG_NOSIGNAL, 10.77.0.1:53)` A + AAAA `:139-140`
4. **`poll([{fd=-1},{fd=-1},{fd=3,POLLIN}], 3, 2500)`** — **must ignore negative fds** `:141`
5. **Phase B gap:** **`recvfrom` on success** not observed.

**Fixture TCP client (no httpd):** connect to **`m7.fixture.test:4001`** after DNS — fails in `wget-fixture-fail.strace:146` (`bad address`).

### `open` (#101 primary, #147 fd for `open`)

| Flags | Mode | Use | evidence |
|-------|------|-----|----------|
| `O_RDONLY\|O_LARGEFILE` | — | cat, resolv | `cat-hostname.strace:124`, `nslookup-fixture.strace:124` |
| `O_RDONLY\|O_LARGEFILE\|O_CLOEXEC` | — | script, dir | `script-sh.strace:115`, `:156` |
| `O_RDONLY\|O_LARGEFILE\|O_CLOEXEC\|O_DIRECTORY` | — | ls | `script-sh.strace:156` |
| `O_WRONLY\|O_CREAT\|O_TRUNC\|O_LARGEFILE` | **0666** | `> file` | `tmp-file-io.strace:152` |

No **`openat`/`newfstatat`** in fixture slice.

### `fcntl` (#147)

| Command | evidence |
|---------|----------|
| `F_SETFD, FD_CLOEXEC` on script fd | `script-sh.strace:116` |
| `F_DUPFD_CLOEXEC, 10` → fd **10** | `tmp-file-io.strace:153` |
| `F_DUPFD_CLOEXEC, 10` → fd **11** | `script-sh.strace:245` |
| `F_GETFL` / `F_SETFL O_NONBLOCK` (DNS) | `nslookup-fixture.strace:139-140` |
| `F_GETFL` on redirected stdout | `tmp-file-io.strace:157` |

### `dup2` (#147)

| (old, new) | evidence |
|------------|----------|
| (3, 1) redirect to file | `tmp-file-io.strace:155` |
| (10, 1) restore stdout | `tmp-file-io.strace:160` |
| (3, 0) pipe stdin to grep | `pipe-grep.strace:177` |
| (4, 1) pipe stdout | `pipe-grep.strace:143` |
| (1, 2) stderr merge | `busybox-list.strace:102` |

### `mmap` / `munmap` / `brk` (#103)

- **No file-backed `mmap` in fixture slice** (chroot host `mmap(..., fd=3)` lines excluded).
- **Anonymous only:** `MAP_PRIVATE|MAP_ANONYMOUS` heap/stack (`true.strace:84-88`), `MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS` guard pages (`true.strace:84`), grep scratch (`pipe-grep.strace:186-191` munmap).
- **`brk`:** NULL probe + increment (`true.strace:82-83`).

### `write` / `read` / `writev` bounds (#147)

- **`writev`:** max **2 iov** (`pipe-grep.strace:193`).
- **`read`:** pipe **1024** byte chunks (`pipe-grep.strace:187`); HTTP body read loop **Phase B** (`wget-local-httpd.strace:229` harness only).

### `getdents64` (#101)

- Buffer **2048**, until **0 entries** (`ls-root.strace:135`, `:143`).

### `ioctl` (#103)

- **`TIOCGWINSZ`** on fd 0/1 → **`-1 ENOTTY`** batch mode (`ls-root.strace:124-126`). No **`TCGETS`**.

### Signals (#103 record-only for M9 batch)

**Ash installs** (`true.strace:89-97`, `pipe-grep.strace:115-118`):

- `rt_sigprocmask`: `SIG_UNBLOCK [RT_1 RT_2]`; pipeline adds `SIG_BLOCK` around `fork`.
- `rt_sigaction`: **SIGCHLD** handler `0x46e54e` + **`SA_RESTORER`**; **SIGINT** same; query **SIGQUIT/SIGTERM** defaults.

**Delivered in fixture traces:** **`SIGCHLD` only** (`pipe-grep.strace:170`, `:198`; `exit-3.strace:137`; `script-sh.strace` multiple). **No** `SIGINT`/`SIGPIPE` delivery in frozen commands. M9 may treat handlers as **record-only** without delivery for **`sh -c`/script** batch mode.

---

## Lane ownership (required syscalls)

Counts match `syscall-matrix.toml` **`syscall_count = 35`**.

| Owner | Required syscalls |
|-------|-------------------|
| **#146** | execve |
| **#147** | read, write, writev, close, fstat, dup2, fcntl, lseek; **open** has `secondary_owner = "#147"` |
| **#101** | open, stat, lstat, getcwd, chdir, mkdir, getdents64 |
| **#102** | fork, pipe, wait4, getppid, exit_group |
| **#103** | mmap, munmap, brk, mprotect, rt_sig*, ioctl, poll, nanosleep, getpid, getuid, arch_prctl, set_tid_address, uname, kill* |
| **#105** | socket, connect, sendto, bind |

\* **`kill`** required=false in fixture matrix (only harness trace).

### Blocking calls for #145 (fixture)

- **`poll`** 2500 ms DNS (`nslookup-fixture.strace:143`)
- **`nanosleep`** 1s (`sleep-1.strace:124`)
- **`wait4`** blocking reap (`pipe-grep.strace:168`)
- **`connect`** may block (`nslookup-fixture.strace:138`)
- **Not listed:** `accept` (harness only)

### Descriptor kinds for #147 (fixture)

Regular **file**, **pipe**, **connected UDP/TCP client** fds, **stdio**. **Not required:** TCP **listening** socket.

---

## Network / DNS (#105 / #104)

- **No kernel resolver** — `/etc/resolv.conf` parse + UDP only (`nslookup-fixture.strace:124-142`).
- **AAAA + A** queries sent; fixture DNS at **10.77.0.1** should answer **A → 10.77.0.50** and allow AAAA to fail without breaking wget/nslookup A path.
- **wget** HTTP bytes (harness reference only): `GET / HTTP/1.1\r\nHost: 127.0.0.1:18080\r\n…` (`wget-local-httpd.strace:253`).

---

## Decisions (cited)

### `sendfile` recommendation

BusyBox **1.37.0** `libbb/copyfd.c` inside `bb_full_fd_action` (lines **62–70** in upstream tarball): on `sendfile(...)`, if result `< 0`, sets **`sendfile_sz = 0`** and falls through to **`safe_read` / `full_write`** (lines **87–88**).

- **Phase B recommendation:** **(a)** pin **`CONFIG_FEATURE_USE_SENDFILE=n`** in trimmed `.config` (current build has **`CONFIG_FEATURE_USE_SENDFILE=y`** in `musl-minimal/.config:103`).
- Matrix: **`sendfile` `required = false`** until Phase B.

### Applet alias recommendation (#104 / #146)

1. **No applet `readlink`** in fixture traces for path resolution.
2. **`execve("/bin/grep", ["grep", …])`** via symlink (`grep-via-symlink.strace:156`) and **`execve("/bin/busybox", ["busybox", "grep", …])`** (`grep-via-busybox.strace:120`) — BusyBox selects applet from **`argv[0]` basename** after exec.
3. **#104 rootfs:** provide **`/bin/<applet>`** entries that resolve to busybox bytes **without symlink support** (hard links / manifest aliases). **#146** must preserve **`argv[0]`** as invoked name (`/bin/grep`).

### Shell `.config` knobs (committed `musl-minimal/.config`)

| Knob | Value | Implication |
|------|-------|-------------|
| `CONFIG_STATIC` | **y** | static ET_EXEC |
| `CONFIG_PIE` | **not set** | no PIE |
| `CONFIG_FEATURE_SH_STANDALONE` | **not set** | pipelines **exec** applets (`pipe-grep.strace:179`) |
| `CONFIG_FEATURE_SH_NOFORK` | **not set** | uses **fork** |
| `CONFIG_FEATURE_PREFER_APPLETS` | **not set** | |
| `CONFIG_FEATURE_USE_SENDFILE` | **y** (change in Phase B) | |
| `CONFIG_ASH_JOB_CONTROL` | **y** | not exercised in `sh -c` batch |
| `CONFIG_ASH_INTERNAL_GLOB` | **y** | |
| `CONFIG_FEATURE_SH_MATH` | **y** | not in command matrix |

Phase B must keep **STANDALONE/NOFORK/PREFER_APPLETS = n** so #102 child-exec proof stays valid.

### Minimum auxv set (#146) — musl **1.2.5** (Alpine 3.21)

From **`musl-1.2.5/src/env/__libc_start_main.c`**:

| AT_* | musl use | Required? |
|------|----------|-----------|
| **AT_PAGESZ** | `libc.page_size = aux[AT_PAGESZ]` (L32) | **REQUIRED** |
| **AT_HWCAP** | `__hwcap = aux[AT_HWCAP]` (L30) | **REQUIRED** (may be 0) |
| **AT_PHDR / AT_PHNUM / AT_PHENT** | **`__init_tls(aux)`** scans PHDR for TLS (`__init_tls.c` L90-93) | **REQUIRED** for static ET_EXEC |
| **AT_RANDOM** | **`__init_ssp((void*)aux[AT_RANDOM])`** (L40) | **REQUIRED** for normal canary |
| **AT_RANDOM absent/0** | **`__init_ssp`** uses fallback canary (`__stack_chk_fail.c` L7-10) | OPTIONAL degraded |
| **AT_SYSINFO** (vDSO) | `if (aux[AT_SYSINFO]) __sysinfo = …` (L31) | **OPTIONAL** (0 = tolerated) |
| **AT_UID/EUID/GID/EGID/AT_SECURE** | secure mode + `/dev/null` stdio fix (L42-57) | Emit consistent non-secure values for fixture |
| **AT_EXECFN** | progname fallback (L34-37) | OPTIONAL |

### Environment contract

| Test | Result | evidence |
|------|--------|----------|
| `env -i /bin/sh -c 'echo \| grep hello'` | Works; **`execve /bin/env`**, then **`execve /bin/sh` with NULL env** for inner script (`pipe-grep-env-i.strace:104-108`) | `:104-108`, `:192` |
| `env -i PATH=/bin /bin/sh -c '…'` | **`execve("/bin/grep")`** with **3 env vars** (`pipe-grep-path-only.strace:191`) | `:191` |
| **`PATH` required?** | For bare **`grep`** token, ash **`stat`s PATH dirs** then **`/bin/grep`** (`pipe-grep-env-i.strace:98-103`, `:153-179`) | Full **`PATH=/bin`** recommended |
| **`PWD`/`HOME`/`TERM`** | Not read in non-interactive traces | — |

### Ash startup files

No opens of **`/etc/profile`**, **`~/.profile`**, or **`$ENV`** in any fixture trace (grep across `fixtures/busybox/traces`).

### PWD / cwd contract (#101)

Ash calls **`getcwd("/", 4096)`** (`true.strace:93`) and **`stat("/work")` → ENOENT** when outer cwd path is invisible (`true.strace:92`) — in chroot **`/`** is authoritative; do not depend on host **`PWD`**.

---

## Explicitly NOT required (evidence)

| Item | evidence |
|------|----------|
| `futex`, `clone`, `vfork` | absent in fixture traces |
| `openat`, `newfstatat`, `statx` | absent |
| `pipe2` | absent (`pipe` only) |
| `getrandom`, `prlimit64` | absent |
| `listen`, `accept`, httpd | harness only |
| File-backed **`mmap`** | not in fixture slice |
| Applet **`readlink`** | not observed |

---

## Phase B follow-up

- Pin **`CONFIG_FEATURE_USE_SENDFILE=n`**; re-run traces with **10.77.0.1** DNS + TCP **4001**; capture **`recvfrom`/`read`** after DNS success; freeze binary SHA.
