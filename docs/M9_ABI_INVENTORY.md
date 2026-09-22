# M9 BusyBox ABI inventory (Phase A — #100)

Draft compatibility contract from **Linux strace evidence only** (Docker Desktop linux/amd64, `strace -f -tt -s 200`). Phase B freezes the binary; this document does **not** freeze the artifact.

Trace methodology: minimal chroot rootfs (`fixtures/busybox/run-traces.sh`) with `/bin/busybox` + applet symlinks, `/etc/hostname`, `/etc/resolv.conf` → `nameserver 10.77.0.1`, writable `/tmp`, device nodes for `/dev/null`. Outer `chroot(8)` from Alpine is present in raw traces; syscall rows below cite the **BusyBox slice** (lines after `execve("/bin/...")` inside the rootfs). See `fixtures/busybox/syscall-matrix.toml` for the machine-readable matrix (#108 guardrail).

---

## Candidate comparison

| | **musl-minimal** (recommended) | **alpine-static** (package) |
|---|----------------|----------------|
| Version | BusyBox **1.37.0** (built 2026-09-22) | **1.37.0-r14** (`busybox-static` apk) |
| Toolchain | `alpine:3.21` + `musl-gcc`, `CONFIG_STATIC=y`, `-no-pie` | Alpine apk build (opaque) |
| SHA-256 | `2877cefa6ac0b1c755c477845b646e0733e5ab4501cdfd3a048974abcbf4164c` | `aa1e1f4214ec2489ed373f3c5b92b7a7c665821a1decaa9685e5363886a93c7c` |
| Size | 1,185,688 bytes | 1,033,216 bytes (apk installed size ~1009 KiB) |
| `e_type` | **ET_EXEC** | **ET_DYN** (PIE) |
| Entry | `0x41798d` | `0x6ed1` |
| PT_INTERP | **Absent** | **Present** (`/lib/ld-musl-x86_64.so.1`) |
| PT_LOAD (musl-minimal) | 4 segments @ **0x400000** region: R@0x400000, RX@0x401000, R@0x4e9000, RW@0x521e30 | Low PIE mappings + dynamic |
| PT_TLS | Absent | Absent in both observed |
| Dynamic | Static musl in binary | `.dynamic`, `.interp`, RELRO |
| Policy fit | Matches M9 preference: static ET_EXEC, no loader, classic **0x400000** link | Fails ET_EXEC / no-INTERP goals despite package name |

**Recommendation (not frozen):** **`musl-minimal`** — reproducible Dockerfile + committed `.config`, true static **ET_EXEC** at `0x400000`, no dynamic loader. Alpine `busybox-static` is useful as a negative comparison (PIE + interpreter) but is a poor M9 load target for #142/#146.

Artifacts: `fixtures/busybox/candidates/{musl-minimal,alpine-static}/` (`.config`, build recipe, `readelf.txt`, `sha256`, `applets.txt`, `toolchain.txt`).

---

## Process primitive

Ash for `sh -c` / scripts uses **`fork(2)` (nr 57)** — **not** `vfork` or `clone` in observed traces.

- Example: `pipe-grep.strace:122` — `fork()` before `execve("/bin/grep", ...)`.
- `wait4(-1, …, WNOHANG, NULL)` reaps children (`exit-3.strace:139` captures exit status **3**).
- No `futex`, `clone`, or `vfork` in any BusyBox slice trace (single-threaded applets; job control not exercised).

---

## Startup / TLS / memory (musl + BusyBox)

Observed on every applet after `execve("/bin/sh")` or busybox re-exec (e.g. `true.strace:79–88`):

| Step | Syscall | Evidence |
|------|---------|----------|
| TLS | `arch_prctl(ARCH_SET_FS, …)` | `true.strace:79` |
| Thread pointer | `set_tid_address(0x523bf8)` | `true.strace:80` |
| Heap | `brk` + guard `mmap(PROT_NONE)` | `true.strace:82–84` |
| Signals (non-interactive ash) | `rt_sigprocmask`, `rt_sigaction` (SIGCHLD, SIGINT, …) | `true.strace:89–97` |

**Auxv:** strace does not show auxv reads. For #146/#92, loader must still supply Linux musl expectations: at minimum **`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_PAGESZ`, `AT_ENTRY`**, plus M9 **`AT_RANDOM`** (and likely `AT_SECURE` when appropriate). musl static startup observed here does **not** call `getrandom` or `prlimit64` in these traces (explicitly absent — see “NOT required”).

---

## Syscall inventory by owning lane

Blocking column: **yes** = observed sleep/poll/wait/connect/read blocking path; **no** = returns immediately in traces. Errno policy: return Linux negative errno in `RAX`; paths below note required failures.

### #146 — exec / image

| nr | name | flags/args observed | triggers | success | errno cases | blocking? | resource | evidence |
|----|------|---------------------|----------|---------|-------------|-----------|----------|----------|
| 59 | execve | path `/bin/<applet>`, argv, envp | every applet via ash | new program runs | `ENOENT`, `EACCES`, `ENOEXEC` | no | path bytes | `cat-hostname.strace:120` |

### #147 — fd core

| nr | name | flags/args observed | triggers | success | errno cases | blocking? | resource | evidence |
|----|------|---------------------|----------|---------|-------------|-----------|----------|----------|
| 0 | read | fd, buf, count; HTTP body loop | wget, nslookup resolv read | data / 0 EOF | `EBADF`, `EFAULT` | yes (TCP) | file/socket | `wget-local-httpd.strace:229` |
| 1 | write | stdout/stderr; DNS wire on connected UDP | all applets | full count / short write | `EBADF`, `EPIPE` | no | file/socket | `nslookup-fixture.strace:141` |
| 2 | open | `O_RDONLY\|O_LARGEFILE`, paths | `cat`, nslookup | fd ≥3 | `ENOENT` | no | file | `cat-hostname.strace:124` |
| 3 | close | fd | all | 0 | `EBADF` | no | any | `cat-hostname.strace:127` |
| 4 | stat | path | ash before exec | 0 | `ENOENT` | no | path | `cat-hostname.strace:119` |
| 8 | lseek | `SEEK_CUR` | wget progress | offset | `ESPIPE` on pipe | no | file | `wget-local-httpd.strace:296` |
| 9 | mmap | `MAP_PRIVATE\|MAP_ANONYMOUS`, heap | startup | mapped VA | `ENOMEM` | no | vm | `true.strace:84` |
| 20 | writev | iov pairs | ls, pwd, grep | sum iov | `EBADF` | no | file | `pwd.strace:120` |
| 33 | dup2 | pipe → stdout, `1→2` | pipes, httpd | new fd | `EBADF` | no | fd table | `pipe-grep.strace:247` |
| 40 | sendfile | out_fd, in_fd, count | cat, file→stdout | bytes copied | `EINVAL` | no | file pair | `cat-hostname.strace:125` |
| 72 | fcntl | `F_SETFL` O_NONBLOCK on UDP; `F_GETFL` | nslookup, wget DNS | 0 | `EBADF` | no | fd | `nslookup-fixture.strace:139` |

### #101 — filesystem / paths

| nr | name | flags/args observed | triggers | success | errno cases | blocking? | resource | evidence |
|----|------|---------------------|----------|---------|-------------|-----------|----------|----------|
| 6 | lstat | directory entries | `ls /` | 0 | `ENOENT` | no | path | `ls-root.strace:136` |
| 83 | mkdir | mode 0777, `/tmp/...` | `mkdir -p` | 0 / exists ok | `EEXIST` | no | path | `tmp-file-io.strace:143` |
| 217 | getdents64 | buf 2048 | `ls` | entries then 0 | `ENOTDIR` | no | dir fd | `ls-root.strace:135` |

Paths are **UTF-8 byte strings** in traces (`/etc/hostname`, `/tmp/demo/file`); no non-UTF-8 names observed.

### #102 — process / pipe

| nr | name | flags/args observed | triggers | success | errno cases | blocking? | resource | evidence |
|----|------|---------------------|----------|---------|-------------|-----------|----------|----------|
| 22 | pipe | fd pair | `\| grep` | 0 | `EMFILE` | no | pipe | `pipe-grep.strace:119` |
| 57 | fork | — | `sh -c` pipelines, subshells | child pid | — | no | process | `pipe-grep.strace:122` |
| 61 | wait4 | `-1`, `WNOHANG` / blocking | parent ash | status / 0 / ECHILD | `ECHILD` | yes (blocking wait variant) | child | `exit-3.strace:136` |
| 110 | getppid | — | startup | ppid | — | no | — | `true.strace:91` |

### #103 — runtime / time / poll / ioctl

| nr | name | flags/args observed | triggers | success | errno cases | blocking? | resource | evidence |
|----|------|---------------------|----------|---------|-------------|-----------|----------|----------|
| 7 | poll | fds, timeout ms | DNS timeout | 0 timeout | — | **yes** | fd set | `nslookup-fixture.strace:143` |
| 11 | munmap | heap scratch | nslookup | 0 | — | no | vm | `nslookup-fixture.strace:133` |
| 12 | brk | heap growth | startup | new break | `ENOMEM` | no | heap | `true.strace:82` |
| 13–14 | rt_sigaction / rt_sigprocmask | SIGCHLD, SIGINT, … | ash | 0 | — | no | signals | `true.strace:89–90` |
| 16 | ioctl | **`TIOCGWINSZ`** on fd 0/1 | many applets | **-1 ENOTTY** (non-tty batch) | `ENOTTY` ok | no | tty (optional) | `ls-root.strace:124` |
| 35 | nanosleep | `{tv_sec=1}` | `sleep 1` | 0 | `EINTR` | **yes** | clock | `sleep-1.strace:124` |
| 39 | getpid | — | startup | pid | — | no | — | `true.strace:87` |
| 62 | kill | SIGTERM | wget/httpd teardown | 0 | `ESRCH` | no | process | `wget-local-httpd.strace:314` |
| 63 | uname | `struct utsname` | `uname`, nslookup | 0 | — | no | — | `uname.strace:124` |
| 79 | getcwd | buf 4096 | ash | path | — | no | — | `true.strace:93` |
| 80 | chdir | `/` | httpd `-h` | 0 | `ENOENT` | no | — | `wget-local-httpd.strace:164` |
| 102 | getuid | — | startup | 0 (root in container) | — | no | — | `true.strace:81` |
| 158 | arch_prctl | `ARCH_SET_FS` | musl TLS | 0 | `EPERM` | no | tls | `true.strace:79` |
| 218 | set_tid_address | &tid field | musl | tid | — | no | tls | `true.strace:80` |
| 231 | exit_group | status & 0xff | all applets | never returns | — | no | process | `exit-3.strace:134` (status **3**) |

### #105 — sockets (no custom “resolve” syscall)

| nr | name | flags/args observed | triggers | success | errno cases | blocking? | resource | evidence |
|----|------|---------------------|----------|---------|-------------|-----------|----------|----------|
| 41 | socket | `AF_INET`/`AF_INET6`, `SOCK_DGRAM`/`STREAM` | nslookup, wget, httpd | fd | `EAFNOSUPPORT` | no | socket | `nslookup-fixture.strace:136` |
| 42 | connect | UDP → `10.77.0.1:53`; TCP → `127.0.0.1:18080` | nslookup; wget ok path | 0 | timeout path | **yes** (TCP) | socket | `nslookup-fixture.strace:138` |
| 43 | accept | backlog 9 | httpd | connected fd | `EAGAIN` | **yes** | listening fd | `wget-local-httpd.strace:174` |
| 44 | sendto | DNS wire, `MSG_NOSIGNAL` | wget DNS (libc path) | 33 | — | no | UDP | `wget-fixture-fail.strace:139` |
| 49 | bind | ephemeral / port 18080 | DNS, httpd | 0 | `EADDRINUSE` | no | socket | `nslookup-fixture.strace:137` |
| 50 | listen | backlog 9 | httpd | 0 | — | no | socket | `wget-local-httpd.strace:169` |

**Note:** BusyBox `nslookup` uses **connected UDP** + **`write(2)`** for queries (`nslookup-fixture.strace:141–142`); `wget` uses **`sendto`** to `10.77.0.1:53` (`wget-fixture-fail.strace:139`). Both are socket fd paths for #105/#147 — no kernel DNS syscall.

---

## Blocking calls for #145

Observed blocking/wait primitives (must not spin forever; honour timeouts):

- `poll` — DNS wait **2500 ms** (`nslookup-fixture.strace:143–146`).
- `nanosleep` — `sleep 1` (`sleep-1.strace:124`).
- `wait4` — child reap (`exit-3.strace:136`; also `WNOHANG` polls).
- `connect` / `read` — TCP wget (`wget-local-httpd.strace:212`, `229`).
- `accept` — httpd (`wget-local-httpd.strace:174`).

---

## Descriptor kinds / readiness for #147

| Kind | syscalls | example |
|------|----------|---------|
| regular file | `open`, `read`, `sendfile`, `close` | `/etc/hostname` |
| directory | `open` + `getdents64` | `ls /` |
| pipe | `pipe`, `dup2`, `read`/`write` | `echo \| grep` |
| connected UDP | `socket`, `bind`, `connect`, `write`, `poll` | DNS |
| TCP client | `socket`, `connect`, `writev`, `read` | wget |
| TCP listening | `socket`, `bind`, `listen`, `accept`, `read`, `write` | httpd |
| stdio | `write`/`writev` to 1/2 | all |

`fcntl` **O_NONBLOCK** on DNS socket (`nslookup-fixture.strace:140`) + `poll` for readiness.

---

## Rootfs / namespace requirements for #104 / #101

Minimal root observed:

- `/bin/busybox` + applet symlinks (`busybox --install -s /bin`).
- `/etc/hostname` (read by `cat`).
- `/etc/resolv.conf` — **line-oriented** `nameserver 10.77.0.1\n` parsed by nslookup (`nslookup-fixture.strace:129`).
- `/tmp` writable for `mkdir`, scripts, temp files.
- `/dev/null` (and basic char devs) for redirects / httpd.
- Single-user UID **0** in container traces (`getuid()` → 0).

No mount namespace, no `/proc` reliance in matrix commands (proc dir listed but not required).

---

## Network behaviour as Linux performs it (#105)

**DNS (UDP, userspace):**

1. Read `/etc/resolv.conf` (`open`/`read`, `nslookup-fixture.strace:124–129`).
2. `socket(AF_INET, SOCK_DGRAM)` → `bind` ephemeral → `connect` to **`10.77.0.1:53`**.
3. Send A/AAAA-style wire queries (binary in `write`/`sendto` traces).
4. `poll` with **2.5 s** timeout; on failure print `;; connection timed out; no servers could be reached` (`nslookup-fixture.strace:149`) and `exit_group(1)`.

**wget fixture URL** `http://m7.fixture.test:4001/` (M7 `TCP_ECHO_PORT`): without reachable DNS, **`wget: bad address`** after UDP timeout (`wget-fixture-fail.strace:146`) — still documents DNS **sendto** + **poll** sequence.

**HTTP success path** (local `busybox httpd -f -p 18080`):

- Client request bytes: `GET / HTTP/1.1\r\nHost: 127.0.0.1:18080\r\nUser-Agent: Wget\r\nConnection: close\r\n\r\n` (`wget-local-httpd.strace:253`).
- Response: `HTTP/1.1 200 OK` + body; body via **`sendfile`** to socket (`wget-local-httpd.strace:260–266`); client **`read`** loop + stdout (`wget-local-httpd.strace:229`, `285`).

Hermetic lab target (Clean-Slate): resolver **10.77.0.1**, name **`m7.fixture.test`**, TCP echo port **4001** per `network/src/fixture.rs` (Docker traces use unreachable DNS by design).

---

## Unsupported behaviour / deterministic errno policy

- Unknown syscalls: **`-ENOSYS`**, process continues (M8 rule) unless/until M9 lane implements handler.
- Missing files: **`ENOENT`** (e.g. ash `stat("/work")` → ENOENT in chroot — `true.strace:92`).
- Non-tty batch: **`ioctl(TIOCGWINSZ)` → `ENOTTY`** — treat as success path for `sh -c` / scripts (not interactive job control).
- DNS unreachable: timed **`poll` → 0**, user-visible error, non-zero exit — do not hang kernel.
- Do **not** invent a `resolve()` syscall; mirror socket + resolv.conf behaviour above.

---

## Explicitly NOT required (evidence)

| Item | Evidence |
|------|----------|
| `futex` | absent in all `fixtures/busybox/traces/*.strace` |
| `vfork` / `clone` / `clone3` | absent; only `fork` |
| `getrandom`, `prlimit64` | absent in BusyBox slices |
| `openat` / `newfstatat` / `statx` | absent; legacy `open`/`stat`/`lstat`/`getdents64` used |
| `pipe2` | absent; `pipe` only |
| Dynamic loader / `PT_INTERP` | absent in **musl-minimal**; present in alpine-static (disqualified) |
| Full job-control tty driver | `TIOCGWINSZ` fails ENOTTY; no `tcsetpgrp` |
| Multithreaded pthread startup | no futex; single-threaded applets |

---

## Command matrix results

| Command | Result | Trace |
|---------|--------|-------|
| `sh -c 'true'` | exit 0 | `true.strace` |
| `busybox --list` | listed applets | `busybox-list.strace` |
| `sh -c 'pwd'` | `/` | `pwd.strace` |
| `sh -c 'ls /'` | dir listing | `ls-root.strace` |
| `sh -c 'cat /etc/hostname'` | `m9-fixture` | `cat-hostname.strace` |
| tmp file create/cat | `test` | `tmp-file-io.strace` |
| `echo hello \| grep hello` | `hello` | `pipe-grep.strace` |
| `sh -c 'uname'` | `Linux` | `uname.strace` |
| `nslookup m7.fixture.test` | timeout (no DNS in Docker) | `nslookup-fixture.strace` |
| `wget … m7.fixture.test:4001/` | bad address / DNS fail | `wget-fixture-fail.strace` |
| `wget` → local httpd | **success** body | `wget-local-httpd.strace` |
| `sleep 1` | ~1s | `sleep-1.strace` |
| `exit 3` / `$?` | status 3 | `exit-3.strace` |
| `sh /tmp/script.sh` | combined paths | `script-sh.strace` |

---

## Phase B follow-up

- Freeze **musl-minimal** binary + SHA-256 in repo after orchestrator sign-off.
- Trim `.config` to M9-minimal applets (current build still carries full defconfig surface from `make defconfig` + static).
- Re-run traces against hermetic DNS peer (10.77.0.1) and M7 TCP echo **4001** when host peer available.
- Align #108 matrix test with `syscall-matrix.toml`.

## Lane dependencies

- **#142 / #146:** ET_EXEC @ **0x400000**, PT_LOAD table from `musl-minimal/readelf.txt`; auxv emission including `AT_RANDOM`.
- **#147 / #101:** fd kinds above; `sendfile` zero-copy path optional optimization.
- **#102:** `fork`+`wait4`+`pipe` only for M9 script/pipeline scope.
- **#103:** `poll`, `nanosleep`, `ioctl(ENOTTY)`, TLS syscalls at startup.
- **#105:** UDP DNS + TCP HTTP byte-exact behaviour; no resolver syscall.
- **#104:** rootfs layout + `/etc/resolv.conf` contract.
