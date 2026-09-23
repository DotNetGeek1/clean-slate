# Frozen BusyBox `.config` changes (Phase B)

Base: **`make allnoconfig`** on BusyBox **1.37.0**, then `apply-minimal-config.sh` (musl **1.2.5-r11** / Alpine **3.21** `build-base`, `CONFIG_STATIC=y`, no PIE). Compared to Phase A **`candidates/musl-minimal`** (desktop defconfig + applet enables).

## Policy knobs (unchanged intent vs Phase A)

| Line | Value | Rationale |
|------|-------|-----------|
| `CONFIG_STATIC=y` | y | Static **ET_EXEC** at conventional low VA; no `PT_INTERP` / dynamic loader (#142 / #146). |
| `# CONFIG_PIE is not set` | off | Non-PIE ET_EXEC link region ~`0x400000`. |
| `# CONFIG_FEATURE_SH_STANDALONE is not set` | off | Pipelines must **`fork` + `execve("/bin/grep")`** (#102 evidence). |
| `# CONFIG_FEATURE_SH_NOFORK is not set` | off | Same as above. |
| `# CONFIG_FEATURE_PREFER_APPLETS is not set` | off | Same as above. |
| `CONFIG_FEATURE_USE_SENDFILE=n` | **n** | Phase A decision: avoid `sendfile` syscall; BusyBox `copyfd.c` uses `read`/`write` fallback. |
| `CONFIG_MONOTONIC_SYSCALL=y` | y | `sleep` / `nanosleep` monotonic path (#103). |
| `CONFIG_LFS=y` | y | Large file `open` / `O_LARGEFILE` flags in traces (#101). |

## Enabled applets only (fixture closure)

| Line | Rationale |
|------|-----------|
| `CONFIG_BUSYBOX=y` | Multi-call binary + `--list` command. |
| `CONFIG_ASH=y`, `CONFIG_FEATURE_SH_IS_ASH=y`, `CONFIG_SH_IS_ASH=y` | `/bin/sh` shell startup matrix. |
| `CONFIG_CAT`, `CONFIG_LS`, `CONFIG_MKDIR`, `CONFIG_ECHO`, `CONFIG_GREP`, `CONFIG_UNAME`, `CONFIG_NSLOOKUP`, `CONFIG_WGET`, `CONFIG_SLEEP`, `CONFIG_TRUE`, `CONFIG_PWD`, `CONFIG_PRINTF`, `CONFIG_ENV` | Exact frozen command / supplement traces only. |

## Removed vs `musl-minimal` (representative)

| Change | Rationale |
|--------|-----------|
| `CONFIG_DESKTOP=y` → **absent** (`allnoconfig`) | Drops hundreds of applets and optional syscalls not in the M9 matrix (`clone`, `futex`, `epoll`, extra `socket` servers, etc.). |
| `CONFIG_HTTPD=y` → **not set** | HTTP acceptance uses **fixture TCP** on `10.77.0.50:4001`, not in-process `httpd` (Phase A `wget-local-httpd` was harness-only). |
| `CONFIG_FEATURE_USE_SENDFILE=y` → **`n`** | See policy table above. |
| All other Phase A applets (archival, coreutils, networking daemons, …) → **not set** | Smaller binary (~207 KiB vs ~1.16 MiB) and tighter syscall surface. |

Full generated config: `fixtures/busybox/frozen/.config` (produced by `frozen/build.sh` / Docker build).
