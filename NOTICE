# Third-party notices

The Rust code in this repository is under the licence in `LICENSE-MIT` and
`LICENSE-APACHE`. The material below is not.

## BusyBox 1.37.0

`fixtures/busybox/frozen/busybox` is a committed executable (206,712 bytes,
SHA-256 `7ba56acec9fb89deace4ebfab6f4baaa8d1b778754b8f7ae3dbd7cf7990fe380`).
Its strings identify it as `BusyBox v1.37.0 (2026-09-23 09:18:28 UTC)` and say
`Licensed under GPLv2`. The same timestamp is in the header of
`fixtures/busybox/frozen/.config` (`Busybox version: 1.37.0`).

The licence text shipped with upstream BusyBox 1.37.0 is
`fixtures/busybox/frozen/COPYING`. That file is `busybox-1.37.0/LICENSE` from
the upstream tarball. It states that version 2 of the GNU General Public
License is the only version under which this BusyBox may be distributed, and
it includes the GPL-2.0 text. BusyBox is not covered by the repository's
`MIT OR Apache-2.0` licence.

Corresponding source for this version:

https://busybox.net/downloads/busybox-1.37.0.tar.bz2

SHA-256 `3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4`,
which is the pin in `fixtures/busybox/frozen/Dockerfile` and
`fixtures/busybox/frozen/toolchain.txt`. That hash matches the file at the URL
above.

`fixtures/busybox/frozen/.config` is the configuration the committed build
copies out of the image (`Dockerfile` copies `/busybox.config` to
`/export/.config`, and `build.sh` copies that to `.config`). It is produced
from `make allnoconfig` plus `fixtures/busybox/frozen/apply-minimal-config.sh`.
`CONFIG_STATIC=y` is set and `CONFIG_PIE` is not.

The committed `Dockerfile` and `build.sh` download that tarball and do not
apply source patches. This repository contains no BusyBox patch file that
those scripts run. The binary was not rebuilt as part of adding this notice,
so an uncommitted local patch applied before the binary was committed cannot
be ruled out from these files alone. The binary's version banner and the
`.config` header carry the same timestamp.

`fixtures/busybox/frozen/readelf.txt` shows an `ET_EXEC` x86-64 binary with no
`PT_INTERP` program header. `fixtures/busybox/frozen/file.txt` says it is
statically linked and stripped.

The committed build recipe implies that a binary it produces contains musl.
`fixtures/busybox/frozen/Dockerfile` builds in `alpine:3.21` pinned by digest
`sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507`.
Its first line calls the result "musl-static". It installs `build-base` and
links with `LDFLAGS="-static -no-pie"`. Alpine's C library is musl, so a
binary produced by that Dockerfile contains musl.

What was not verified: the committed `busybox` file was not rebuilt from that
Dockerfile, so these bytes are not shown to be that recipe's output. The
string `musl=1.2.5-r11 (Alpine 3.21 build-base)` written by the Dockerfile
`echo` into `toolchain.txt` is a literal, not a query of the Alpine package
database, so the exact musl package revision is not established.

`fixtures/busybox/frozen/COPYRIGHT.musl` is the `COPYRIGHT` file from the
upstream musl 1.2.5 release (`musl-1.2.5/COPYRIGHT` inside
https://musl.libc.org/releases/musl-1.2.5.tar.gz), committed unchanged. Musl
as a whole is licensed under the MIT licence stated in that file.

The committed binary contains the bytes `No error information` once. That is
musl's message for an unknown errno. The hit is evidence that musl text is
present. It is not proof that the binary is the Dockerfile's output, and it
does not identify the Alpine package revision.

`fixtures/busybox/candidates/` does not contain a committed BusyBox binary
(`fixtures/busybox/candidates/.gitignore`).

## Spleen 8x16 2.1.0

`raster/fonts/spleen-8x16.bdf` identifies itself as Spleen 8x16 2.1.0,
copyright 2018-2024 Frederic Cambus, BSD-2-Clause, SPDX `BSD-2-Clause`.
The licence text in the repository is `raster/fonts/LICENSE.spleen`.
`raster/src/font/spleen_8x16.rs` is generated from that BDF
(`cargo xtask gen-raster-font`). The BDF's SHA-256 is
`b2b05484ba4380c9c6854cc57637235a9fb039c65b5ba38a65289540f8fab7dc`,
which is the hash recorded in the generated file. No upstream release URL is
recorded in the BDF beyond https://www.cambus.net/.
