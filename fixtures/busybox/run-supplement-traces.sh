#!/bin/sh
# Supplemental strace evidence for M9 matrix revision (env -i, applet dispatch).
set -eu
REPO="/work"
TRACE_DIR="$REPO/fixtures/busybox/traces"
ROOTFS="/tmp/m9-supp-rootfs"
BB="/busybox"

apk add --no-cache strace >/dev/null 2>&1 || true
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/etc" "$ROOTFS/tmp" "$ROOTFS/dev"
cp "$BB" "$ROOTFS/bin/busybox"
chmod +x "$ROOTFS/bin/busybox"
chroot "$ROOTFS" /bin/busybox --install -s /bin >/dev/null
printf 'm9-fixture\n' > "$ROOTFS/etc/hostname"
printf 'nameserver 10.77.0.1\n' > "$ROOTFS/etc/resolv.conf"
mknod -m 666 "$ROOTFS/dev/null" c 1 3 2>/dev/null || true

strace_one() {
  name="$1"
  cmd="$2"
  strace -f -tt -s 200 -o "$TRACE_DIR/${name}.strace" \
    chroot "$ROOTFS" /bin/sh -c "$cmd" || true
}

# env -i tests
strace_one "pipe-grep-env-i" "env -i /bin/sh -c 'echo hello | grep hello'"
strace_one "pipe-grep-path-only" "env -i PATH=/bin /bin/sh -c 'echo hello | grep hello'"

# Applet dispatch: explicit busybox vs symlink path
strace_one "grep-via-busybox" "/bin/busybox grep hello <<EOF
hello
EOF"
strace_one "grep-via-symlink" "echo hello | /bin/grep hello"

echo "Supplement traces done"
