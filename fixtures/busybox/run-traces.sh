#!/bin/bash
# M9 Phase A — run strace command matrix in a minimal rootfs (Linux evidence only).
set -euo pipefail
REPO="/work"
BB="${BUSYBOX_BIN:-/busybox}"
if [ ! -x "$BB" ] && [ -x "$REPO/fixtures/busybox/candidates/musl-minimal/busybox" ]; then
  BB="$REPO/fixtures/busybox/candidates/musl-minimal/busybox"
elif [ ! -x "$BB" ] && [ -x "$REPO/fixtures/busybox/candidates/alpine-static/busybox" ]; then
  BB="$REPO/fixtures/busybox/candidates/alpine-static/busybox"
fi
if [ ! -x "$BB" ]; then
  echo "Missing BusyBox binary at BUSYBOX_BIN=$BB" >&2
  exit 1
fi
TRACE_DIR="$REPO/fixtures/busybox/traces"
ROOTFS="/tmp/m9-rootfs"
TCP_PORT="${TCP_ECHO_PORT:-4001}"

mkdir -p "$TRACE_DIR"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/etc" "$ROOTFS/tmp" "$ROOTFS/dev" "$ROOTFS/proc" "$ROOTFS/sys" "$ROOTFS/var/www"
cp "$BB" "$ROOTFS/bin/busybox"
chmod +x "$ROOTFS/bin/busybox"
chroot "$ROOTFS" /bin/busybox --install -s /bin >/dev/null 2>&1 || {
  for app in sh ls cat mkdir echo grep uname nslookup wget sleep true httpd pwd printf kill; do
    ln -sf busybox "$ROOTFS/bin/$app"
  done
}
mknod -m 666 "$ROOTFS/dev/null" c 1 3 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/zero" c 1 5 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/random" c 1 8 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/urandom" c 1 9 2>/dev/null || true

echo 'm9-fixture' > "$ROOTFS/etc/hostname"
printf 'nameserver 10.77.0.1\n' > "$ROOTFS/etc/resolv.conf"
printf 'hello-from-httpd\n' > "$ROOTFS/var/www/index.html"

run_trace() {
  local name="$1"
  shift
  local out="$TRACE_DIR/${name}.strace"
  echo "=== trace $name: $* ==="
  chroot "$ROOTFS" /bin/sh -c "
    export PATH=/bin
    $*
  " 2>/dev/null &
  local pid=$!
  # Run via strace wrapping the chroot invocation from outside
  true
}

strace_one() {
  local name="$1"
  local cmd="$2"
  local out="$TRACE_DIR/${name}.strace"
  echo "=== $name ==="
  strace -f -tt -s 200 -o "$out" \
    chroot "$ROOTFS" /bin/sh -c "export PATH=/bin; $cmd" \
    || true
}

# Minimal baseline
strace_one "true" 'true'
strace_one "busybox-list" '/bin/busybox --list'

strace_one "pwd" "sh -c 'pwd'"
strace_one "ls-root" "sh -c 'ls /'"
strace_one "cat-hostname" "sh -c 'cat /etc/hostname'"
strace_one "tmp-file-io" "sh -c 'mkdir -p /tmp/demo; printf test > /tmp/demo/file; cat /tmp/demo/file'"
strace_one "pipe-grep" "sh -c 'echo hello | grep hello'"
strace_one "uname" "sh -c 'uname'"
strace_one "nslookup-fixture" "sh -c 'nslookup m7.fixture.test'"
strace_one "wget-fixture-fail" "sh -c 'wget -O - http://m7.fixture.test:${TCP_PORT}/'"
strace_one "sleep-1" "sh -c 'sleep 1'"
strace_one "exit-3" "sh -c 'exit 3'; /bin/busybox echo exit_code=\$?"

# Script execution path
cat > "$ROOTFS/tmp/script.sh" <<'SCRIPT'
pwd
ls /
cat /etc/hostname
mkdir -p /tmp/demo2
printf script > /tmp/demo2/file
cat /tmp/demo2/file
echo hi | grep hi
uname
sleep 0
exit 0
SCRIPT
chmod +x "$ROOTFS/tmp/script.sh"
strace_one "script-sh" "sh /tmp/script.sh"

# Local httpd success path for wget (background server in same strace tree)
HTTPD_OUT="$TRACE_DIR/wget-local-httpd.strace"
echo "=== wget-local-httpd ==="
(
  strace -f -tt -s 200 -o "$HTTPD_OUT" \
    chroot "$ROOTFS" /bin/sh -c "
      export PATH=/bin
      /bin/busybox httpd -f -p 18080 -h /var/www &
      HPID=\$!
      sleep 0.2
      wget -O - http://127.0.0.1:18080/
      kill \$HPID 2>/dev/null || true
    " || true
)

# Optional: local DNS with dnsmasq if available (timeout path already captured)
if command -v dnsmasq >/dev/null 2>&1; then
  strace_one "nslookup-local-dns" "sh -c 'nslookup m7.fixture.test 127.0.0.1'" || true
fi

# Startup-only trace: exec busybox sh -c true with focus on first process
strace_one "sh-c-minimal" "sh -c 'true'"

echo "Traces written to $TRACE_DIR"
ls -la "$TRACE_DIR"
