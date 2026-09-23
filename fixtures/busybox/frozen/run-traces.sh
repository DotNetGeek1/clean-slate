#!/bin/bash
# M9 Phase B — hermetic strace matrix (--network none + in-container fixture DNS/HTTP).
set -euo pipefail
REPO="/work"
BB="${BUSYBOX_BIN:-/busybox}"
TRACE_DIR="$REPO/fixtures/busybox/frozen/traces"
ROOTFS="/tmp/m9-frozen-rootfs"
TCP_PORT="${TCP_FIXTURE_PORT:-4001}"

mkdir -p "$TRACE_DIR"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/etc" "$ROOTFS/tmp" "$ROOTFS/dev"
cp "$BB" "$ROOTFS/bin/busybox"
chmod +x "$ROOTFS/bin/busybox"
for app in sh ls cat mkdir echo grep uname nslookup wget sleep true pwd printf env; do
  ln -sf busybox "$ROOTFS/bin/$app"
done
mknod -m 666 "$ROOTFS/dev/null" c 1 3 2>/dev/null || true
mknod -m 666 "$ROOTFS/dev/zero" c 1 5 2>/dev/null || true
echo 'm9-fixture' > "$ROOTFS/etc/hostname"
printf 'nameserver 10.77.0.1\n' > "$ROOTFS/etc/resolv.conf"

# Fixture addresses on loopback (requires CAP_NET_ADMIN; no external network).
ip link set lo up
ip addr add 10.77.0.1/32 dev lo
ip addr add 10.77.0.50/32 dev lo

python3 "$REPO/fixtures/busybox/frozen/fixture-responder.py" &
FIX_PID=$!
sleep 0.2

strace_one() {
  local name="$1"
  local cmd="$2"
  local out="$TRACE_DIR/${name}.strace"
  echo "=== $name ==="
  strace -f -ttt -yy -s 256 -o "$out" \
    chroot "$ROOTFS" /bin/sh -c "export PATH=/bin; $cmd" \
    || true
}

strace_one "true" 'true'
strace_one "busybox-list" '/bin/busybox --list'
strace_one "pwd" "sh -c 'pwd'"
strace_one "ls-root" "sh -c 'ls /'"
strace_one "cat-hostname" "sh -c 'cat /etc/hostname'"
strace_one "tmp-file-io" "sh -c 'mkdir -p /tmp/demo; printf test > /tmp/demo/file; cat /tmp/demo/file'"
strace_one "pipe-grep" "sh -c 'echo hello | grep hello'"
strace_one "uname" "sh -c 'uname'"
strace_one "nslookup-fixture" "sh -c 'nslookup m7.fixture.test'"
strace_one "wget-fixture-http" "sh -c 'wget -O - http://m7.fixture.test:${TCP_PORT}/'"
strace_one "sleep-0" "sh -c 'sleep 0'"
strace_one "exit-3" "sh -c 'exit 3'; /bin/busybox echo exit_code=\$?"

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
strace_one "sh-c-minimal" "sh -c 'true'"

# Supplemental argv/env/exec dispatch evidence
strace_one "pipe-grep-env-i" "env -i /bin/sh -c 'echo hello | grep hello'"
strace_one "pipe-grep-path-only" "env -i PATH=/bin /bin/sh -c 'echo hello | grep hello'"
strace_one "grep-via-busybox" "/bin/busybox grep hello <<EOF
hello
EOF"
strace_one "grep-via-symlink" "echo hello | /bin/grep hello"

kill "$FIX_PID" 2>/dev/null || true
echo "Frozen traces in $TRACE_DIR"
ls -la "$TRACE_DIR"
