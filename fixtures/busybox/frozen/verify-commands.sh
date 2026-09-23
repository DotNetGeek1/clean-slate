#!/bin/sh
set -eu
ROOTFS=/tmp/m9-verify-rootfs
BB="${BUSYBOX_BIN:-/busybox}"
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS/bin" "$ROOTFS/etc" "$ROOTFS/tmp"
cp "$BB" "$ROOTFS/bin/busybox"
for a in sh ls cat mkdir echo grep uname nslookup wget sleep true pwd printf env; do
  ln -sf busybox "$ROOTFS/bin/$a"
done
echo m9-fixture > "$ROOTFS/etc/hostname"
printf 'nameserver 10.77.0.1\n' > "$ROOTFS/etc/resolv.conf"
ip link set lo up
ip addr add 10.77.0.1/32 dev lo 2>/dev/null || true
ip addr add 10.77.0.50/32 dev lo 2>/dev/null || true
python3 /work/fixtures/busybox/frozen/fixture-responder.py &
sleep 0.3
run() {
  name="$1"
  cmd="$2"
  printf 'CMD %s\n' "$name"
  chroot "$ROOTFS" /bin/sh -c "export PATH=/bin; $cmd"
  printf 'EXIT %s\n' "$?"
}

run true true
run pwd "pwd"
run ls-root "ls /"
run cat-hostname "cat /etc/hostname"
run tmp-file-io "mkdir -p /tmp/demo; printf test > /tmp/demo/file; cat /tmp/demo/file"
run pipe-grep "echo hello | grep hello"
run uname "uname"
run sleep-0 "sleep 0"
run wget-fixture-http "wget -qO- http://m7.fixture.test:4001/"
run nslookup-fixture "nslookup m7.fixture.test"
