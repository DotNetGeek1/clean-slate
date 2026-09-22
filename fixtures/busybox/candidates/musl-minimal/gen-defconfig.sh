#!/bin/bash
# Generate defconfig with applets required for M9 command matrix (#100).
set -euo pipefail
VER="${1:-1.37.0}"
wget -q "https://busybox.net/downloads/busybox-${VER}.tar.bz2"
tar xf "busybox-${VER}.tar.bz2"
cd "busybox-${VER}"
make defconfig
# Enable static, disable PIE where applicable, enable needed applets.
sed -i \
  -e 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' \
  -e 's/# CONFIG_FEATURE_SH_IS_ASH is not set/CONFIG_FEATURE_SH_IS_ASH=y/' \
  -e 's/# CONFIG_ASH is not set/CONFIG_ASH=y/' \
  -e 's/# CONFIG_LS is not set/CONFIG_LS=y/' \
  -e 's/# CONFIG_CAT is not set/CONFIG_CAT=y/' \
  -e 's/# CONFIG_MKDIR is not set/CONFIG_MKDIR=y/' \
  -e 's/# CONFIG_ECHO is not set/CONFIG_ECHO=y/' \
  -e 's/# CONFIG_GREP is not set/CONFIG_GREP=y/' \
  -e 's/# CONFIG_UNAME is not set/CONFIG_UNAME=y/' \
  -e 's/# CONFIG_NSLOOKUP is not set/CONFIG_NSLOOKUP=y/' \
  -e 's/# CONFIG_WGET is not set/CONFIG_WGET=y/' \
  -e 's/# CONFIG_SLEEP is not set/CONFIG_SLEEP=y/' \
  -e 's/# CONFIG_TRUE is not set/CONFIG_TRUE=y/' \
  -e 's/# CONFIG_HTTPD is not set/CONFIG_HTTPD=y/' \
  -e 's/# CONFIG_PWD is not set/CONFIG_PWD=y/' \
  -e 's/# CONFIG_PRINTF is not set/CONFIG_PRINTF=y/' \
  -e 's/# CONFIG_PIPE_PROGRESS is not set//' \
  .config
# Fallback: use scripts for any still-disabled
for opt in CONFIG_STATIC CONFIG_ASH CONFIG_FEATURE_SH_IS_ASH CONFIG_LS CONFIG_CAT \
  CONFIG_MKDIR CONFIG_ECHO CONFIG_GREP CONFIG_UNAME CONFIG_NSLOOKUP CONFIG_WGET \
  CONFIG_SLEEP CONFIG_TRUE CONFIG_HTTPD CONFIG_PWD CONFIG_PRINTF; do
  grep -q "^${opt}=y" .config || echo "${opt}=y" >> .config
done
grep -q '^CONFIG_PIE=' .config && sed -i 's/^CONFIG_PIE=.*/# CONFIG_PIE is not set/' .config || echo '# CONFIG_PIE is not set' >> .config
cp .config /out/.config
