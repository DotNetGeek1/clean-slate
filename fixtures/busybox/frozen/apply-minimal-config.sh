#!/bin/sh
# Apply M9 frozen BusyBox 1.37.0 musl-static minimal applet set on top of allnoconfig.
set -eu
CFG="${1:-.config}"

make allnoconfig
test -f "$CFG"

append() {
  for line in "$@"; do
    key="${line%%=*}"
    if grep -q "^${key}=" "$CFG" 2>/dev/null; then
      sed -i "s|^${key}=.*|${line}|" "$CFG"
    elif grep -q "^# ${key} is not set" "$CFG" 2>/dev/null; then
      sed -i "s|^# ${key} is not set|${line}|" "$CFG"
    else
      echo "$line" >> "$CFG"
    fi
  done
}

unset_opt() {
  for key in "$@"; do
    if grep -q "^${key}=y" "$CFG" 2>/dev/null; then
      sed -i "s|^${key}=y|# ${key} is not set|" "$CFG"
    fi
  done
}

append \
  CONFIG_STATIC=y \
  CONFIG_FEATURE_USE_SENDFILE=n \
  CONFIG_MONOTONIC_SYSCALL=y \
  CONFIG_LFS=y \
  CONFIG_ASH=y \
  CONFIG_FEATURE_SH_IS_ASH=y \
  CONFIG_SH_IS_ASH=y \
  CONFIG_CAT=y \
  CONFIG_LS=y \
  CONFIG_MKDIR=y \
  CONFIG_ECHO=y \
  CONFIG_GREP=y \
  CONFIG_UNAME=y \
  CONFIG_NSLOOKUP=y \
  CONFIG_WGET=y \
  CONFIG_SLEEP=y \
  CONFIG_TRUE=y \
  CONFIG_PWD=y \
  CONFIG_PRINTF=y \
  CONFIG_ENV=y \
  CONFIG_BUSYBOX=y

# #102 child-exec proof: pipelines must fork+exec applets, not standalone/nofork.
unset_opt CONFIG_FEATURE_SH_STANDALONE CONFIG_FEATURE_SH_NOFORK CONFIG_FEATURE_PREFER_APPLETS
grep -q '^# CONFIG_FEATURE_SH_STANDALONE is not set' "$CFG" || echo '# CONFIG_FEATURE_SH_STANDALONE is not set' >> "$CFG"
grep -q '^# CONFIG_FEATURE_SH_NOFORK is not set' "$CFG" || echo '# CONFIG_FEATURE_SH_NOFORK is not set' >> "$CFG"
grep -q '^# CONFIG_FEATURE_PREFER_APPLETS is not set' "$CFG" || echo '# CONFIG_FEATURE_PREFER_APPLETS is not set' >> "$CFG"
grep -q '^# CONFIG_PIE is not set' "$CFG" || echo '# CONFIG_PIE is not set' >> "$CFG"

yes '' | make oldconfig >/dev/null
