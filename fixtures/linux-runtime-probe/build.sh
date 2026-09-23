#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker build -t cs-linux-runtime-probe .
docker run --rm -v "$PWD:/out" cs-linux-runtime-probe cp /probe/linux-runtime-probe-x86_64 /out/
sha256sum linux-runtime-probe-x86_64 | awk '{print $1}' > linux-runtime-probe-x86_64.sha256
