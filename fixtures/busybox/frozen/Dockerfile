# M9 Phase B — reproducible frozen musl-static BusyBox 1.37.0 (ET_EXEC @ ~0x400000).
FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS build
RUN apk add --no-cache build-base wget perl linux-headers binutils coreutils
ARG BUSYBOX_VERSION=1.37.0
ARG BUSYBOX_TARBALL_SHA256=3311dff32e746499f4df0d5df04d7eb396382d7e108bb9250e7b519b837043a4
WORKDIR /src
RUN wget -q "https://busybox.net/downloads/busybox-${BUSYBOX_VERSION}.tar.bz2" -O busybox.tar.bz2 \
  && echo "${BUSYBOX_TARBALL_SHA256}  busybox.tar.bz2" | sha256sum -c - \
  && tar xf busybox.tar.bz2
WORKDIR /src/busybox-${BUSYBOX_VERSION}
COPY apply-minimal-config.sh /src/apply-minimal-config.sh
RUN sed -i 's/\r$//' /src/apply-minimal-config.sh \
  && sh /src/apply-minimal-config.sh .config \
  && make -j"$(nproc)" LDFLAGS="-static -no-pie" \
  && cp busybox /busybox && cp .config /busybox.config

FROM alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507 AS export
RUN apk add --no-cache binutils file coreutils
COPY --from=build /busybox /busybox
COPY --from=build /busybox.config /export/.config
RUN mkdir -p /export \
  && /busybox | head -1 > /export/version.txt \
  && /busybox --list | sort > /export/applets.txt \
  && readelf -h -l -S /busybox > /export/readelf.txt \
  && sha256sum /busybox | awk '{print $1}' > /export/busybox.sha256 \
  && wc -c /busybox | awk '{print $1}' > /export/size_bytes.txt \
  && file /busybox > /export/file.txt \
  && echo "musl=1.2.5-r11 (Alpine 3.21 build-base); gcc $(gcc -dumpversion) CONFIG_STATIC=y" > /export/toolchain.txt
