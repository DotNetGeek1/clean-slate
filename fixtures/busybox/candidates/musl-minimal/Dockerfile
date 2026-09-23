# Reproducible minimal static BusyBox (musl, CONFIG_STATIC=y, no PIE).
FROM alpine:3.21 AS build
RUN apk add --no-cache build-base wget perl linux-headers binutils
ARG BUSYBOX_VERSION=1.37.0
WORKDIR /src
RUN wget -q "https://busybox.net/downloads/busybox-${BUSYBOX_VERSION}.tar.bz2" \
  && tar xf "busybox-${BUSYBOX_VERSION}.tar.bz2"
WORKDIR /src/busybox-${BUSYBOX_VERSION}
RUN make defconfig \
  && sed -i \
    -e 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' \
    -e 's/^CONFIG_PIE=y/# CONFIG_PIE is not set/' \
    -e 's/# CONFIG_ASH is not set/CONFIG_ASH=y/' \
    -e 's/# CONFIG_FEATURE_SH_IS_ASH is not set/CONFIG_FEATURE_SH_IS_ASH=y/' \
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
    .config \
  && for o in CONFIG_STATIC CONFIG_ASH CONFIG_FEATURE_SH_IS_ASH CONFIG_LS CONFIG_CAT \
      CONFIG_MKDIR CONFIG_ECHO CONFIG_GREP CONFIG_UNAME CONFIG_NSLOOKUP CONFIG_WGET \
      CONFIG_SLEEP CONFIG_TRUE CONFIG_HTTPD CONFIG_PWD CONFIG_PRINTF; do \
      grep -q "^${o}=y" .config || echo "${o}=y" >> .config; \
    done \
  && grep -q '^# CONFIG_PIE is not set' .config || echo '# CONFIG_PIE is not set' >> .config \
  && make oldconfig </dev/null \
  && make -j"$(nproc)" LDFLAGS="-static -no-pie" EXTRA_CFLAGS="-fno-pie -no-pie" \
  && cp busybox /busybox && cp .config /busybox.config

FROM alpine:3.21 AS export
RUN apk add --no-cache binutils file coreutils
COPY --from=build /busybox /busybox
COPY --from=build /busybox.config /export/.config
RUN mkdir -p /export \
  && /busybox | head -1 > /export/version.txt \
  && /busybox --list > /export/applets.txt \
  && readelf -h -l -S /busybox > /export/readelf.txt \
  && sha256sum /busybox | awk '{print $1}' > /export/sha256 \
  && wc -c /busybox | awk '{print $1}' > /export/size_bytes.txt \
  && file /busybox > /export/file.txt
