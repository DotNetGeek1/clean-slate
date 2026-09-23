FROM alpine:3.21
RUN apk add --no-cache build-base binutils
WORKDIR /src
COPY probe.S linux-fs-probe.ld ./
RUN as --64 -o probe.o probe.S \
 && ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T linux-fs-probe.ld -o linux-fs-probe-x86_64.tmp probe.o \
 && objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack linux-fs-probe-x86_64.tmp linux-fs-probe-x86_64 \
 && sha256sum linux-fs-probe-x86_64 | awk '{print $1}' > linux-fs-probe-x86_64.sha256 \
 && readelf -h -l -S linux-fs-probe-x86_64 > readelf.txt
