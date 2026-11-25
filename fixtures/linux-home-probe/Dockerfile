FROM alpine:3.21
RUN apk add --no-cache build-base binutils
WORKDIR /src
COPY probe.S linux-home-probe.ld ./
RUN as --64 -o probe.o probe.S \
 && ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T linux-home-probe.ld -o linux-home-probe-x86_64.tmp probe.o \
 && objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack linux-home-probe-x86_64.tmp linux-home-probe-x86_64 \
 && sha256sum linux-home-probe-x86_64 | awk '{print $1}' > linux-home-probe-x86_64.sha256 \
 && readelf -h -l -S linux-home-probe-x86_64 > readelf.txt
