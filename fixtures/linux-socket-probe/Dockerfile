FROM alpine:3.21
RUN apk add --no-cache build-base binutils
WORKDIR /src
COPY probe.S probe.ld ./
RUN as --64 -o probe.o probe.S \
 && ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T probe.ld -o linux-socket-probe-x86_64.tmp probe.o \
 && objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack linux-socket-probe-x86_64.tmp linux-socket-probe-x86_64 \
 && sha256sum linux-socket-probe-x86_64 | awk '{print $1}' > linux-socket-probe-x86_64.sha256
