FROM alpine:3.21
RUN apk add --no-cache build-base binutils
WORKDIR /src
COPY probe.S probe.ld ./
RUN as --64 -o probe.o probe.S \
 && ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T probe.ld -o linux-runtime-probe-x86_64.tmp probe.o \
 && readelf -l linux-runtime-probe-x86_64.tmp > readelf.txt \
 && objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack linux-runtime-probe-x86_64.tmp linux-runtime-probe-x86_64
