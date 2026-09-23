FROM alpine:3.21
RUN apk add --no-cache build-base binutils
WORKDIR /src
COPY proc-probe.S proc-probe.ld ./
RUN as --64 -o proc-probe.o proc-probe.S \
 && ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T proc-probe.ld -o linux-proc-probe-x86_64.tmp proc-probe.o \
 && objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack linux-proc-probe-x86_64.tmp linux-proc-probe-x86_64 \
 && sha256sum linux-proc-probe-x86_64 | awk '{print $1}' > linux-proc-probe-x86_64.sha256 \
 && readelf -h -l -S linux-proc-probe-x86_64 > readelf.txt
