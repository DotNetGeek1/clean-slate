# Reproducible static ET_EXEC for M9 #146 (Alpine 3.21 / binutils, linux/amd64).
FROM alpine:3.21
RUN apk add --no-cache build-base binutils
WORKDIR /src
COPY exec-args.S exec-args.ld ./
RUN as --64 -o exec-args.o exec-args.S \
 && ld -m elf_x86_64 -static -nostdlib -no-pie --build-id=none --hash-style=sysv -z norelro -T exec-args.ld -o linux-exec-args-x86_64.tmp exec-args.o \
 && objcopy --remove-section=.comment --remove-section=.note --remove-section=.note.gnu.property --remove-section=.note.GNU-stack linux-exec-args-x86_64.tmp linux-exec-args-x86_64 \
 && sha256sum linux-exec-args-x86_64 | awk '{print $1}' > linux-exec-args-x86_64.sha256 \
 && readelf -h -l -S linux-exec-args-x86_64 > readelf.txt
