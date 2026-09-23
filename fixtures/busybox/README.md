# BusyBox M9 ABI evidence (Phase A / #100)

Linux-only evidence for the M9 BusyBox compatibility contract. Reproduce traces on Docker Desktop (linux/amd64):

```bash
# Build musl-minimal candidate (ET_EXEC @ 0x400000)
docker build -f fixtures/busybox/candidates/musl-minimal/Dockerfile \
  -t m9-busybox-musl-minimal:local fixtures/busybox/candidates/musl-minimal

# Strace command matrix (needs SYS_PTRACE)
docker run --rm --cap-add=SYS_PTRACE --security-opt seccomp=unconfined \
  -v "$PWD:/work" -w /work m9-busybox-musl-minimal:local \
  sh -c 'apk add --no-cache strace >/dev/null; BUSYBOX_BIN=/busybox sh fixtures/busybox/run-traces.sh'

python3 fixtures/busybox/gen-syscall-matrix.py
```

Artifacts:

| Path | Role |
|------|------|
| `candidates/*/` | Build evidence |
| `traces/*.strace` | Fixture + supplement traces |
| `run-traces.sh` / `run-supplement-traces.sh` | Regenerate traces |
| `gen-syscall-matrix.py` | TOML/JSON with harness split |

Phase A does **not** commit multi-MB `busybox` binaries (`candidates/.gitignore`); Phase B freezes the chosen artifact.
