#!/usr/bin/env python3
"""Aggregate BusyBox-only strace lines into syscall-matrix.toml (M9 #100 Phase A)."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TRACE_DIR = REPO / "fixtures" / "busybox" / "traces"
OUT_TOML = REPO / "fixtures" / "busybox" / "syscall-matrix.toml"
OUT_JSON = REPO / "fixtures" / "busybox" / "syscall-matrix.json"

# x86-64 Linux syscall numbers (partial — extended at runtime).
SYSCALL_BY_NAME: dict[str, int] = {
    "read": 0,
    "write": 1,
    "open": 2,
    "close": 3,
    "stat": 4,
    "fstat": 5,
    "lstat": 6,
    "poll": 7,
    "lseek": 8,
    "mmap": 9,
    "mprotect": 10,
    "munmap": 11,
    "brk": 12,
    "rt_sigaction": 13,
    "rt_sigprocmask": 14,
    "ioctl": 16,
    "access": 21,
    "pipe": 22,
    "select": 23,
    "madvise": 28,
    "dup": 32,
    "dup2": 33,
    "nanosleep": 35,
    "getpid": 39,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "sendmsg": 46,
    "recvmsg": 47,
    "bind": 49,
    "listen": 50,
    "getsockname": 51,
    "getsockopt": 55,
    "clone": 56,
    "fork": 57,
    "vfork": 58,
    "execve": 59,
    "exit": 60,
    "wait4": 61,
    "kill": 62,
    "uname": 63,
    "fcntl": 72,
    "ftruncate": 77,
    "getcwd": 79,
    "chdir": 80,
    "rename": 82,
    "mkdir": 83,
    "rmdir": 84,
    "unlink": 87,
    "readlink": 89,
    "gettimeofday": 96,
    "getuid": 102,
    "getgid": 104,
    "geteuid": 107,
    "getegid": 108,
    "getppid": 110,
    "getpgrp": 111,
    "setsid": 112,
    "arch_prctl": 158,
    "set_tid_address": 218,
    "getdents64": 217,
    "exit_group": 231,
    "openat": 257,
    "newfstatat": 262,
    "set_robust_list": 273,
    "pipe2": 293,
    "prlimit64": 302,
    "getrandom": 318,
    "statx": 332,
    "rseq": 334,
    "clone3": 435,
    "writev": 20,
    "sendfile": 40,
    "clock_nanosleep": 230,
}

OWNER_BY_NR: dict[int, str] = {
    59: "#146",
    0: "#147",
    1: "#147",
    43: "#105",
    40: "#147",
    20: "#147",
    6: "#101",
    4: "#101",
    2: "#147",
    3: "#147",
    4: "#147",
    5: "#147",
    8: "#147",
    9: "#147",
    257: "#147",
    33: "#147",
    72: "#147",
    57: "#102",
    56: "#102",
    58: "#102",
    435: "#102",
    61: "#102",
    22: "#102",
    293: "#102",
    110: "#102",
    111: "#102",
    83: "#101",
    87: "#101",
    217: "#101",
    262: "#101",
    277: "#101",
    41: "#105",
    42: "#105",
    43: "#105",
    44: "#105",
    45: "#105",
    49: "#105",
    50: "#105",
    51: "#105",
    55: "#105",
    7: "#103",
    35: "#103",
    230: "#103",
    12: "#103",
    10: "#103",
    11: "#103",
    13: "#103",
    14: "#103",
    16: "#103",
    21: "#103",
    28: "#103",
    39: "#103",
    60: "#103",
    63: "#103",
    79: "#103",
    89: "#103",
    96: "#103",
    102: "#103",
    104: "#103",
    107: "#103",
    108: "#103",
    158: "#103",
    218: "#103",
    231: "#103",
    273: "#103",
    302: "#103",
    318: "#103",
    334: "#103",
    332: "#101",
}


def owner_for(name: str, nr: int) -> str:
    if nr in OWNER_BY_NR:
        return OWNER_BY_NR[nr]
    if name in ("execve",):
        return "#146"
    if name in ("fork", "vfork", "clone", "clone3", "wait4", "pipe", "pipe2", "getppid"):
        return "#102"
    if name in ("socket", "connect", "sendto", "recvfrom", "bind", "listen", "accept", "getsockopt", "getsockname"):
        return "#105"
    if name in ("openat", "newfstatat", "getdents64", "statx", "mkdir", "unlink", "rename", "readlink"):
        return "#101"
    if name in ("read", "write", "open", "close", "fstat", "lseek", "dup", "dup2", "fcntl"):
        return "#147"
    return "#103"


SYSCALL_LINE = re.compile(
    r"^(?:\d+\s+)?(?:\d+:\d+:\d+\.\d+\s+)?"
    r"(?:\[pid\s+\d+\]\s+)?(?:\d+:\d+:\d+\.\d+\s+)?"
    r"(\w+)\((.*)\)\s*="
)


def busybox_slice(lines: list[str]) -> list[tuple[int, str]]:
    """Return (line_no, line) for BusyBox rootfs activity only (after execve /bin/*)."""
    out: list[tuple[int, str]] = []
    in_tree = False
    for i, line in enumerate(lines, start=1):
        if 'execve("/usr/sbin/chroot"' in line:
            in_tree = False
            continue
        if re.search(r'execve\("/bin/', line):
            in_tree = True
        if not in_tree:
            continue
        if SYSCALL_LINE.search(line.replace("<unfinished ...>", "").replace("<... ", "")):
            out.append((i, line))
        elif re.search(r"\w+\([^)]*<unfinished", line):
            out.append((i, line))
    return out


def parse_trace(path: Path) -> dict[int, list[dict]]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    by_nr: dict[int, list[dict]] = defaultdict(list)
    for line_no, line in busybox_slice(lines):
        clean = re.sub(r"<unfinished \.\.\.>|\<\.\.\. \w+ resumed\>", "", line)
        m = SYSCALL_LINE.search(clean)
        if not m:
            m2 = re.search(
                r"(?:^|\s)(\w+)\(([^)]*)$",
                clean,
            )
            if not m2:
                m2 = re.search(r"(?:^|\s)(\w+)\(", clean)
            if not m2:
                continue
            name = m2.group(1)
            args = m2.group(2) if m2.lastindex and m2.lastindex >= 2 else ""
        else:
            name = m.group(1)
            args = m.group(2)
        nr = SYSCALL_BY_NAME.get(name)
        if nr is None:
            continue
        own = owner_for(name, nr)
        by_nr[nr].append(
            {
                "trace": path.name,
                "line": line_no,
                "name": name,
                "args_sample": args[:200],
                "owner": own,
            }
        )
    return by_nr


def main() -> None:
    merged: dict[int, dict] = {}
    for path in sorted(TRACE_DIR.glob("*.strace")):
        for nr, obs in parse_trace(path).items():
            entry = merged.setdefault(
                nr,
                {
                    "nr": nr,
                    "name": obs[0]["name"],
                    "owner": obs[0]["owner"],
                    "commands": set(),
                    "examples": [],
                },
            )
            entry["commands"].add(path.stem)
            for o in obs[:2]:
                if len(entry["examples"]) < 6:
                    entry["examples"].append(o)

    rows = [merged[nr] for nr in sorted(merged)]
    OUT_JSON.write_text(
        json.dumps(
            {
                "syscalls": [
                    {
                        **r,
                        "commands": sorted(r["commands"]),
                        "examples": r["examples"],
                    }
                    for r in rows
                ]
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    lines_out = [
        "# M9 BusyBox syscall matrix (Phase A draft — BusyBox rootfs slice only)",
        "# Evidence: fixtures/busybox/traces/*.strace (post execve /bin/* in chroot)",
        "",
        "[meta]",
        'candidate = "musl-minimal"',
        'busybox_version = "1.37.0"',
        f"syscall_count = {len(rows)}",
        "",
    ]
    for row in rows:
        lines_out.append("[[syscall]]")
        lines_out.append(f"nr = {row['nr']}")
        lines_out.append(f'name = "{row["name"]}"')
        lines_out.append(f'owner = "{row["owner"]}"')
        cmd_list = ", ".join(f'"{c}"' for c in sorted(row["commands"]))
        lines_out.append(f"commands = [{cmd_list}]")
        ex = row["examples"][0]
        lines_out.append(f'evidence = "{ex["trace"]}:{ex["line"]}"')
        lines_out.append("")

    OUT_TOML.write_text("\n".join(lines_out), encoding="utf-8")
    print(f"Wrote {len(rows)} syscalls")

    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        counts[r["owner"]] += 1
    for k in sorted(counts):
        print(f"{k}={counts[k]}")


if __name__ == "__main__":
    main()
