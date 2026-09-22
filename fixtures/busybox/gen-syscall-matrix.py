#!/usr/bin/env python3
"""M9 BusyBox syscall matrix with pid/applet attribution and harness separation."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TRACE_DIR = REPO / "fixtures" / "busybox" / "traces"
OUT_TOML = REPO / "fixtures" / "busybox" / "syscall-matrix.toml"
OUT_JSON = REPO / "fixtures" / "busybox" / "syscall-matrix.json"

# Frozen M9 command matrix traces (fixture); excludes harness-only wget-local-httpd for required counts
FIXTURE_COMMAND_TRACES = {
    "true",
    "busybox-list",
    "pwd",
    "ls-root",
    "cat-hostname",
    "tmp-file-io",
    "pipe-grep",
    "uname",
    "nslookup-fixture",
    "wget-fixture-fail",
    "sleep-1",
    "exit-3",
    "script-sh",
    "sh-c-minimal",
    "pipe-grep-env-i",
    "pipe-grep-path-only",
    "grep-via-busybox",
    "grep-via-symlink",
}

HARNESS_TRACE = "wget-local-httpd"

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
    "dup": 32,
    "dup2": 33,
    "nanosleep": 35,
    "getpid": 39,
    "writev": 20,
    "sendfile": 40,
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "bind": 49,
    "listen": 50,
    "fork": 57,
    "execve": 59,
    "wait4": 61,
    "kill": 62,
    "uname": 63,
    "fcntl": 72,
    "getcwd": 79,
    "chdir": 80,
    "mkdir": 83,
    "getppid": 110,
    "arch_prctl": 158,
    "getdents64": 217,
    "set_tid_address": 218,
    "exit_group": 231,
    "getuid": 102,
}

PRIMARY_OWNER: dict[int, str] = {
    59: "#146",
    0: "#147",
    1: "#147",
    3: "#147",
    5: "#147",
    8: "#147",
    20: "#147",
    33: "#147",
    72: "#147",
    2: "#101",
    4: "#101",
    6: "#101",
    79: "#101",
    80: "#101",
    83: "#101",
    217: "#101",
    57: "#102",
    22: "#102",
    61: "#102",
    110: "#102",
    231: "#102",
    9: "#103",
    10: "#103",
    11: "#103",
    12: "#103",
    13: "#103",
    14: "#103",
    16: "#103",
    35: "#103",
    39: "#103",
    63: "#103",
    102: "#103",
    158: "#103",
    218: "#103",
    41: "#105",
    42: "#105",
    44: "#105",
    45: "#105",
    49: "#105",
    7: "#103",
    40: "#147",  # sendfile — required=false pending Phase B config
    43: "#105",
    50: "#105",
    62: "#103",
}

SECONDARY_OWNER: dict[int, str] = {2: "#147"}

LINE_PID = re.compile(r"^(\d+)\s+")
LINE_SYSCALL = re.compile(
    r"(\w+)\((.*?)\)\s*=\s*(-?\d+|(\?|\.\.\.))"
    r"|(\w+)\([^)]*<unfinished"
    r"|(\w+)\(\.\.\.\)\s*=\s*(\?|\.\.\.)"
)
EXECVE_BIN = re.compile(r'execve\("(/bin/[^"]+)"')
EXECVE_CHROOT = re.compile(r'execve\("/usr/sbin/chroot"')

POLL_NEGATIVE = re.compile(r"fd=-1")
CONNECT_127 = re.compile(r"127\.0\.0\.1")
BIND_18080 = re.compile(r"18080")


def owner_for(nr: int, name: str) -> str:
    return PRIMARY_OWNER.get(nr, "#103")


def blocking_for(name: str, args: str, result: str) -> str:
    if name == "poll":
        if "Timeout" in result or result.strip().endswith("0 (Timeout)"):
            return "timeout"
        return "may-block"
    if name in ("nanosleep", "clock_nanosleep"):
        return "timeout"
    if name == "wait4":
        if "WNOHANG" in args:
            return "never"
        return "may-block"
    if name == "connect":
        return "may-block"
    if name == "read" and "1024" in args:
        return "may-block"
    if name == "accept":
        return "may-block"
    return "never"


def descriptor_kinds(name: str, args: str, applet: str) -> list[str]:
    kinds: list[str] = []
    if name in ("open", "stat", "lstat", "getdents64", "mkdir"):
        kinds.append("path")
    if name in ("read", "write", "writev", "sendfile", "close", "lseek", "fcntl", "dup2"):
        kinds.append("fd")
    if name in ("socket", "connect", "sendto", "recvfrom", "bind", "poll"):
        kinds.append("socket")
    if name == "pipe":
        kinds.append("pipe")
    return kinds or ["process"]


def is_harness(trace_stem: str, applet: str, name: str, args: str) -> bool:
    if trace_stem != HARNESS_TRACE:
        return False
    if applet in ("httpd", "sleep"):
        return True
    if name in ("listen", "accept", "kill"):
        return True
    if name == "connect" and CONNECT_127.search(args):
        return True
    if name == "bind" and BIND_18080.search(args):
        return True
    if name == "socket" and "AF_INET6" in args:
        return True
    if name == "sendfile":
        return True
    if name == "chdir":
        return True
    # wget client in this trace only talks to local httpd
    if applet == "wget":
        return True
    return False


def normalize_flags(name: str, args: str) -> str:
    return f"{name}({args})"


def parse_trace_file(path: Path) -> list[dict]:
    stem = path.stem
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    pid_applet: dict[int, str] = {}
    in_rootfs = False
    observations: list[dict] = []

    for line_no, line in enumerate(lines, start=1):
        if EXECVE_CHROOT.search(line):
            in_rootfs = False
        m_exec = EXECVE_BIN.search(line)
        if m_exec:
            in_rootfs = True
            pid_m = LINE_PID.match(line)
            if pid_m:
                pid = int(pid_m.group(1))
                exe = m_exec.group(1)
                base = exe.rsplit("/", 1)[-1]
                if base == "busybox":
                    if '"grep"' in line or "grep" in line.split("execve")[1][:80]:
                        pid_applet[pid] = "grep"
                    elif '"httpd"' in line:
                        pid_applet[pid] = "httpd"
                    elif '"wget"' in line:
                        pid_applet[pid] = "wget"
                    elif '"sleep"' in line:
                        pid_applet[pid] = "sleep"
                    else:
                        pid_applet[pid] = "busybox"
                else:
                    pid_applet[pid] = base
                # Record execve itself
                harness = is_harness(stem, pid_applet[pid], "execve", line)
                observations.append(
                    {
                        "trace": path.name,
                        "line": line_no,
                        "command": stem,
                        "pid": pid,
                        "applet": pid_applet[pid],
                        "nr": 59,
                        "name": "execve",
                        "flags": line.split("execve", 1)[1].strip()[:200],
                        "blocking": "never",
                        "descriptor_kinds": ["path"],
                        "errno_observed": [],
                        "harness_only": harness,
                        "required": not harness,
                        "owner": "#146",
                    }
                )
            continue

        if not in_rootfs:
            continue

        pid_m = LINE_PID.match(line)
        if not pid_m:
            continue
        pid = int(pid_m.group(1))
        applet = pid_applet.get(pid, "unknown")

        clean = re.sub(r"<unfinished \.\.\.>|\<\.\.\. \w+ resumed\>", "", line)
        sm = re.search(r"(\w+)\((.*)\)\s*=\s*(.+)$", clean)
        if not sm:
            sm2 = re.search(r"(\w+)\((.*)$", clean)
            if not sm2:
                continue
            name, args, result = sm2.group(1), sm2.group(2), "unfinished"
        else:
            name, args, result = sm.group(1), sm.group(2), sm.group(3)

        nr = SYSCALL_BY_NAME.get(name)
        if nr is None:
            continue

        # Skip chroot-wrapper dynamic linker mmap (fd>=3 file-backed in chroot host)
        if name == "mmap" and re.search(r",\s*[3-9]\d*,\s*0\)", args):
            continue
        if name == "open" and "/lib/" in args:
            continue
        if name == "readlink" and "/tmp/m9" in args:
            continue

        flag_sig = normalize_flags(name, args)
        harness = is_harness(stem, applet, name, args)
        errno_obs = []
        em = re.search(r"=\s*-1\s+(\w+)", result)
        if em:
            errno_obs.append(em.group(1))

        observations.append(
            {
                "trace": path.name,
                "line": line_no,
                "command": stem,
                "pid": pid,
                "applet": applet,
                "nr": nr,
                "name": name,
                "flags": flag_sig,
                "blocking": blocking_for(name, args, result),
                "descriptor_kinds": descriptor_kinds(name, args, applet),
                "errno_observed": errno_obs,
                "harness_only": harness,
                "required": not harness,
                "owner": owner_for(nr, name),
            }
        )
    return observations


def merge_observations(all_obs: list[dict]) -> dict[int, dict]:
    merged: dict[int, dict] = {}
    for o in all_obs:
        nr = o["nr"]
        entry = merged.setdefault(
            nr,
            {
                "nr": nr,
                "name": o["name"],
                "owner": o["owner"],
                "secondary_owner": SECONDARY_OWNER.get(nr),
                "applets": set(),
                "commands": set(),
                "flags": set(),
                "blocking": set(),
                "descriptor_kinds": set(),
                "errno_observed": set(),
                "evidence": [],
                "required_evidence": [],
                "harness_evidence": [],
                "required": False,
                "harness_only": True,
            },
        )
        entry["applets"].add(o["applet"])
        entry["commands"].add(o["command"])
        entry["flags"].add(o["flags"])
        entry["blocking"].add(o["blocking"])
        entry["descriptor_kinds"].update(o["descriptor_kinds"])
        entry["errno_observed"].update(o["errno_observed"])
        ev = f"{o['trace']}:{o['line']}"
        if ev not in entry["evidence"]:
            entry["evidence"].append(ev)
        if o["harness_only"]:
            if ev not in entry["harness_evidence"]:
                entry["harness_evidence"].append(ev)
        else:
            entry["required"] = True
            entry["harness_only"] = False
            if ev not in entry["required_evidence"]:
                entry["required_evidence"].append(ev)

    # sendfile: Phase A decision — not required until config pinned
    if 40 in merged:
        merged[40]["required"] = False
        merged[40]["note"] = (
            "BusyBox copyfd.c falls back on sendfile failure; Phase B should set CONFIG_FEATURE_USE_SENDFILE=n"
        )

    return merged


def highest_fd(all_obs: list[dict]) -> int:
    mx = 3
    fd_first_arg = {
        "read",
        "write",
        "close",
        "lseek",
        "fcntl",
        "dup2",
        "fstat",
        "ioctl",
        "sendfile",
    }
    for o in all_obs:
        name = o["name"]
        args = o["flags"]
        if name in fd_first_arg:
            m = re.match(rf"{name}\((\d+)", args)
            if m:
                mx = max(mx, int(m.group(1)))
        if name == "dup2":
            m = re.search(r"dup2\((\d+),\s*(\d+)\)", args)
            if m:
                mx = max(mx, int(m.group(1)), int(m.group(2)))
        if name == "fcntl":
            m = re.search(r"fcntl\((\d+)", args)
            if m:
                mx = max(mx, int(m.group(1)))
            m = re.search(r"F_DUPFD(?:_CLOEXEC)?,\s*(\d+)", args)
            if m:
                mx = max(mx, int(m.group(1)))
        if name == "pipe":
            m = re.search(r"pipe\(\[(\d+),\s*(\d+)\]", args)
            if m:
                mx = max(mx, int(m.group(1)), int(m.group(2)))
        if name == "poll":
            m = re.search(r"fd=(\d+)", args)
            if m:
                mx = max(mx, int(m.group(1)))
    return mx


def main() -> None:
    all_obs: list[dict] = []
    for path in sorted(TRACE_DIR.glob("*.strace")):
        all_obs.extend(parse_trace_file(path))

    merged = merge_observations(all_obs)
    rows = [merged[nr] for nr in sorted(merged)]

    required_rows = [r for r in rows if r["required"]]
    harness_rows = [r for r in rows if r["harness_only"] and not r["required"]]

    hi_fd = highest_fd(all_obs)

    json_rows = []
    for r in rows:
        json_rows.append(
            {
                "nr": r["nr"],
                "name": r["name"],
                "owner": r["owner"],
                "secondary_owner": r.get("secondary_owner"),
                "required": r["required"],
                "harness_only": r["harness_only"] and not r["required"],
                "applets": sorted(r["applets"]),
                "commands": sorted(r["commands"]),
                "flags": sorted(r["flags"])[:50],
                "blocking": sorted(r["blocking"]),
                "descriptor_kinds": sorted(r["descriptor_kinds"]),
                "errno_observed": sorted(r["errno_observed"]),
                "evidence": r["evidence"][:30],
                "required_evidence": r["required_evidence"][:20],
                "harness_evidence": r["harness_evidence"][:20],
                "note": r.get("note"),
            }
        )

    OUT_JSON.write_text(
        json.dumps(
            {
                "meta": {
                    "candidate": "musl-minimal",
                    "busybox_version": "1.37.0",
                    "syscall_count": len(required_rows),
                    "harness_only_count": len(harness_rows),
                    "highest_fd_observed": hi_fd,
                },
                "syscalls": json_rows,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    lines_out = [
        "# M9 BusyBox syscall matrix (Phase A — fixture vs harness split)",
        "",
        "[meta]",
        'candidate = "musl-minimal"',
        'busybox_version = "1.37.0"',
        f"syscall_count = {len(required_rows)}",
        f"harness_only_count = {len(harness_rows)}",
        f"highest_fd_observed = {hi_fd}",
        "",
    ]
    for r in rows:
        lines_out.append("[[syscall]]")
        lines_out.append(f"nr = {r['nr']}")
        lines_out.append(f'name = "{r["name"]}"')
        lines_out.append(f'owner = "{r["owner"]}"')
        if r.get("secondary_owner"):
            lines_out.append(f'secondary_owner = "{r["secondary_owner"]}"')
        lines_out.append(f"required = {'true' if r['required'] else 'false'}")
        lines_out.append(
            f"harness_only = {'true' if (r['harness_only'] and not r['required']) else 'false'}"
        )
        lines_out.append(f"applets = {json.dumps(sorted(r['applets']))}")
        lines_out.append(f"commands = {json.dumps(sorted(r['commands']))}")
        lines_out.append(f"blocking = {json.dumps(sorted(r['blocking']))}")
        lines_out.append(f"descriptor_kinds = {json.dumps(sorted(r['descriptor_kinds']))}")
        lines_out.append(f"errno_observed = {json.dumps(sorted(r['errno_observed']))}")
        # TOML array of flags (truncate very long)
        flag_list = sorted(r["flags"])
        lines_out.append("flags = [")
        for fl in flag_list[:40]:
            esc = fl.replace("\\", "\\\\").replace('"', '\\"')
            lines_out.append(f'  "{esc}",')
        if len(flag_list) > 40:
            lines_out.append(f'  "... +{len(flag_list)-40} more",')
        lines_out.append("]")
        ev = r["required_evidence"] or r["harness_evidence"] or r["evidence"]
        lines_out.append("evidence = [")
        for e in ev[:25]:
            lines_out.append(f'  "{e}",')
        lines_out.append("]")
        if r.get("note"):
            lines_out.append(f'note = "{r["note"]}"')
        lines_out.append("")

    OUT_TOML.write_text("\n".join(lines_out), encoding="utf-8")
    print(f"required={len(required_rows)} harness_only={len(harness_rows)} hi_fd={hi_fd}")


if __name__ == "__main__":
    main()
