#!/usr/bin/env python3
"""Fail if a workspace member is missing from the PR workflow path filters, or has no clippy
or no test line in the workflow's `check` job."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def members(text: str) -> list[str]:
    match = re.search(r"(?m)^members\s*=\s*\[(.*?)\]", text, re.S)
    if match is None:
        sys.exit("Cargo.toml: workspace members array not found")
    found = re.findall(r'"([^"]+)"', match.group(1))
    if not found:
        sys.exit("Cargo.toml: no workspace members parsed")
    unique: list[str] = []
    for name in found:
        if name not in unique:
            unique.append(name)
    return unique


def package_name(member: str) -> str:
    manifest = (ROOT / member / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^name\s*=\s*"([^"]+)"', manifest)
    if match is None:
        sys.exit(f"{member}/Cargo.toml: package name not found")
    return match.group(1)


def path_blocks(text: str) -> list[list[str]]:
    blocks = re.findall(r"(?m)^    paths:\n((?:      - .*\n)+)", text)
    if len(blocks) != 2:
        sys.exit(
            f".github/workflows/pr.yml: expected pull_request and push path lists, found {len(blocks)}"
        )
    return [re.findall(r'"([^"]+)"', block) for block in blocks]


def check_job(text: str) -> str:
    match = re.search(r"(?ms)^  check:\n(.*?)(?=^  \S)", text)
    if match is None:
        sys.exit(".github/workflows/pr.yml: check job not found")
    return match.group(1)


def has_command(job: str, command: str, package: str) -> bool:
    pattern = rf"(?m)^\s*(?:run:\s*)?cargo {command} -p {re.escape(package)}(?=\s|$)"
    return re.search(pattern, job) is not None


def main() -> int:
    cargo = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "pr.yml").read_text(encoding="utf-8")
    names = members(cargo)
    missing = False
    for event, globs in zip(("pull_request", "push"), path_blocks(workflow)):
        for name in names:
            required = f"{name}/**"
            if required not in globs:
                print(f"{event} paths omit {required}", file=sys.stderr)
                missing = True
    job = check_job(workflow)
    for name in names:
        package = package_name(name)
        for command in ("clippy", "test"):
            if not has_command(job, command, package):
                print(f"check job has no `cargo {command} -p {package}` line", file=sys.stderr)
                missing = True
    if missing:
        return 1
    print(f"path filters, clippy and test lines cover {len(names)} workspace members")
    return 0


if __name__ == "__main__":
    sys.exit(main())
