#!/usr/bin/env python3
"""Fail if a workspace member is missing from the PR workflow path filters."""

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


def path_blocks(text: str) -> list[list[str]]:
    blocks = re.findall(r"(?m)^    paths:\n((?:      - .*\n)+)", text)
    if len(blocks) != 2:
        sys.exit(
            f".github/workflows/pr.yml: expected pull_request and push path lists, found {len(blocks)}"
        )
    return [re.findall(r'"([^"]+)"', block) for block in blocks]


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
    if missing:
        return 1
    print(f"path filters include {len(names)} workspace members")
    return 0


if __name__ == "__main__":
    sys.exit(main())
