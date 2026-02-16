#!/usr/bin/env python3
"""Simple secret scanner for local pre-push and CI."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")),
    ("aws-access-key", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    (
        "generic-secret-assignment",
        re.compile(
            r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret)\b\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
    ),
]

SKIP_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".tar",
    ".woff",
    ".woff2",
    ".ttf",
}

SAFE_HINTS = (
    "example",
    "dummy",
    "sample",
    "placeholder",
    "changeme",
    "your_",
    "your-",
    "your ",
    "<token>",
    "<secret>",
    "<password>",
    "test_",
    "test-",
    "test ",
)

ALLOW_MARKER = "allow-secret"


def git_ls_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files"], capture_output=True, text=True, check=True
    )
    return [Path(line.strip()) for line in result.stdout.splitlines() if line.strip()]


def is_probably_text(path: Path) -> bool:
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    return b"\x00" not in raw


def should_skip_line(line: str) -> bool:
    lower = line.lower()
    if ALLOW_MARKER in lower:
        return True
    return any(hint in lower for hint in SAFE_HINTS)


def main() -> int:
    findings: list[tuple[str, int, str, str]] = []
    for rel_path in git_ls_files():
        if rel_path.suffix.lower() in SKIP_EXTENSIONS:
            continue
        if not rel_path.exists() or not is_probably_text(rel_path):
            continue

        try:
            lines = rel_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines, start=1):
            if should_skip_line(line):
                continue
            for rule_name, pattern in PATTERNS:
                if pattern.search(line):
                    findings.append((str(rel_path), idx, rule_name, line.strip()))
                    break

    if findings:
        print("Secret scan failed. Potential sensitive values found:")
        for path, line_no, rule, line in findings:
            preview = line[:200]
            print(f"- {path}:{line_no} [{rule}] {preview}")
        print("\nIf this is intentional test data, append 'allow-secret' on that line.")
        return 1

    print("Secret scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
