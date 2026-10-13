#!/usr/bin/env python3
"""Checks a title against the commit convention (docs/releasing.md, "Conventions"): a
Conventional Commit, `<type>[(scope)][!]: <description>`. A squash merge's commit subject is the
PR title (the merge request title, on other forges), so pr-title.yml checks the title before
merging, and tests.yml checks what landed on main.

    check_title.py [--warn] [TITLE]     no TITLE: the first line of stdin

Exit 1 if it isn't one; with --warn, a GitHub Actions warning and exit 0."""

import argparse
import re
import sys
from typing import Optional, Sequence

# The convention's types (docs/releasing.md, "Conventions"). cliff.toml groups the changelog by
# them; tests/test_check_title.py keeps the two in step.
TYPES = ("feat", "fix", "security", "docs", "build", "ci", "test", "refactor", "perf", "chore",
         "revert")
TITLE = re.compile(r"^(%s)(\([a-z0-9][a-z0-9._/-]*\))?!?: \S" % "|".join(TYPES))


def check(title: str) -> Optional[str]:
    """None if the title follows the convention, else why not."""
    if not title.strip():
        return "the title is empty"
    if TITLE.match(title):
        return None
    return ("not a Conventional Commit title: %r. Use '<type>[(scope)][!]: <description>', "
            "where <type> is one of %s, and a scope is lower case, e.g. 'fix(receiver): ...'."
            % (title, ", ".join(TYPES)))


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check a title against the commit convention.")
    p.add_argument("--warn", action="store_true", help="warn (GitHub Actions) instead of failing")
    p.add_argument("title", nargs="?", help="the title; default: the first line of stdin")
    a = p.parse_args(argv)
    t = a.title if a.title is not None else (sys.stdin.readline().rstrip("\r\n"))
    why = check(t)
    if why is None:
        print("ok: %s" % t)
        return 0
    if a.warn:
        print("::warning title=Commit convention::%s" % why)
        return 0
    print(why, file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
