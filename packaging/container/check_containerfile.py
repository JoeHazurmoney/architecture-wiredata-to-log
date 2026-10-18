#!/usr/bin/env python3
"""Checks a Containerfile before anything is built (docs/decisions/0004-container-base-image.md).
packaging/container/Containerfile, wd2l's image (the "hardened" profile):

* every FROM is a Red Hat Hardened Image, a FIPS variant, pinned as NAME:TAG@sha256:DIGEST;
* the last stage is a runtime image, not a builder.

packaging/container/Containerfile.ubi9, the comparison image on UBI 9 (the "ubi9" profile, #192):

* every FROM is registry.access.redhat.com/ubi9/ubi, pinned the same way, and all one digest.

Either way, COPY --from names a stage, never an image. The profile follows the file's name.

    check_containerfile.py [FILE]           check; exit 1 with one line per problem
    check_containerfile.py [FILE] --base    print the runtime base (NAME:TAG@DIGEST)
    check_containerfile.py [FILE] --json    print every FROM as JSON"""

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "Containerfile")
REGISTRY = "registry.access.redhat.com/hi/"
UBI9 = "registry.access.redhat.com/ubi9/ubi"
PROFILES = {"Containerfile": "hardened", "Containerfile.ubi9": "ubi9"}
FROM = re.compile(r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I)
COPY_FROM = re.compile(r"^\s*COPY\s+.*--from=(\S+)", re.I)
PINNED = re.compile(r"^(?P<name>[^@\s]+):(?P<tag>[^@\s:/]+)@(?P<digest>sha256:[0-9a-f]{64})$")


def froms(text: str) -> List[Dict[str, Optional[str]]]:
    out = []
    for line in text.splitlines():
        m = FROM.match(line)
        if m:
            p = PINNED.match(m.group(1))
            out.append({"ref": m.group(1), "stage": m.group(2),
                        "name": p.group("name") if p else None,
                        "tag": p.group("tag") if p else None,
                        "digest": p.group("digest") if p else None})
    return out


def profile_of(path: str) -> str:
    """The rules a Containerfile is checked by, from its name."""
    return PROFILES.get(os.path.basename(path), "hardened")


def problems(text: str, profile: str = "hardened") -> List[str]:
    refs = froms(text)
    if not refs:
        return ["no FROM line"]
    out = []
    for r in refs:
        if not r["digest"]:
            out.append("%s: not pinned as NAME:TAG@sha256:DIGEST" % r["ref"])
            continue
        if profile == "ubi9":
            if r["name"] != UBI9:
                out.append("%s: not UBI 9 (%s)" % (r["ref"], UBI9))
            continue
        if not str(r["name"]).startswith(REGISTRY):
            out.append("%s: not a Red Hat Hardened Image (%s...)" % (r["ref"], REGISTRY))
        if not re.search(r"-fips(-builder)?$", str(r["tag"])):
            out.append("%s: not a FIPS variant" % r["ref"])
    last = refs[-1]
    if profile == "ubi9":
        if len({r["digest"] for r in refs}) > 1:
            out.append("every stage must be the same UBI 9 image, the same digest")
    elif last["tag"] and str(last["tag"]).endswith("-builder"):
        out.append("%s: the last stage must be a runtime image, not a builder" % last["ref"])
    stages = {r["stage"] for r in refs if r["stage"]}
    for line in text.splitlines():
        m = COPY_FROM.match(line)
        if m and m.group(1) not in stages:
            out.append("COPY --from=%s: copies from an image, not a stage" % m.group(1))
    return out


def base(text: str) -> str:
    return str(froms(text)[-1]["ref"])


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check the wd2l Containerfile.")
    p.add_argument("file", nargs="?", default=DEFAULT)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--base", action="store_true", help="print the runtime base image")
    g.add_argument("--json", action="store_true", help="print every FROM as JSON")
    a = p.parse_args(argv)
    with open(a.file) as f:
        text = f.read()
    probs = problems(text, profile_of(a.file))
    for x in probs:
        print("containerfile: " + x, file=sys.stderr)
    if probs:
        return 1
    if a.base:
        print(base(text))
    elif a.json:
        print(json.dumps(froms(text), indent=1))
    else:
        print("containerfile: ok (%s)" % base(text))
    return 0


if __name__ == "__main__":
    sys.exit(main())
