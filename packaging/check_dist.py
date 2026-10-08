#!/usr/bin/env python3
"""Checks dist/ before anything is packaged from it (the image pipeline and the release):

* one wheel and one sdist, both named for wd2l/__init__.py's version;
* the wheel carries wd2l/BUILD (the commit), the three commands and the MIT license;
* the sdist carries what the RPM is built from (deploy/, packaging/, LICENSE).

    python3 packaging/check_dist.py DIST_DIR --commit SHA [--version V]

Exit 0 when all is well, 1 with one line per problem."""

import argparse
import glob
import os
import re
import sys
import tarfile
import zipfile
from typing import List, Optional, Sequence

SCRIPTS = ("wd2l-sender", "wd2l-receiver", "wd2l-audit-report")
# Files the sdist must hold. Task 5.2 adds the RPM spec and rpmify.py.
SDIST_NEEDS = ("LICENSE", "README.md", "wd2l/__init__.py", "wd2l/BUILD",
               "deploy/common/wd2l-audit-seal.sh", "deploy/log-server/wd2l-sender.service",
               "deploy/receiver/wd2l-receiver.service", "packaging/check_dist.py")
REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


def repo_version(init: str = os.path.join(REPO, "wd2l", "__init__.py")) -> str:
    with open(init) as f:
        m = re.search(r'^__version__ = "([^"]+)"$', f.read(), re.M)
    if not m:
        raise SystemExit("no __version__ in %s" % init)
    return m.group(1)


def _text(z: zipfile.ZipFile, name: str) -> str:
    try:
        return z.read(name).decode("utf-8", "replace")
    except KeyError:
        return ""


def check_wheel(path: str, version: str, commit: str) -> List[str]:
    out = []
    want = "wd2l-%s-py3-none-any.whl" % version
    if os.path.basename(path) != want:
        out.append("wheel name %s, expected %s" % (os.path.basename(path), want))
    di = "wd2l-%s.dist-info/" % version
    with zipfile.ZipFile(path) as z:
        names = set(z.namelist())
        build = _text(z, "wd2l/BUILD").strip()
        if build != commit:
            out.append("wheel wd2l/BUILD is %r, expected the commit %r" % (build, commit))
        ep = _text(z, di + "entry_points.txt")
        for s in SCRIPTS:
            if not re.search(r"^%s\s*=" % re.escape(s), ep, re.M):
                out.append("wheel has no %s command" % s)
        if not re.search(r"^License-Expression: MIT$", _text(z, di + "METADATA"), re.M):
            out.append("wheel METADATA has no License-Expression: MIT")
        if di + "licenses/LICENSE" not in names:
            out.append("wheel has no %slicenses/LICENSE" % di)
    return out


def check_sdist(path: str, version: str) -> List[str]:
    out = []
    want = "wd2l-%s.tar.gz" % version
    if os.path.basename(path) != want:
        out.append("sdist name %s, expected %s" % (os.path.basename(path), want))
    top = "wd2l-%s/" % version
    with tarfile.open(path) as t:
        names = set(t.getnames())
    out += ["sdist has no %s" % (top + n) for n in SDIST_NEEDS if top + n not in names]
    return out


def check(dist: str, version: str, commit: str) -> List[str]:
    wheels = sorted(glob.glob(os.path.join(dist, "*.whl")))
    sdists = sorted(glob.glob(os.path.join(dist, "*.tar.gz")))
    out = []
    if len(wheels) != 1:
        out.append("expected one wheel in %s, found %d" % (dist, len(wheels)))
    if len(sdists) != 1:
        out.append("expected one sdist in %s, found %d" % (dist, len(sdists)))
    if len(wheels) == 1:
        out += check_wheel(wheels[0], version, commit)
    if len(sdists) == 1:
        out += check_sdist(sdists[0], version)
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check the wheel and sdist in DIST.")
    p.add_argument("dist")
    p.add_argument("--commit", required=True, help="the commit wd2l/BUILD must name")
    p.add_argument("--version", help="default: wd2l/__init__.py's __version__")
    a = p.parse_args(argv)
    version = a.version or repo_version()
    probs = check(a.dist, version, a.commit)
    for x in probs:
        print("dist: " + x)
    if not probs:
        print("dist: ok (wd2l %s, BUILD %s)" % (version, a.commit))
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
