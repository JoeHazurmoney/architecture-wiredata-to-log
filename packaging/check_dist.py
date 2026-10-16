#!/usr/bin/env python3
"""Checks dist/ before anything is packaged from it (the image pipeline and the release):

* one wheel and one sdist, both named for wd2l/__init__.py's version;
* the wheel carries wd2l/BUILD (the commit), the three commands and the MIT license;
* the sdist carries what the RPM is built from (deploy/, packaging/, LICENSE);
* with --same-as, every file is byte-identical to another build's (image.yml's reproducible
  job), and where a wheel or an sdist differs, the members that differ are named.

    python3 packaging/check_dist.py DIST_DIR --commit SHA [--version V] [--same-as DIR]

Exit 0 when all is well, 1 with one line per problem."""

import argparse
import glob
import hashlib
import os
import re
import sys
import tarfile
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

SCRIPTS = ("wd2l-sender", "wd2l-receiver", "wd2l-audit-report")
# Files the sdist must hold: what the RPM spec builds from.
SDIST_NEEDS = ("LICENSE", "README.md", "wd2l/__init__.py", "wd2l/BUILD",
               "deploy/common/wd2l-audit-seal.sh", "deploy/log-server/wd2l-sender.service",
               "deploy/receiver/wd2l-receiver.service", "packaging/check_dist.py",
               "packaging/rpm/wd2l.spec", "packaging/rpm/rpmify.py", "packaging/rpm/wd2l.sysusers",
               "packaging/rpm/wd2l.tmpfiles", "packaging/rpm/wd2l-receiver.tmpfiles")
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


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _members(path: str) -> List[Tuple[str, Dict[str, Any]]]:
    """A wheel's or an sdist's members, in order, each with what makes its bytes."""
    out = []
    if path.endswith(".whl"):
        with zipfile.ZipFile(path) as z:
            for i in z.infolist():
                out.append((i.filename, {"time": i.date_time, "mode": oct(i.external_attr >> 16),
                                         "compression": i.compress_type, "crc": i.CRC}))
    else:
        with tarfile.open(path) as t:
            for m in t.getmembers():
                data = t.extractfile(m).read() if m.isfile() else b""
                out.append((m.name, {"type": m.type, "mtime": m.mtime, "mode": oct(m.mode),
                                     "owner": (m.uid, m.gid, m.uname, m.gname),
                                     "pax": m.pax_headers, "content": hashlib.sha256(data).hexdigest()}))
    return out


def _member_diff(path: str, other: str) -> List[str]:
    a, b = _members(path), _members(other)
    am, bm = dict(a), dict(b)
    out = ["  %s: only in %s" % (n, p) for n, p in
           [(n, path) for n, _ in a if n not in bm] + [(n, other) for n, _ in b if n not in am]]
    for n, attrs in a:
        if n in bm:
            out += ["  %s: %s %r, not %r" % (n, k, v, bm[n][k])
                    for k, v in attrs.items() if v != bm[n][k]]
    if not out and [n for n, _ in a] != [n for n, _ in b]:
        out.append("  the same members in another order")
    if not out:
        out.append("  the same members: the compression or the archive header differs")
    return out


def same_as(dist: str, other: str) -> List[str]:
    """Every file in DIST is byte-identical to the one of the same name in OTHER (#159)."""
    mine, theirs = sorted(os.listdir(dist)), sorted(os.listdir(other))
    out = ["%s: only in %s" % (n, d) for n, d in
           [(n, dist) for n in mine if n not in theirs] + [(n, other) for n in theirs if n not in mine]]
    for n in mine:
        if n in theirs and _sha256(os.path.join(dist, n)) != _sha256(os.path.join(other, n)):
            out.append("%s differs from %s's" % (n, other))
            if n.endswith((".whl", ".tar.gz")):
                out += _member_diff(os.path.join(dist, n), os.path.join(other, n))[:20]
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check the wheel and sdist in DIST.")
    p.add_argument("dist")
    p.add_argument("--commit", required=True, help="the commit wd2l/BUILD must name")
    p.add_argument("--version", help="default: wd2l/__init__.py's __version__")
    p.add_argument("--same-as", metavar="DIR", help="another build of the same commit")
    a = p.parse_args(argv)
    version = a.version or repo_version()
    probs = check(a.dist, version, a.commit)
    if a.same_as:
        probs += same_as(a.dist, a.same_as)
    for x in probs:
        print("dist: " + x)
    if not probs:
        print("dist: ok (wd2l %s, BUILD %s%s)" % (version, a.commit,
                                                   ", identical to " + a.same_as if a.same_as else ""))
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
