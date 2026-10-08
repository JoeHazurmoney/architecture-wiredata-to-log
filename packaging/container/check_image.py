#!/usr/bin/env python3
"""Hardening rules for the built image (docs/decisions/0004-container-base-image.md), checked on
its filesystem and its config:

* it runs as 65532, and its command isn't a shell;
* no shell and no package manager (pip comes with the base; the root filesystem is read-only
  and the user non-root, so it can't install anything);
* no setuid or setgid file, and nothing world-writable except sticky /tmp-like directories;
* the system crypto policy is FIPS;
* the RPM database is byte-identical to the base's, so the image adds no packages;
* wd2l's files match the wheel's RECORD hashes, and wd2l/BUILD names the commit;
* the labels name wd2l (not the base), the version, the commit, MIT and the exact base.

    check_image.py --rootfs DIR --base-rootfs DIR --config INSPECT.json --wheel WHL
                   --commit SHA --version V [--base-ref NAME:TAG@DIGEST]

The two rootfs directories come from `podman image mount`, inside `podman unshare`."""

import argparse
import base64
import csv
import glob
import hashlib
import io
import json
import os
import stat
import sys
import zipfile
from typing import Any, List, Optional, Sequence

SHELLS = ("bin/sh", "bin/bash", "usr/bin/sh", "usr/bin/bash", "bin/ash", "bin/dash",
          "usr/bin/dash", "bin/busybox", "usr/bin/busybox", "usr/bin/zsh")
PACKAGE_MANAGERS = ("usr/bin/dnf", "usr/bin/dnf5", "usr/bin/dnf-3", "usr/bin/microdnf",
                    "usr/bin/yum", "usr/bin/rpm", "usr/bin/apt", "usr/bin/apt-get",
                    "usr/bin/dpkg", "sbin/apk", "usr/bin/apk")
RPMDB = "usr/lib/sysimage/rpm/rpmdb.sqlite"
STICKY_OK = ("tmp", "var/tmp", "dev/shm")
REMOVED_LABELS = ("cpe", "com.redhat.component")
REQUIRED_LABELS = ("org.opencontainers.image.title", "org.opencontainers.image.version",
                   "org.opencontainers.image.revision", "org.opencontainers.image.source",
                   "org.opencontainers.image.licenses", "org.opencontainers.image.base.name",
                   "org.opencontainers.image.base.digest")


def _read(path: str) -> Optional[str]:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return None


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def check_config(inspect: Any, version: str, commit: str, base_ref: Optional[str]) -> List[str]:
    cfg = inspect[0] if isinstance(inspect, list) else inspect
    c = cfg.get("Config") or cfg.get("config") or {}
    out = []
    if str(c.get("User", "")).split(":")[0] != "65532":
        out.append("runs as %r, not 65532" % c.get("User"))
    cmd = list(c.get("Entrypoint") or []) + list(c.get("Cmd") or [])
    if cmd and os.path.basename(cmd[0]) in ("sh", "bash", "ash", "dash"):
        out.append("its command runs a shell: %s" % cmd)
    labels = c.get("Labels") or {}
    for k in REQUIRED_LABELS:
        if not labels.get(k):
            out.append("label %s is missing" % k)
    want = {"name": "wd2l", "org.opencontainers.image.licenses": "MIT",
            "org.opencontainers.image.version": version,
            "org.opencontainers.image.revision": commit}
    if base_ref:
        want["org.opencontainers.image.base.name"] = base_ref.split("@")[0]
        want["org.opencontainers.image.base.digest"] = base_ref.split("@")[1]
    for k, v in want.items():
        if labels.get(k) != v:
            out.append("label %s is %r, expected %r" % (k, labels.get(k), v))
    for k in sorted(labels):
        if k in REMOVED_LABELS or k.startswith("io.hummingbird-project."):
            out.append("label %s from the base is still there (the image would claim to be it)" % k)
    return out


def check_filesystem(root: str, base_root: str) -> List[str]:
    out = []
    for p in SHELLS:
        if os.path.lexists(os.path.join(root, p)):
            out.append("shell present: /" + p)
    for p in PACKAGE_MANAGERS:
        if os.path.lexists(os.path.join(root, p)):
            out.append("package manager present: /" + p)
    for dirpath, dirnames, filenames in os.walk(root):
        rel = os.path.relpath(dirpath, root)
        if rel.split(os.sep)[0] in ("proc", "sys"):
            dirnames[:] = []
            continue
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            st = os.lstat(path)
            relp = os.path.relpath(path, root).replace(os.sep, "/")
            if stat.S_ISLNK(st.st_mode):
                continue
            if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                out.append("setuid/setgid file: /" + relp)
            if st.st_mode & stat.S_IWOTH and not (
                    stat.S_ISDIR(st.st_mode) and st.st_mode & stat.S_ISVTX and relp in STICKY_OK):
                out.append("world-writable: /" + relp)
    policy = (_read(os.path.join(root, "etc/crypto-policies/config")) or "").strip()
    if policy != "FIPS":
        out.append("the crypto policy is %r, not FIPS" % policy)
    a, b = os.path.join(root, RPMDB), os.path.join(base_root, RPMDB)
    if not (os.path.isfile(a) and os.path.isfile(b)):
        out.append("the rpm database is missing in the image or the base")
    elif _sha256(a) != _sha256(b):
        out.append("the rpm database differs from the base's: the image changed packages")
    return out


def check_wheel_files(root: str, wheel: str, commit: str) -> List[str]:
    sites = glob.glob(os.path.join(root, "usr/lib/python3.*/site-packages"))
    if len(sites) != 1:
        return ["expected one site-packages under /usr/lib, found %d" % len(sites)]
    site, out = sites[0], []
    with zipfile.ZipFile(wheel) as z:
        record = [n for n in z.namelist() if n.endswith(".dist-info/RECORD")][0]
        rows = csv.reader(io.StringIO(z.read(record).decode("utf-8")))
        for row in rows:
            if len(row) < 2 or not row[0].startswith("wd2l/") or not row[1]:
                continue
            algo, _, digest = row[1].partition("=")
            want = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
            path = os.path.join(site, row[0])
            shown = "/" + os.path.relpath(path, root).replace(os.sep, "/")
            if not os.path.isfile(path):
                out.append("missing: " + shown)
                continue
            with open(path, "rb") as f:
                if hashlib.new(algo, f.read()).digest() != want:
                    out.append("changed: " + shown)
    build = (_read(os.path.join(site, "wd2l", "BUILD")) or "").strip()
    if build != commit:
        out.append("wd2l/BUILD is %r, not the commit %s" % (build, commit))
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Hardening checks for the wd2l image.")
    p.add_argument("--rootfs", required=True)
    p.add_argument("--base-rootfs", required=True)
    p.add_argument("--config", required=True, help="`podman image inspect` output")
    p.add_argument("--wheel", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--base-ref", help="the runtime base, NAME:TAG@DIGEST")
    a = p.parse_args(argv)
    with open(a.config) as f:
        inspect = json.load(f)
    probs = (check_config(inspect, a.version, a.commit, a.base_ref)
             + check_filesystem(a.rootfs, a.base_rootfs)
             + check_wheel_files(a.rootfs, a.wheel, a.commit))
    for x in probs:
        print("hardening: " + x)
    if not probs:
        print("hardening: ok")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
