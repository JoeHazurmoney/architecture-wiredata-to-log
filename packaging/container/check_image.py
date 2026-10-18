#!/usr/bin/env python3
"""Hardening rules for the built image (docs/decisions/0004-container-base-image.md), checked on
its filesystem and its config:

* it runs as 65532, and its command isn't a shell;
* no shell and no package manager, pip included (the base installs pip with ensurepip, not as an
  RPM; the Containerfile removes it);
* no setuid or setgid file, and nothing world-writable except sticky /tmp-like directories;
* the system crypto policy is FIPS;
* the RPM database is byte-identical to the base's, so the image adds no packages;
* wd2l's files match the wheel's RECORD hashes, and wd2l/BUILD names the commit;
* site-packages/wd2l holds nothing else but the compiled .pyc of those files;
* each of the wheel's console scripts is in /usr/bin: pip's script, executable, run by an
  interpreter the image has, importing and calling its entry point. No other wd2l* command;
* the labels name wd2l (not the base), the version, the commit, MIT and the exact base.

The comparison image on UBI 9 (--profile ubi9, #192) is checked the same way, except that by
design it keeps UBI 9's shell, package manager, setuid files and DEFAULT crypto policy: it is
there to show the difference. Its labels name wd2l-ubi9, and its RPM database is in /var/lib/rpm.

    check_image.py --rootfs DIR --base-rootfs DIR --config INSPECT.json --wheel WHL
                   --commit SHA --version V [--base-ref NAME:TAG@DIGEST] [--profile ubi9]

The two rootfs directories come from `podman image mount`, inside `podman unshare`."""

import argparse
import ast
import base64
import configparser
import csv
import glob
import hashlib
import io
import json
import os
import re
import stat
import sys
import zipfile
from typing import Any, Dict, List, Optional, Sequence

SHELLS = ("bin/sh", "bin/bash", "usr/bin/sh", "usr/bin/bash", "bin/ash", "bin/dash",
          "usr/bin/dash", "bin/busybox", "usr/bin/busybox", "usr/bin/zsh")
PACKAGE_MANAGERS = ("usr/bin/dnf", "usr/bin/dnf5", "usr/bin/dnf-3", "usr/bin/microdnf",
                    "usr/bin/yum", "usr/bin/rpm", "usr/bin/apt", "usr/bin/apt-get",
                    "usr/bin/dpkg", "sbin/apk", "usr/bin/apk")
PIP = ("usr/local/bin/pip*", "usr/bin/pip*", "usr/local/lib*/python3*/site-packages/pip",
       "usr/lib*/python3*/site-packages/pip")
RPMDB = "usr/lib/sysimage/rpm/rpmdb.sqlite"
RPMDBS = {"hardened": RPMDB, "ubi9": "var/lib/rpm/rpmdb.sqlite"}
NAMES = {"hardened": "wd2l", "ubi9": "wd2l-ubi9"}
STICKY_OK = ("tmp", "var/tmp", "dev/shm")
REMOVED_LABELS = ("cpe", "com.redhat.component")
REMOVED_UBI9_LABELS = ("io.k8s.display-name", "io.openshift.tags")      # "Red Hat Universal Base Image 9"
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


def check_config(inspect: Any, version: str, commit: str, base_ref: Optional[str],
                 profile: str = "hardened") -> List[str]:
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
    want = {"name": NAMES[profile], "org.opencontainers.image.licenses": "MIT",
            "org.opencontainers.image.version": version,
            "org.opencontainers.image.revision": commit}
    if base_ref:
        want["org.opencontainers.image.base.name"] = base_ref.split("@")[0]
        want["org.opencontainers.image.base.digest"] = base_ref.split("@")[1]
    for k, v in want.items():
        if labels.get(k) != v:
            out.append("label %s is %r, expected %r" % (k, labels.get(k), v))
    removed = REMOVED_LABELS + (REMOVED_UBI9_LABELS if profile == "ubi9" else ())
    for k in sorted(labels):
        if k in removed or k.startswith("io.hummingbird-project."):
            out.append("label %s from the base is still there (the image would claim to be it)" % k)
    return out


def check_filesystem(root: str, base_root: str, profile: str = "hardened") -> List[str]:
    out = []
    if profile == "ubi9":
        # By design (#192): UBI 9's shell, package manager, setuid files and policy stay.
        return out + check_no_pip(root) + check_rpmdb(root, base_root, RPMDBS[profile])
    for p in SHELLS:
        if os.path.lexists(os.path.join(root, p)):
            out.append("shell present: /" + p)
    for p in PACKAGE_MANAGERS:
        if os.path.lexists(os.path.join(root, p)):
            out.append("package manager present: /" + p)
    out += check_no_pip(root)
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
    return out + check_rpmdb(root, base_root, RPMDB)


def check_no_pip(root: str) -> List[str]:
    """wd2l installs nothing at run time, so no image keeps a package installer for Python."""
    return ["package manager present: /" + os.path.relpath(path, root).replace(os.sep, "/")
            for pattern in PIP for path in sorted(glob.glob(os.path.join(root, pattern)))]


def check_rpmdb(root: str, base_root: str, rpmdb: str) -> List[str]:
    a, b = os.path.join(root, rpmdb), os.path.join(base_root, rpmdb)
    if not (os.path.isfile(a) and os.path.isfile(b)):
        return ["the rpm database is missing in the image or the base"]
    if _sha256(a) != _sha256(b):
        return ["the rpm database differs from the base's: the image changed packages"]
    return []


def _in_image(root: str, path: str) -> Optional[str]:
    """PATH, an absolute path inside the image, as a path under ROOT with every symlink
    resolved inside the image too (the runner's own files never count), or None."""
    todo, done, hops = [p for p in path.split("/") if p], [], 0
    while todo:
        part = todo.pop(0)
        if part in (".", ".."):
            done = done[:-1] if part == ".." else done
            continue
        here = os.path.join(root, *done, part)
        if os.path.islink(here):
            hops += 1
            target = os.readlink(here)
            if hops > 40:
                return None
            todo = [p for p in target.split("/") if p] + todo
            done = [] if target.startswith("/") else done
        elif os.path.lexists(here):
            done.append(part)
        else:
            return None
    return os.path.join(root, *done)


def check_commands(root: str, scripts: Dict[str, str]) -> List[str]:
    """Each console script (name -> module:attr) is pip's script for it in /usr/bin."""
    out = []
    for name, target in sorted(scripts.items()):
        path, shown = os.path.join(root, "usr/bin", name), "/usr/bin/" + name
        if os.path.islink(path):
            out.append("%s is a symlink, not pip's script" % shown)
            continue
        if not os.path.isfile(path):
            out.append("missing command: " + shown)
            continue
        if not os.stat(path).st_mode & 0o111:
            out.append("not executable: " + shown)
        with open(path, "rb") as f:
            text = f.read().decode("utf-8", "replace")
        first = text.split("\n", 1)[0]
        interp = first[2:].split()[0] if first.startswith("#!") and first[2:].split() else ""
        real = _in_image(root, interp) if interp.startswith("/") else None
        if not (real and os.path.isfile(real)):
            out.append("%s runs %r, which the image doesn't have" % (shown, interp or first))
        module, _, attr = target.partition(":")
        head = attr.split(".")[0]
        try:
            tree = ast.parse(text)
        except SyntaxError:
            tree = ast.parse("")
        imported = any(isinstance(n, ast.ImportFrom) and n.module == module and n.level == 0
                       and [a.name for a in n.names] == [head] and n.names[0].asname is None
                       for n in ast.walk(tree))
        called = any(isinstance(n, ast.Call) and isinstance(n.func, (ast.Name, ast.Attribute))
                     and ast.unparse(n.func) == attr for n in ast.walk(tree))
        if not (imported and called):
            out.append("%s doesn't run %s" % (shown, target))
    for path in sorted(glob.glob(os.path.join(root, "usr/bin/wd2l*"))):
        if os.path.basename(path) not in scripts:
            out.append("not in the wheel's entry points: /usr/bin/" + os.path.basename(path))
    return out


def check_wheel_files(root: str, wheel: str, commit: str) -> List[str]:
    sites = glob.glob(os.path.join(root, "usr/lib/python3.*/site-packages"))
    if len(sites) != 1:
        return ["expected one site-packages under /usr/lib, found %d" % len(sites)]
    site, out = sites[0], []
    with zipfile.ZipFile(wheel) as z:
        record = [n for n in z.namelist() if n.endswith(".dist-info/RECORD")][0]
        rows = list(csv.reader(io.StringIO(z.read(record).decode("utf-8"))))
        ep = record[:-len("RECORD")] + "entry_points.txt"
        cp = configparser.ConfigParser(delimiters=("=",), interpolation=None)
        cp.optionxform = str                     # keep the command names' case
        cp.read_string(z.read(ep).decode("utf-8") if ep in z.namelist() else "")
        scripts = dict(cp["console_scripts"]) if cp.has_section("console_scripts") else {}
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
    # Nothing beside the wheel's files but their .pyc (the Containerfile's compileall).
    files = {r[0] for r in rows if r and r[0].startswith("wd2l/")}
    dirs = {os.path.dirname(f) for f in files}
    dirs |= {d + "/__pycache__" for d in dirs}
    for dirpath, dirnames, filenames in os.walk(os.path.join(site, "wd2l")):
        for name in sorted(dirnames + filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, site).replace(os.sep, "/")
            pyc = re.match(r"^(.*)/__pycache__/([^/.]+)\.cpython-\d+\.pyc$", rel)
            shown = "/" + os.path.relpath(path, root).replace(os.sep, "/")
            if os.path.islink(path):             # the hashes above read through it
                out.append("a symlink, not the wheel's file: " + shown)
            elif not (rel in (dirs if os.path.isdir(path) else files)
                      or (pyc and "%s/%s.py" % pyc.groups() in files)):
                out.append("not in the wheel: " + shown)
    return out + check_commands(root, scripts)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Hardening checks for the wd2l image.")
    p.add_argument("--rootfs", required=True)
    p.add_argument("--base-rootfs", required=True)
    p.add_argument("--config", required=True, help="`podman image inspect` output")
    p.add_argument("--wheel", required=True)
    p.add_argument("--commit", required=True)
    p.add_argument("--version", required=True)
    p.add_argument("--base-ref", help="the runtime base, NAME:TAG@DIGEST")
    p.add_argument("--profile", choices=sorted(NAMES), default="hardened",
                   help="ubi9: the comparison image (keeps UBI 9's shell, package manager and policy)")
    a = p.parse_args(argv)
    with open(a.config) as f:
        inspect = json.load(f)
    probs = (check_config(inspect, a.version, a.commit, a.base_ref, a.profile)
             + check_filesystem(a.rootfs, a.base_rootfs, a.profile)
             + check_wheel_files(a.rootfs, a.wheel, a.commit))
    for x in probs:
        print("hardening: " + x)
    if not probs:
        print("hardening: ok")
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
