#!/usr/bin/env python3
"""Checks a wd2l release offline, from its files alone: retrieve, not rebuild
(docs/decisions/0008-release-manifest.md). Ships in every release as
wd2l-<version>-verify-release.py. Python 3 standard library only, plus the `cosign` and `git`
commands for the checks that need them.

    python3 wd2l-<version>-verify-release.py [--dir DIR] --key cosign.pub
                                              [--image-tar wd2l-<version>-image-<arch>-oci.tar]

Use a cosign.pub obtained from a trusted channel, not the copy among the release files.

  1. signature   SHA256SUMS is signed by the release key (cosign verify-blob)
  2. checksums   every file SHA256SUMS lists is present and matches
  3. manifest    every deliverable the manifest lists matches SHA256SUMS, size and digest
  4. source      the source bundle is complete, and its tag is the manifest's commit
  5. image       (with --image-tar) the image's signature verifies offline

One line per check; exit 0 only if none failed. --skip-signature is for a dry run's files,
which have no signature."""

import argparse
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Dict, List, Optional, Sequence, Tuple

Result = Tuple[str, str, str]      # (ok | FAIL | skip, check, detail)


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def read_sums(path: str) -> Dict[str, str]:
    sums = {}
    with open(path) as f:
        for line in f:
            if line.strip():
                h, name = line.rstrip("\n").split(None, 1)
                sums[name.lstrip("*")] = h
    return sums


def run(cmd: Sequence[str], cwd: Optional[str] = None) -> Tuple[int, str]:
    p = subprocess.run(list(cmd), cwd=cwd, capture_output=True, text=True)
    lines = (p.stderr or p.stdout).strip().splitlines()
    return p.returncode, lines[-1] if lines else ""


def check_signature(d: str, key: Optional[str], cosign: str, skip: bool) -> Result:
    if skip:
        return ("skip", "signature", "--skip-signature")
    bundle = os.path.join(d, "SHA256SUMS.sigstore.json")
    if not key:
        return ("FAIL", "signature", "no --key given")
    if not os.path.exists(bundle):
        return ("FAIL", "signature", "SHA256SUMS.sigstore.json is missing")
    if not shutil.which(cosign):
        return ("FAIL", "signature", "%s not found (install cosign, or --cosign PATH)" % cosign)
    code, out = run([cosign, "verify-blob", "--key", key, "--insecure-ignore-tlog", "--bundle", bundle,
                     os.path.join(d, "SHA256SUMS")])
    return ("ok", "signature", "SHA256SUMS signed by the release key") if code == 0 else \
        ("FAIL", "signature", out or "cosign verify-blob failed")


def check_checksums(d: str, sums: Dict[str, str]) -> Result:
    bad = []
    for name, h in sorted(sums.items()):
        p = os.path.join(d, name)
        if not os.path.exists(p):
            bad.append("%s missing" % name)
        elif sha256(p) != h:
            bad.append("%s differs" % name)
    if bad:
        return ("FAIL", "checksums", "; ".join(bad))
    return ("ok", "checksums", "%d files match SHA256SUMS" % len(sums))


def check_manifest(d: str, man: Dict, man_name: str, sums: Dict[str, str]) -> Result:
    bad = []
    if man_name not in sums:
        bad.append("SHA256SUMS doesn't list %s" % man_name)
    for x in man.get("deliverables", []):
        p = os.path.join(d, x["name"])
        if sums.get(x["name"]) != x["sha256"]:
            bad.append("%s: not as in SHA256SUMS" % x["name"])
        elif not os.path.exists(p) or os.path.getsize(p) != x["size"]:
            bad.append("%s: missing or wrong size" % x["name"])
    if bad:
        return ("FAIL", "manifest", "; ".join(bad))
    return ("ok", "manifest", "%d deliverables match, commit %s" % (
        len(man["deliverables"]), man["source"]["commit"]))


def check_source(d: str, man: Dict, git: str) -> Result:
    bundles = glob.glob(os.path.join(d, "wd2l-*-source.bundle"))
    if len(bundles) != 1:
        return ("FAIL", "source", "expected one wd2l-*-source.bundle, found %d" % len(bundles))
    if not shutil.which(git):
        return ("FAIL", "source", "%s not found" % git)
    code, out = run([git, "bundle", "verify", bundles[0]])
    if code:
        return ("FAIL", "source", "git bundle verify: %s" % out)
    ref = "HEAD" if man["release"]["dry_run"] else "refs/tags/%s" % man["release"]["tag"]
    with tempfile.TemporaryDirectory() as tmp:
        code, out = run([git, "clone", "-q", "--no-checkout", bundles[0], os.path.join(tmp, "src")])
        if code:
            return ("FAIL", "source", "git clone: %s" % out)
        p = subprocess.run([git, "rev-parse", "--verify", "-q", ref + "^{commit}"],
                           cwd=os.path.join(tmp, "src"), capture_output=True, text=True)
        got = p.stdout.strip()
    if got != man["source"]["commit"]:
        return ("FAIL", "source", "%s in the bundle is %s, the manifest says %s" % (
            ref, got or "missing", man["source"]["commit"]))
    return ("ok", "source", "the bundle's %s is the manifest's commit" % ref.replace("refs/tags/", ""))


def check_image(d: str, tar: Optional[str], key: Optional[str], cosign: str) -> Result:
    if not tar:
        return ("skip", "image", "no --image-tar")
    if not key or not shutil.which(cosign):
        return ("FAIL", "image", "needs --key and cosign")
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(os.path.join(d, tar) if not os.path.isabs(tar) else tar) as t:
            for m in t.getmembers():      # refuse paths outside the directory
                if m.name.startswith("/") or ".." in m.name.split("/"):
                    return ("FAIL", "image", "unsafe path in the tar: %s" % m.name)
            try:
                t.extractall(tmp, filter="data")
            except TypeError:             # a Python without extraction filters
                t.extractall(tmp)
        code, out = run([cosign, "verify", "--key", key, "--insecure-ignore-tlog", "--local-image",
                         os.path.join(tmp, "wd2l-oci")])
    return ("ok", "image", "%s: signature verifies" % os.path.basename(tar)) if code == 0 else \
        ("FAIL", "image", out or "cosign verify failed")


def verify(d: str, key: Optional[str], image_tar: Optional[str] = None, skip_signature: bool = False,
           cosign: str = "cosign", git: str = "git") -> List[Result]:
    mans = glob.glob(os.path.join(d, "wd2l-*-release-manifest.json"))
    if len(mans) != 1 or not os.path.exists(os.path.join(d, "SHA256SUMS")):
        return [("FAIL", "files", "expected SHA256SUMS and one wd2l-*-release-manifest.json in %s" % d)]
    with open(mans[0]) as f:
        man = json.load(f)
    sums = read_sums(os.path.join(d, "SHA256SUMS"))
    return [check_signature(d, key, cosign, skip_signature), check_checksums(d, sums),
            check_manifest(d, man, os.path.basename(mans[0]), sums), check_source(d, man, git),
            check_image(d, image_tar, key, cosign)]


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check a wd2l release offline, from its files alone.")
    p.add_argument("--dir", default=".", help="the directory of release files (default: here)")
    p.add_argument("--key", help="cosign.pub, from a trusted channel")
    p.add_argument("--image-tar", help="also check this OCI image tar's signature")
    p.add_argument("--skip-signature", action="store_true", help="a dry run's files: no signature")
    p.add_argument("--cosign", default="cosign")
    p.add_argument("--git", default="git")
    a = p.parse_args(argv)
    results = verify(a.dir, a.key, a.image_tar, a.skip_signature, a.cosign, a.git)
    for status, check, detail in results:
        print("%-4s  %-9s  %s" % (status, check, detail))
    failed = [r for r in results if r[0] == "FAIL"]
    print("release: %s" % ("FAILED (%d checks)" % len(failed) if failed else "verified"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
