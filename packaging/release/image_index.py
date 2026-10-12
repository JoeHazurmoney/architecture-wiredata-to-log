#!/usr/bin/env python3
"""Checks the image index publish.yml pushed: an OCI index whose digest is the one pushed,
holding exactly linux/amd64 and linux/arm64, each the image that platform's build tested (its
config digest is the tested image ID). Writes digest_amd64= and digest_arm64= for later steps.

    image_index.py --index index.json --digest sha256:... --manifest amd64=m.json
        --manifest arm64=m.json --build-info amd64=b.json --build-info arm64=b.json
        [--github-output FILE]"""

import argparse
import hashlib
import json
import sys
from typing import Dict, List, Optional, Sequence, Tuple

ARCHES = ("amd64", "arm64")
OCI_INDEX = "application/vnd.oci.image.index.v1+json"


def _sha(b: bytes) -> str:
    return "sha256:" + hashlib.sha256(b).hexdigest()


def check(index: bytes, digest: str, manifests: Dict[str, bytes],
          image_ids: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
    """({arch: platform image digest}, problems) for the index and each platform's manifest."""
    probs: List[str] = []
    if _sha(index) != digest:
        probs.append("the index fetched (%s) is not the digest pushed (%s)" % (_sha(index), digest))
    doc = json.loads(index)
    if doc.get("mediaType") != OCI_INDEX:
        probs.append("not an OCI image index: %s" % doc.get("mediaType"))
    found = {(m.get("platform") or {}).get("architecture"): m["digest"]
             for m in doc.get("manifests", []) if (m.get("platform") or {}).get("os") == "linux"}
    if set(found) - set(ARCHES):
        probs.append("the index also holds %s" % ", ".join(
            "linux/%s" % a for a in sorted(set(found) - set(ARCHES))))
    out: Dict[str, str] = {}
    for arch in ARCHES:
        if arch not in found:
            probs.append("no linux/%s image in the index" % arch)
            continue
        m = manifests.get(arch, b"")
        if _sha(m) != found[arch]:
            probs.append("%s: the manifest fetched is not %s" % (arch, found[arch]))
            continue
        cfg = json.loads(m).get("config", {}).get("digest")
        if cfg != "sha256:" + image_ids.get(arch, ""):
            probs.append("%s: the image pushed (config %s) is not the one tested (%s)"
                         % (arch, cfg, image_ids.get(arch)))
        out[arch] = found[arch]
    return out, probs


def _pairs(items: Sequence[str]) -> Dict[str, str]:
    return dict(x.split("=", 1) for x in items)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Check the pushed image index.")
    p.add_argument("--index", required=True)
    p.add_argument("--digest", required=True)
    p.add_argument("--manifest", action="append", default=[], metavar="ARCH=FILE")
    p.add_argument("--build-info", action="append", default=[], metavar="ARCH=FILE")
    p.add_argument("--github-output")
    a = p.parse_args(argv)
    with open(a.index, "rb") as f:
        index = f.read()
    manifests = {}
    for arch, path in _pairs(a.manifest).items():
        with open(path, "rb") as f:
            manifests[arch] = f.read()
    ids = {}
    for arch, path in _pairs(a.build_info).items():
        with open(path) as f:
            ids[arch] = json.load(f)["image_id"]
    got, probs = check(index, a.digest, manifests, ids)
    for x in probs:
        print("image-index: " + x, file=sys.stderr)
    if probs:
        return 1
    lines = ["digest_%s=%s" % (arch, d) for arch, d in sorted(got.items())]
    print("\n".join(lines))
    if a.github_output:
        with open(a.github_output, "a") as f:
            f.write("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
