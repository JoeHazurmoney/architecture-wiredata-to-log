#!/usr/bin/env python3
"""Cross-checks what the base-verify job collected for each base image, and writes
base-image-record.json: the exact images a build stood on, and how each was checked
(docs/decisions/0006-release-artifacts-and-signing.md).

EVIDENCE holds, for FROM number i of the Containerfile (0 = the first):
  index-<i>.json       the image index, raw bytes (skopeo inspect --raw)
  config-<i>.json      the amd64 image config (skopeo inspect --config)
  signature-<i>.json   `cosign verify` output with keys/redhat-release3.pub
  provenance-<i>.json  `cosign verify-attestation --type slsaprovenance` output with
                       keys/hummingbird-ci.pub, one JSON object per line
  sbom-<i>.spdx.json   the base's SPDX SBOM, from quay.io/hummingbird
cosign has already verified the signatures (it exits non-zero otherwise). This script checks
that they are about the pinned digests, so nothing else could have been verified instead.

    base_record.py --containerfile FILE --evidence DIR --keys DIR --out FILE"""

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_containerfile  # noqa: E402  (a sibling script, not a package)

REGISTRY = "registry.access.redhat.com/hi/"
MIRROR = "quay.io/hummingbird/"
SIGNING_KEY, PROVENANCE_KEY = "redhat-release3.pub", "hummingbird-ci.pub"


def _sha256(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def platform_digests(index: Dict[str, Any]) -> Dict[str, str]:
    return {m["platform"]["architecture"]: m["digest"] for m in index.get("manifests", [])
            if m.get("platform", {}).get("os", "linux") == "linux"}


def provenance_subjects(text: str) -> Tuple[Set[str], Set[str]]:
    """(subject digests, predicate types) of the attestations in cosign's output."""
    digests, types = set(), set()
    for line in text.splitlines():
        if not line.strip():
            continue
        env = json.loads(line)
        st = json.loads(base64.b64decode(env["payload"]))
        types.add(st.get("predicateType", ""))
        for s in st.get("subject", []):
            if "sha256" in s.get("digest", {}):
                digests.add("sha256:" + s["digest"]["sha256"])
    return digests, types


def _entry(i: int, f: Dict[str, Any], ev: str, probs: List[str]) -> Dict[str, Any]:
    def path(name: str) -> Optional[str]:
        p = os.path.join(ev, name % i)
        if not os.path.isfile(p):
            probs.append("%s: missing %s" % (f["ref"], name % i))
            return None
        return p

    digest = f["digest"]
    out: Dict[str, Any] = {"ref": f["ref"], "stage": f["stage"] or "runtime",
                           "index_digest": digest,
                           "mirror": MIRROR + f["name"][len(REGISTRY):] + "@" + digest}
    p = path("index-%d.json")
    if p:
        got = "sha256:" + _sha256(p)
        if got != digest:
            probs.append("%s: the index fetched (%s) is not the pinned digest" % (f["ref"], got))
        with open(p) as fh:
            out["platforms"] = platform_digests(json.load(fh))
    known = {digest} | set(out.get("platforms", {}).values())
    p = path("config-%d.json")
    if p:
        with open(p) as fh:
            labels = (json.load(fh).get("config") or {}).get("Labels") or {}
        out["version"], out["release"] = labels.get("version"), labels.get("release")
        out["source_image"] = "%s:%s-source" % (f["name"], labels.get("release"))
        if str(f["tag"]).endswith(("-fips", "-fips-builder")) and \
                labels.get("io.hummingbird-project.variant.fips") != "true":
            probs.append("%s: tagged FIPS but its config has no FIPS variant label" % f["ref"])
    p = path("signature-%d.json")
    if p:
        with open(p) as fh:
            text = fh.read()
        ok = digest in text
        if not ok:
            probs.append("%s: the Red Hat signature verified is not for %s" % (f["ref"], digest))
        out["signature"] = {"key": SIGNING_KEY, "verified": ok, "evidence_sha256": _sha256(p)}
    p = path("provenance-%d.json")
    if p:
        with open(p) as fh:
            subjects, types = provenance_subjects(fh.read())
        if not subjects & known:
            probs.append("%s: the provenance is about %s, not this image" % (f["ref"], sorted(subjects)))
        out["provenance"] = {"key": PROVENANCE_KEY, "predicate_type": ",".join(sorted(types)),
                             "subjects": sorted(subjects), "evidence_sha256": _sha256(p)}
    p = path("sbom-%d.spdx.json")
    if p:
        with open(p) as fh:
            sbom = json.load(fh)
        if not str(sbom.get("spdxVersion", "")).startswith("SPDX-"):
            probs.append("%s: the SBOM is not SPDX" % f["ref"])
        out["sbom"] = {"file": os.path.basename(p), "sha256": _sha256(p),
                       "packages": len(sbom.get("packages", []))}
    return out


def record(froms: List[Dict[str, Any]], evidence: str, keys: str,
           now: str) -> Tuple[Dict[str, Any], List[str]]:
    probs: List[str] = []
    rec: Dict[str, Any] = {"created": now, "keys": {}, "images": []}
    for k in (SIGNING_KEY, PROVENANCE_KEY):
        p = os.path.join(keys, k)
        rec["keys"][k] = _sha256(p) if os.path.isfile(p) else None
        if rec["keys"][k] is None:
            probs.append("missing key %s" % p)
    for i, f in enumerate(froms):
        if not f.get("digest"):
            probs.append("%s: not pinned" % f["ref"])
            continue
        rec["images"].append(_entry(i, f, evidence, probs))
    return rec, probs


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Write base-image-record.json from the evidence.")
    p.add_argument("--containerfile", default=check_containerfile.DEFAULT)
    p.add_argument("--evidence", required=True)
    p.add_argument("--keys", default=os.path.join(HERE, "keys"))
    p.add_argument("--out", required=True)
    a = p.parse_args(argv)
    with open(a.containerfile) as fh:
        froms = check_containerfile.froms(fh.read())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    rec, probs = record(froms, a.evidence, a.keys, now)
    for x in probs:
        print("base: " + x, file=sys.stderr)
    with open(a.out, "w") as fh:
        json.dump(rec, fh, indent=1, sort_keys=True)
    if not probs:
        print("base: ok, %d images verified and recorded in %s" % (len(rec["images"]), a.out))
    return 1 if probs else 0


if __name__ == "__main__":
    sys.exit(main())
