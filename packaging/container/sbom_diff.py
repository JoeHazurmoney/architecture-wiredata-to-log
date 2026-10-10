#!/usr/bin/env python3
"""The image adds wd2l to its base and nothing else: compares the SPDX SBOMs Syft makes of the
base and of the image, package by package (by purl). Ignored: packages without a purl, and the
package the document DESCRIBES (Syft's entry for the image itself, a pkg:oci/... purl that is
always different).

    sbom_diff.py BASE.spdx.json IMAGE.spdx.json [--allow PREFIX ...] [--allow-removed PREFIX ...]
The default --allow is pkg:pypi/wd2l@, and the default --allow-removed pkg:pypi/pip@ (the
Containerfile removes the base's pip). Exit 1 when anything else was added or removed."""

import argparse
import json
import sys
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple


def purls(doc: Dict[str, Any]) -> Set[str]:
    described = set(doc.get("documentDescribes") or [])
    described |= {r.get("relatedSpdxElement") for r in doc.get("relationships") or []
                  if r.get("spdxElementId") == "SPDXRef-DOCUMENT"
                  and r.get("relationshipType") == "DESCRIBES"}
    out = set()
    for p in doc.get("packages") or []:
        if p.get("SPDXID") in described:
            continue
        for ref in p.get("externalRefs") or []:
            if ref.get("referenceType") == "purl":
                out.add(ref["referenceLocator"])
    return out


def diff(base: Dict[str, Any], image: Dict[str, Any], allow: Sequence[str],
         allow_removed: Sequence[str] = ()) -> Tuple[List[str], List[str]]:
    b, i = purls(base), purls(image)
    added = sorted(p for p in i - b if not any(p.startswith(a) for a in allow))
    return added, sorted(p for p in b - i if not any(p.startswith(a) for a in allow_removed))


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Only wd2l may be added to the base.")
    p.add_argument("base")
    p.add_argument("image")
    p.add_argument("--allow", action="append", default=None)
    p.add_argument("--allow-removed", action="append", default=None)
    a = p.parse_args(argv)
    allow = a.allow or ["pkg:pypi/wd2l@"]
    allow_removed = a.allow_removed or ["pkg:pypi/pip@"]
    with open(a.base) as f:
        base = json.load(f)
    with open(a.image) as f:
        image = json.load(f)
    added, removed = diff(base, image, allow, allow_removed)
    for x in added:
        print("sbom: added to the base: " + x)
    for x in removed:
        print("sbom: missing from the image: " + x)
    if not (added or removed):
        print("sbom: ok, the image is the base plus %s, less %s"
              % (", ".join(allow), ", ".join(allow_removed)))
    return 1 if added or removed else 0


if __name__ == "__main__":
    sys.exit(main())
