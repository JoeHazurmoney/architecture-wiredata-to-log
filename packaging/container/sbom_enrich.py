#!/usr/bin/env python3
"""Completes the SPDX and CycloneDX SBOMs Syft makes of the image, in place
(docs/decisions/0009-sbom-content.md). Syft leaves gaps that a reviewer finds:

* No supplier on any component. Each one gets the supplier its package ID names (SUPPLIERS).
  A component no rule covers fails the run, so a new dependency can't arrive unattributed.
* wd2l's own files aren't linked to wd2l (Syft reads its RECORD but links only the launchers in
  /usr/bin). wd2l is given every file in the wheel's RECORD, each hash checked against it, every
  file in its dist-info directory, and the compiled .pyc of its modules. Anything else in its
  directory fails the run.
* Syft names its maker as the SBOM's author, and says nothing of when in the life cycle the SBOM
  was made: the author becomes the project, with Syft named as the tool, and the generation
  context is recorded (CycloneDX's "post-build" lifecycle, an SPDX comment).
* Syft runs with every file cataloged (SYFT_FILE_METADATA_SELECTION=all), which in SPDX also
  lists each directory and symlink, with no checksum. Those entries are dropped.

The SPDX document namespace becomes the repository's, with the version, platform and digest,
instead of Syft's, with a random UUID.

    sbom_enrich.py --spdx S.json --cdx C.json --wheel W.whl --arch ARCH --repo-url URL
Exit 1 with a line for each gap that remains."""

import argparse
import base64
import binascii
import hashlib
import json
import posixpath
import re
import sys
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

PROJECT = "wd2l project"
# The supplier of each component, by its package ID's prefix: who built it and ships its fixes.
# The base's RPMs are Red Hat's; Syft has named their namespace both ways.
SUPPLIERS = (("pkg:rpm/redhat/", "Red Hat, Inc."), ("pkg:rpm/hummingbird/", "Red Hat, Inc."),
             ("pkg:pypi/wd2l@", PROJECT))
# CycloneDX's operating-system component has no package ID: its supplier, by distribution
# (rhel: UBI 9, the comparison image).
OS_SUPPLIERS = {"hummingbird": "Red Hat, Inc.", "rhel": "Red Hat, Inc."}
PURL_PACKAGE = "pkg:pypi/wd2l@"


def supplier_for(purl: str) -> Optional[str]:
    return next((s for prefix, s in SUPPLIERS if purl.startswith(prefix)), None)


def purl_of(pkg: Dict[str, Any]) -> str:
    return next((r["referenceLocator"] for r in pkg.get("externalRefs") or []
                 if r.get("referenceType") == "purl"), "")


def record(wheel: str) -> Tuple[str, Dict[str, str]]:
    """The wheel's dist-info directory, and its RECORD: each path (relative to site-packages)
    and its SHA-256 in hex, empty for the entries RECORD lists without one (RECORD itself)."""
    with zipfile.ZipFile(wheel) as z:
        name = next(n for n in z.namelist() if re.fullmatch(r"[^/]+\.dist-info/RECORD", n))
        rows = z.read(name).decode("utf-8").splitlines()
    out = {}
    for row in rows:
        if not row.strip():
            continue
        path, digest = row.split(",")[:2]
        hexd = ""
        if digest.startswith("sha256="):
            b64 = digest[len("sha256="):]
            hexd = binascii.hexlify(base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))).decode()
        out[path] = hexd
    return name.split("/")[0], out


def described(doc: Dict[str, Any]) -> Set[str]:
    return {r["relatedSpdxElement"] for r in doc.get("relationships") or []
            if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES"}


def sha256_of(f: Dict[str, Any]) -> str:
    return next((c["checksumValue"] for c in f.get("checksums") or [] if c.get("algorithm") == "SHA256"), "")


def verification_code(sha1s: Sequence[str]) -> str:
    """SPDX 2.3, 7.9: SHA-1 over the package's file SHA-1s, sorted and concatenated."""
    return hashlib.sha1("".join(sorted(sha1s)).encode("ascii")).hexdigest()


def complete_spdx(doc: Dict[str, Any], dist_info: str, rec: Dict[str, str], arch: str,
                  repo_url: str) -> Tuple[List[str], List[str]]:
    """Completes doc in place. Returns (what was done, the gaps that remain)."""
    done: List[str] = []
    gaps: List[str] = []
    rels = doc.setdefault("relationships", [])
    referenced = {r["spdxElementId"] for r in rels} | {r["relatedSpdxElement"] for r in rels}

    # Directories and symlinks: no SHA-256 and, from Syft, no relationships.
    keep, dropped = [], 0
    for f in doc.get("files") or []:
        if sha256_of(f):
            keep.append(f)
        elif f["SPDXID"] in referenced:
            keep.append(f)
            gaps.append("a file without a SHA-256 has relationships: " + f.get("fileName", "?"))
        else:
            dropped += 1
    doc["files"] = keep
    done.append("dropped %d entries without a SHA-256 (directories and links)" % dropped)

    # Suppliers, and the project as the supplier of the image itself.
    roots = described(doc)
    tally: Dict[str, int] = {}
    for p in doc.get("packages") or []:
        s = PROJECT if p["SPDXID"] in roots else supplier_for(purl_of(p))
        if not s:
            gaps.append("no supplier rule for %s %s (%s)" % (p.get("name"), p.get("versionInfo"),
                                                             purl_of(p) or "no package ID"))
            continue
        p["supplier"] = "Organization: " + s
        tally[s] = tally.get(s, 0) + 1
    done.append("suppliers: " + ", ".join("%s %d" % kv for kv in sorted(tally.items())))

    # wd2l's files.
    by_name = {f["fileName"].lstrip("/"): f for f in doc["files"]}
    pkg = next((p for p in doc.get("packages") or [] if purl_of(p).startswith(PURL_PACKAGE)), None)
    rec_file = next((n for n in by_name if n.endswith("/" + dist_info + "/RECORD")), None)
    if pkg is None or rec_file is None:
        gaps.append("wd2l or its RECORD is not in the SBOM")
    else:
        site = rec_file[:-len(dist_info + "/RECORD") - 1]
        owned = {r["relatedSpdxElement"] for r in rels
                 if r["spdxElementId"] == pkg["SPDXID"] and r.get("relationshipType") == "CONTAINS"}
        mine: Dict[str, Dict[str, Any]] = {}
        listed = set()
        for path, hexd in rec.items():
            full = posixpath.normpath(posixpath.join(site, path))
            listed.add(full)
            f = by_name.get(full)
            if f is None:
                gaps.append("in wd2l's RECORD but not in the SBOM: /" + full)
            elif hexd and sha256_of(f) != hexd:
                gaps.append("not the wheel's file (SHA-256 differs): /" + full)
            else:
                mine[full] = f
        tops = {p.split("/")[0] for p in rec if "/" in p and not p.startswith(("..", dist_info + "/"))}
        modules = {posixpath.splitext(posixpath.basename(p))[0] + "|" + posixpath.dirname(p)
                   for p in rec if p.endswith(".py")}
        for name, f in by_name.items():
            if not name.startswith(site + "/") or name in listed:
                continue
            rel = name[len(site) + 1:]
            if rel.startswith(dist_info + "/"):
                mine[name] = f                      # written by the installer (INSTALLER, REQUESTED…)
            elif rel.split("/")[0] in tops:
                m = re.fullmatch(r"(.*)/__pycache__/([^/.]+)\.cpython-\d+(?:\.opt-\d)?\.pyc", rel)
                if m and m.group(2) + "|" + m.group(1) in modules:
                    mine[name] = f
                else:
                    gaps.append("in wd2l's directory but not in its RECORD: /" + name)
        added = 0
        for f in mine.values():
            if f["SPDXID"] not in owned:
                rels.append({"spdxElementId": pkg["SPDXID"], "relatedSpdxElement": f["SPDXID"],
                             "relationshipType": "CONTAINS"})
                owned.add(f["SPDXID"])
                added += 1
        ids = {f["SPDXID"]: f for f in doc["files"]}
        sha1s = [next((c["checksumValue"] for c in ids[i].get("checksums") or [] if c["algorithm"] == "SHA1"), "")
                 for i in owned if i in ids]
        pkg["filesAnalyzed"] = True
        pkg["packageVerificationCode"] = {"packageVerificationCodeValue": verification_code(sha1s)}
        done.append("wd2l: %d files (%d newly linked; every RECORD hash checked)" % (len(owned), added))

    # The author, the generation context and a namespace of our own.
    info = doc.setdefault("creationInfo", {})
    tools = [c for c in info.get("creators") or [] if c.startswith("Tool: ")]
    info["creators"] = ["Organization: " + PROJECT] + tools
    info["comment"] = ("Generated after the build (post-build), from the built container image for "
                       "linux/%s, by %s; completed by packaging/container/sbom_enrich.py."
                       % (arch, ", ".join(t[len("Tool: "):] for t in tools) or "Syft"))
    root = next((p for p in doc.get("packages") or [] if p["SPDXID"] in roots), None)
    digest = next((c["checksumValue"] for c in (root or {}).get("checksums") or []
                   if c.get("algorithm") == "SHA256"), "")
    if not (root and digest):
        gaps.append("the image's digest is not in the SBOM")
    else:
        doc["documentNamespace"] = "%s/sbom/%s-%s-%s-%s" % (repo_url.rstrip("/"), root["name"].split("/")[-1],
                                                             root.get("versionInfo"), arch, digest)
    file_ids = {f["SPDXID"] for f in doc["files"]}
    in_a_package = {r["relatedSpdxElement"] for r in rels
                    if r.get("relationshipType") == "CONTAINS" and r["relatedSpdxElement"] in file_ids}
    done.append("%d files, %d of them in no package" % (len(file_ids), len(file_ids - in_a_package)))
    return done, gaps


def complete_cdx(doc: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    done: List[str] = []
    gaps: List[str] = []
    tally: Dict[str, int] = {}
    for c in doc.get("components") or []:
        if c.get("type") == "file":
            continue
        s = OS_SUPPLIERS.get(c.get("name", "")) if c.get("type") == "operating-system" \
            else supplier_for(c.get("purl") or "")
        if not s:
            gaps.append("no supplier rule for %s %s (%s)" % (c.get("name"), c.get("version"),
                                                             c.get("purl") or c.get("type")))
            continue
        c["supplier"] = {"name": s}
        tally[s] = tally.get(s, 0) + 1
    done.append("suppliers: " + ", ".join("%s %d" % kv for kv in sorted(tally.items())))
    meta = doc.setdefault("metadata", {})
    meta["authors"] = [{"name": PROJECT}]
    meta["manufacturer"] = {"name": PROJECT}
    meta["supplier"] = {"name": PROJECT}
    meta["lifecycles"] = [{"phase": "post-build"}]
    if "component" in meta:
        meta["component"]["supplier"] = {"name": PROJECT}
    return done, gaps


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Complete Syft's SBOMs of the image, in place.")
    p.add_argument("--spdx", required=True)
    p.add_argument("--cdx", required=True)
    p.add_argument("--wheel", required=True)
    p.add_argument("--arch", required=True)
    p.add_argument("--repo-url", required=True)
    a = p.parse_args(argv)
    dist_info, rec = record(a.wheel)
    gaps: List[str] = []
    for path, fn in ((a.spdx, lambda d: complete_spdx(d, dist_info, rec, a.arch, a.repo_url)),
                     (a.cdx, complete_cdx)):
        with open(path) as f:
            doc = json.load(f)
        done, g = fn(doc)
        with open(path, "w") as f:
            json.dump(doc, f, separators=(",", ":"))
        for line in done:
            print("sbom %s: %s" % (path, line))
        gaps += ["%s: %s" % (path, x) for x in g]
    for x in gaps:
        print("sbom: gap: " + x)
    return 1 if gaps else 0


if __name__ == "__main__":
    sys.exit(main())
