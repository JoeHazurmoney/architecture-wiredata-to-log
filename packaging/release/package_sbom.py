#!/usr/bin/env python3
"""SBOMs of the release's own packages (#190, docs/decisions/0009-sbom-content.md): a set of RPMs
(one per EL version), and the Python package (the wheel and the sdist), each in SPDX 2.3 and
CycloneDX 1.7. They are written from the packages' own metadata, not by Syft, which records neither
an RPM's requirements nor its files' hashes, and nothing at all of a wheel or sdist file
(docs/decisions/0010-sbom-generator.md).

An RPM set's SBOM describes each RPM: its file's SHA-256 and SHA-1, its payload's and header's
digests, its license, and each file it installs with its SHA-1 and SHA-256, hashed from the payload
(rpm2archive's tar of it, FILE.rpm.tar) and checked against the header's digests. What an RPM
requires from the host (its Requires, less rpm's own rpmlib() entries and what the RPM or the set
provides) is listed as a package of its own, marked required from the host, not shipped (SPDX
DEPENDS_ON; CycloneDX isExternal with a version range). The set's own RPMs depend on each other.

The Python package's SBOM describes the wheel and the sdist, each with its files' hashes (the
wheel's checked against its RECORD), and the hash-pinned tools that built them, as build
dependencies (packaging/build-tools/requirements.txt), never as runtime ones.

Supplier and author: the wd2l project. The time is given (the commit's, for the same SBOMs from the
same files), and the namespace and serial number follow from the files' digests.

    package_sbom.py rpms --set el9 --rpm A.rpm [--rpm B.rpm ...] COMMON
    package_sbom.py python --wheel W.whl --sdist S.tar.gz --build-tools requirements.txt COMMON
    COMMON: --version V --repo-url URL --created YYYY-MM-DDTHH:MM:SSZ --out-spdx F --out-cdx F
Exit 1, writing nothing, when a file isn't what its package's metadata says."""

import argparse
import base64
import email.parser
import hashlib
import json
import os
import re
import sys
import tarfile
import uuid
import zipfile
from typing import Any, Dict, List, Optional, Sequence, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "container"))
import rpm_header  # noqa: E402  (a sibling script, not a package)

PROJECT = "wd2l project"
TOOL = "Tool: wd2l-package-sbom (packaging/release/package_sbom.py)"
RPMLIB = 1 << 24
OPS = {2: "<", 4: ">", 8: "=", 10: "<=", 12: ">="}


class Refused(Exception):
    pass


def digests(data: bytes) -> Tuple[str, str]:
    return hashlib.sha256(data).hexdigest(), hashlib.sha1(data).hexdigest()


def file_sha(path: str) -> Tuple[str, str]:
    with open(path, "rb") as f:
        return digests(f.read())


def sid(prefix: str, *parts: str) -> str:
    return "SPDXRef-%s-%s" % (prefix, "-".join(re.sub(r"[^A-Za-z0-9.]+", "-", p).strip("-") for p in parts))


def spdx_file(spdxid: str, name: str, data: bytes) -> Dict[str, Any]:
    s256, s1 = digests(data)
    return {"fileName": name, "SPDXID": spdxid,
            "checksums": [{"algorithm": "SHA1", "checksumValue": s1}, {"algorithm": "SHA256", "checksumValue": s256}],
            "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION"}


def cdx_file(ref: str, name: str, data: bytes) -> Dict[str, Any]:
    s256, s1 = digests(data)
    return {"bom-ref": ref, "type": "file", "name": name,
            "hashes": [{"alg": "SHA-1", "content": s1}, {"alg": "SHA-256", "content": s256}]}


def verification(files: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    """SPDX 2.3, 7.9: SHA-1 over the package's file SHA-1s, sorted and concatenated."""
    sha1s = sorted(c["checksumValue"] for f in files for c in f["checksums"] if c["algorithm"] == "SHA1")
    return {"packageVerificationCodeValue": hashlib.sha1("".join(sha1s).encode("ascii")).hexdigest()}


def documents(title: str, namespace: str, created: str, comment: str, packages: List[Dict[str, Any]],
              files: List[Dict[str, Any]], rels: List[Dict[str, Any]], described: List[str],
              components: List[Dict[str, Any]], dependencies: List[Dict[str, Any]],
              version: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    spdx = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": title,
            "documentNamespace": namespace,
            "creationInfo": {"created": created, "creators": ["Organization: " + PROJECT, TOOL], "comment": comment},
            "packages": packages, "files": files,
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": d,
                               "relationshipType": "DESCRIBES"} for d in described] + rels}
    cdx = {"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX",
           "specVersion": "1.7", "serialNumber": "urn:uuid:%s" % uuid.uuid5(uuid.NAMESPACE_URL, namespace),
           "version": 1,
           "metadata": {"timestamp": created, "lifecycles": [{"phase": "build"}],
                        "tools": {"components": [{"type": "application", "group": "wd2l", "name": "package_sbom.py"}]},
                        "authors": [{"name": PROJECT}], "manufacturer": {"name": PROJECT},
                        "supplier": {"name": PROJECT},
                        "component": {"bom-ref": "the-set", "type": "application", "name": title,
                                      "version": version, "supplier": {"name": PROJECT}}},
           "components": components, "dependencies": dependencies}
    return spdx, cdx


# ---- RPMs ---------------------------------------------------------------------------------

def requirement(r: Dict[str, Any]) -> Tuple[str, str, str]:
    """(name, operator, version), the operator "" when there is no version."""
    op = OPS.get(r["flags"] & 0x0E, "") if r["version"] else ""
    return r["name"], op, r["version"] if op else ""


def payload_files(rpm: Dict[str, Any], tar_path: str) -> List[Tuple[str, bytes]]:
    """Each file the header lists with a digest, read from the payload and checked against it."""
    with tarfile.open(tar_path) as t:
        # rpm's build hardlinks identical files (the .pyc and its .opt-1.pyc), and the tar keeps
        # the second as a link: tarfile reads it through to the first.
        members = {m.name[1:] if m.name.startswith("./") else "/" + m.name.lstrip("/"): m
                   for m in t.getmembers() if m.isfile() or m.islnk()}
        out = []
        for f in rpm["files"]:
            if not f["sha256"]:
                continue                                  # directories, links, ghost files
            m = members.get(f["path"])
            if m is None:
                raise Refused("%s: in the header, not in the payload" % f["path"])
            data = t.extractfile(m).read()
            if hashlib.sha256(data).hexdigest() != f["sha256"]:
                raise Refused("%s: not the file the RPM's header names (SHA-256 differs)" % f["path"])
            out.append((f["path"], data))
    return out


def rpm_set(paths: Sequence[str], set_name: str, version: str, repo_url: str,
            created: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    rpms = []
    for path in sorted(paths, key=os.path.basename):
        r = rpm_header.read_rpm(path)
        r["file"], (r["sha256"], r["sha1"]) = os.path.basename(path), file_sha(path)
        r["evr"] = "%s-%s" % (r["version"], r["release"])
        r["purl"] = "pkg:rpm/wd2l/%s@%s?arch=%s%s&distro=%s" % (
            r["name"], r["evr"], r["arch"], "&epoch=%d" % r["epoch"] if r["epoch"] is not None else "", set_name)
        r["spdxid"] = sid("Package-rpm", r["name"])
        r["payload"] = payload_files(r, path + ".tar")
        rpms.append(r)
    provided = {p: r for r in rpms for p in r["provides"] + [r["name"]]}
    packages: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    rels: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = []
    deps: List[Dict[str, Any]] = []
    needs: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for r in rpms:
        mine = [spdx_file(sid("File", r["name"], str(i)), path, data) for i, (path, data) in enumerate(r["payload"])]
        files += mine
        rels += [{"spdxElementId": r["spdxid"], "relatedSpdxElement": f["SPDXID"], "relationshipType": "CONTAINS"}
                 for f in mine]
        packages.append({
            "name": r["name"], "SPDXID": r["spdxid"], "versionInfo": r["evr"], "packageFileName": r["file"],
            "supplier": "Organization: " + PROJECT, "originator": "Organization: " + PROJECT,
            "downloadLocation": "%s/releases/download/v%s/%s" % (repo_url.rstrip("/"), version, r["file"]),
            "filesAnalyzed": True, "packageVerificationCode": verification(mine),
            "checksums": [{"algorithm": "SHA256", "checksumValue": r["sha256"]},
                          {"algorithm": "SHA1", "checksumValue": r["sha1"]}],
            "homepage": r["url"] or "NOASSERTION", "licenseConcluded": "NOASSERTION",
            "licenseDeclared": r["license"] or "NOASSERTION", "copyrightText": "NOASSERTION",
            "summary": r["summary"] or "",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": r["purl"]}],
            "primaryPackagePurpose": "INSTALL",
            "comment": "The RPM's payload SHA-256 %s; its header SHA-256 %s (rpm -qp --qf '%%{PAYLOADDIGEST}' "
                       "and '%%{SHA256HEADER}')." % (r["payload_sha256"], r["header_sha256"])})
        components.append({
            "bom-ref": r["purl"], "type": "application", "name": r["name"], "version": r["evr"], "purl": r["purl"],
            "supplier": {"name": PROJECT}, "description": r["summary"] or "",
            "licenses": [{"license": {"id": r["license"]}}] if re.fullmatch(r"[A-Za-z0-9.+-]+", r["license"] or "")
            else [{"expression": r["license"]}] if r["license"] else [],
            "hashes": [{"alg": "SHA-256", "content": r["sha256"]}],
            "properties": [{"name": "wd2l:file", "value": r["file"]},
                           {"name": "wd2l:rpm:payload-sha256", "value": r["payload_sha256"] or ""},
                           {"name": "wd2l:rpm:header-sha256", "value": r["header_sha256"] or ""}]})
        components += [cdx_file("file:%s:%s" % (r["name"], p), p, d) for p, d in r["payload"]]
        on: List[str] = []
        for q in r["requires"]:
            name, op, ver = requirement(q)
            if name.startswith("rpmlib(") or name in r["provides"] or name == r["name"]:
                continue
            if name in provided:                         # another RPM of this set
                target, ref = provided[name]["spdxid"], provided[name]["purl"]
            else:
                key = (name, op, ver)
                if key not in needs:
                    text = " ".join(x for x in key if x)
                    needs[key] = {"text": text, "spdxid": sid("Requirement", name, hashlib.sha256(text.encode()).hexdigest()[:8]),
                                  "ref": "requirement:" + text}
                    packages.append({
                        "name": name, "SPDXID": needs[key]["spdxid"], "versionInfo": "%s %s" % (op, ver) if op else "NOASSERTION",
                        "supplier": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                        "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                        "copyrightText": "NOASSERTION", "primaryPackagePurpose": "OTHER",
                        "comment": "Required from the host, not shipped in this release: " + text})
                    c = {"bom-ref": needs[key]["ref"], "type": "file" if name.startswith("/") else "library",
                         "name": name, "isExternal": True, "scope": "required",
                         "description": "Required from the host, not shipped in this release: " + text}
                    if op:
                        c["versionRange"] = "vers:rpm/%s%s" % ("" if op == "=" else op, ver)
                    components.append(c)
                target, ref = needs[key]["spdxid"], needs[key]["ref"]
            if ref in on:
                continue
            on.append(ref)
            rels.append({"spdxElementId": r["spdxid"], "relatedSpdxElement": target, "relationshipType": "DEPENDS_ON"})
        deps.append({"ref": r["purl"], "dependsOn": sorted(on)})
    digest = hashlib.sha256("".join(sorted(r["sha256"] for r in rpms)).encode()).hexdigest()
    namespace = "%s/sbom/rpms-%s-%s-%s" % (repo_url.rstrip("/"), set_name, version, digest)
    title = "wd2l %s RPMs (%s)" % (version, set_name)
    comment = ("Generated at release, from the built RPMs (build): each RPM's header, and its payload as "
               "rpm2archive unpacks it, by packaging/release/package_sbom.py.")
    return documents(title, namespace, created, comment, packages, files, rels, [r["spdxid"] for r in rpms],
                     components, deps, version)


# ---- The Python package -------------------------------------------------------------------

def wheel_files(path: str) -> Tuple[List[Tuple[str, bytes]], Dict[str, str]]:
    """Its files, checked against its RECORD, and its METADATA's fields."""
    with zipfile.ZipFile(path) as z:
        names = [n for n in z.namelist() if not n.endswith("/")]
        record = next(n for n in names if re.fullmatch(r"[^/]+\.dist-info/RECORD", n))
        meta = email.parser.Parser().parsestr(z.read(record[:-len("RECORD")] + "METADATA").decode("utf-8"))
        want = {}
        for row in z.read(record).decode("utf-8").splitlines():
            if row.strip():
                p, d = row.split(",")[:2]
                if d.startswith("sha256="):
                    b64 = d[len("sha256="):]
                    want[p] = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)).hex()
        out = []
        for n in sorted(names):
            data = z.read(n)
            if n in want and hashlib.sha256(data).hexdigest() != want[n]:
                raise Refused("%s: not the file the wheel's RECORD names (SHA-256 differs)" % n)
            out.append((n, data))
    return out, {"license": meta.get("License-Expression") or meta.get("License") or "",
                 "summary": meta.get("Summary") or "", "home": meta.get("Home-page") or ""}


def sdist_files(path: str) -> List[Tuple[str, bytes]]:
    with tarfile.open(path) as t:
        return sorted((m.name, t.extractfile(m).read()) for m in t.getmembers() if m.isfile())


def build_tools(path: str) -> List[Tuple[str, str, List[str]]]:
    """(name, version, sha256s) for each hash-pinned requirement."""
    with open(path, encoding="utf-8") as f:
        text = re.sub(r"\\\n", " ", f.read())
    out = []
    for line in text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9._-]+)==([^\s;]+)(.*)$", line.split("#", 1)[0])
        if m:
            out.append((m.group(1), m.group(2), re.findall(r"--hash=sha256:([0-9a-f]{64})", m.group(3))))
    return out


def python_package(wheel: str, sdist: str, tools_path: str, version: str, repo_url: str,
                   created: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    wfiles, meta = wheel_files(wheel)
    sfiles = sdist_files(sdist)
    packages: List[Dict[str, Any]] = []
    files: List[Dict[str, Any]] = []
    rels: List[Dict[str, Any]] = []
    components: List[Dict[str, Any]] = []
    ids, shas = [], []
    for kind, path, purpose, content in (("wheel", wheel, "INSTALL", wfiles), ("sdist", sdist, "SOURCE", sfiles)):
        name = os.path.basename(path)
        s256, s1 = file_sha(path)
        shas.append(s256)
        pid = sid("Package-python", kind)
        ids.append(pid)
        mine = [spdx_file(sid("File", kind, str(i)), n, d) for i, (n, d) in enumerate(content)]
        files += mine
        rels += [{"spdxElementId": pid, "relatedSpdxElement": f["SPDXID"], "relationshipType": "CONTAINS"} for f in mine]
        purl = "pkg:pypi/wd2l@%s?file_name=%s" % (version, name)
        packages.append({
            "name": "wd2l", "SPDXID": pid, "versionInfo": version, "packageFileName": name,
            "supplier": "Organization: " + PROJECT, "originator": "Organization: " + PROJECT,
            "downloadLocation": "%s/releases/download/v%s/%s" % (repo_url.rstrip("/"), version, name),
            "filesAnalyzed": True, "packageVerificationCode": verification(mine),
            "checksums": [{"algorithm": "SHA256", "checksumValue": s256}, {"algorithm": "SHA1", "checksumValue": s1}],
            "homepage": meta["home"] or repo_url, "licenseConcluded": "NOASSERTION",
            "licenseDeclared": meta["license"] or "NOASSERTION", "copyrightText": "NOASSERTION",
            "summary": meta["summary"],
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": purl}],
            "primaryPackagePurpose": purpose})
        components.append({"bom-ref": purl, "type": "application" if kind == "wheel" else "library",
                           "name": "wd2l", "version": version, "purl": purl, "supplier": {"name": PROJECT},
                           "licenses": [{"license": {"id": meta["license"]}}] if meta["license"] else [],
                           "hashes": [{"alg": "SHA-256", "content": s256}],
                           "properties": [{"name": "wd2l:file", "value": name}]})
        components += [cdx_file("file:%s:%s" % (kind, n), n, d) for n, d in content]
    for tool, tver, hashes in build_tools(tools_path):
        tid = sid("BuildTool", tool)
        note = ("a build tool: it built the wheel and the sdist (packaging/build-tools/requirements.txt, "
                "hash-pinned); not shipped")
        packages.append({
            "name": tool, "SPDXID": tid, "versionInfo": tver, "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": h} for h in hashes[:1]],
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": "pkg:pypi/%s@%s" % (tool.lower(), tver)}],
            "primaryPackagePurpose": "LIBRARY",
            "comment": note + ("; pinned to %s" % ", ".join("sha256:" + h for h in hashes) if len(hashes) > 1 else "")})
        rels += [{"spdxElementId": tid, "relatedSpdxElement": p, "relationshipType": "BUILD_DEPENDENCY_OF"} for p in ids]
        components.append({"bom-ref": "pkg:pypi/%s@%s" % (tool.lower(), tver), "type": "library", "name": tool,
                           "version": tver, "purl": "pkg:pypi/%s@%s" % (tool.lower(), tver), "scope": "excluded",
                           "hashes": [{"alg": "SHA-256", "content": h} for h in hashes[:1]], "description": note})
    digest = hashlib.sha256("".join(sorted(shas)).encode()).hexdigest()
    namespace = "%s/sbom/python-%s-%s" % (repo_url.rstrip("/"), version, digest)
    comment = ("Generated at release, from the built wheel and sdist (build): their files, the wheel's checked "
               "against its RECORD, and the hash-pinned tools that built them, by packaging/release/package_sbom.py.")
    # wd2l needs nothing at run time (pyproject.toml: dependencies = []): said, not left unknown.
    deps = [{"ref": "pkg:pypi/wd2l@%s?file_name=%s" % (version, os.path.basename(x)), "dependsOn": []}
            for x in (wheel, sdist)]
    return documents("wd2l %s Python package" % version, namespace, created, comment, packages, files, rels, ids,
                     components, deps, version)


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="SBOMs of the release's RPMs and Python package.")
    sub = p.add_subparsers(dest="kind", required=True)
    r = sub.add_parser("rpms", help="a set of RPMs (one EL version)")
    r.add_argument("--set", required=True, help="e.g. el9")
    r.add_argument("--rpm", action="append", required=True, help="an RPM, with FILE.rpm.tar beside it (rpm2archive -n)")
    py = sub.add_parser("python", help="the wheel and the sdist")
    py.add_argument("--wheel", required=True)
    py.add_argument("--sdist", required=True)
    py.add_argument("--build-tools", required=True, help="the hash-pinned requirements that built them")
    for s in (r, py):
        s.add_argument("--version", required=True)
        s.add_argument("--repo-url", required=True)
        s.add_argument("--created", required=True, help="YYYY-MM-DDTHH:MM:SSZ, e.g. the commit's time")
        s.add_argument("--out-spdx", required=True)
        s.add_argument("--out-cdx", required=True)
    a = p.parse_args(argv)
    try:
        if a.kind == "rpms":
            spdx, cdx = rpm_set(a.rpm, a.set, a.version, a.repo_url, a.created)
        else:
            spdx, cdx = python_package(a.wheel, a.sdist, a.build_tools, a.version, a.repo_url, a.created)
    except (Refused, ValueError) as e:
        print("package-sbom: %s" % e, file=sys.stderr)
        return 1
    for path, doc in ((a.out_spdx, spdx), (a.out_cdx, cdx)):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1, sort_keys=True)
            f.write("\n")
    described = [x for x in spdx["packages"] if x["SPDXID"].startswith("SPDXRef-Package-")]
    print("package-sbom %s: %d packages, %d files" % (spdx["name"], len(described), len(spdx["files"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
