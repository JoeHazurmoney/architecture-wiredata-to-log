"""The image SBOM's completion (packaging/container/sbom_enrich.py) and the readable report made
from it (packaging/release/sbom_report.py), on documents shaped as Syft 1.54 writes them
(docs/decisions/0009-sbom-content.md)."""

import base64
import copy
import hashlib
import json
import re
import zipfile

import pytest

from helpers import load_script

en = load_script("packaging/container/sbom_enrich.py")

SITE = "usr/lib/python3.12/site-packages"
DIST = "wd2l-9.9.0.dist-info"
DIGEST = "ab" * 32
REPO_URL = "https://github.com/o/r"
SOURCES = {"wd2l/__init__.py": b"VERSION = '9.9.0'\n", "wd2l/sender.py": b"def main():\n    pass\n",
           DIST + "/METADATA": b"Metadata-Version: 2.1\nName: wd2l\nVersion: 9.9.0\n"}


def sha(data, algo):
    return hashlib.new(algo, data).hexdigest()


def make_wheel(path, sources=SOURCES):
    """A wheel as build-dist.sh makes one: the files, and a RECORD of their SHA-256s."""
    rows = []
    for name, data in sources.items():
        b64 = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rows.append("%s,sha256=%s,%d" % (name, b64, len(data)))
    rows.append(DIST + "/RECORD,,")
    with zipfile.ZipFile(str(path), "w") as z:
        for name, data in sources.items():
            z.writestr(name, data)
        z.writestr(DIST + "/RECORD", "\n".join(rows) + "\n")
    return str(path)


def spdx_file(name, data=None, sid=None):
    """A file entry as Syft writes it. Directories and links have only an all-zero SHA-1."""
    sums = ([{"algorithm": "SHA1", "checksumValue": sha(data, "sha1")},
             {"algorithm": "SHA256", "checksumValue": sha(data, "sha256")}] if data is not None
            else [{"algorithm": "SHA1", "checksumValue": "0" * 40}])
    return {"fileName": name, "SPDXID": sid or "SPDXRef-File-" + re.sub(r"[^A-Za-z0-9.-]", "-", name),
            "fileTypes": ["TEXT"] if data is not None else ["OTHER"], "checksums": sums,
            "licenseConcluded": "NOASSERTION", "licenseInfoInFiles": ["NOASSERTION"],
            "copyrightText": "NOASSERTION", "comment": "layerID: sha256:" + "c" * 64}


def spdx_package(name, version, purl, sid):
    return {"name": name, "SPDXID": sid, "versionInfo": version, "supplier": "NOASSERTION",
            "downloadLocation": "NOASSERTION", "filesAnalyzed": True,
            "packageVerificationCode": {"packageVerificationCodeValue": "1" * 40},
            "sourceInfo": "acquired package info from RPM DB: /usr/lib/sysimage/rpm/rpmdb.sqlite",
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT", "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                              "referenceLocator": "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*" % (name, name, version)},
                             {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": purl}]}


ROOT = "SPDXRef-DocumentRoot-Image-ghcr.io-joehazurmoney-wd2l"
SSL, WD2L = "SPDXRef-Package-rpm-openssl-libs-1", "SPDXRef-Package-python-wd2l-2"
SSL_PURL = ("pkg:rpm/redhat/openssl-libs@3.5.9-0.3.hum1?arch=x86_64&distro=hummingbird-20251124"
            "&epoch=1&upstream=openssl-3.5.9-0.3.hum1.src.rpm")
INSTALLED = {"wd2l/__pycache__/__init__.cpython-312.pyc": b"pyc-init",
             "wd2l/__pycache__/sender.cpython-312.pyc": b"pyc-sender",
             DIST + "/INSTALLER": b"pip\n", DIST + "/RECORD": b"the installed RECORD\n"}


def syft_spdx():
    """Syft's SPDX of a small image: openssl-libs from the RPM database, wd2l from its dist-info
    with only its launcher linked, the RPM database in no package, and one directory."""
    files = [spdx_file("usr/bin/wd2l-sender", b"#!/usr/bin/python3\n"),
             spdx_file("usr/lib64/libssl.so.3", b"\x7fELF ssl"),
             spdx_file("usr/lib/sysimage/rpm/rpmdb.sqlite", b"SQLite format 3"),
             spdx_file("usr/lib64")]
    files += [spdx_file(SITE + "/" + n, d) for n, d in list(SOURCES.items()) + list(INSTALLED.items())]
    ids = {f["fileName"]: f["SPDXID"] for f in files}
    root = {"name": "ghcr.io/joehazurmoney/wd2l", "SPDXID": ROOT, "versionInfo": "9.9.0",
            "supplier": "NOASSERTION", "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
            "checksums": [{"algorithm": "SHA256", "checksumValue": DIGEST}],
            "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
            "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                              "referenceLocator": "pkg:oci/ghcr.io%2Fjoehazurmoney%2Fwd2l@sha256%3A" + DIGEST}],
            "primaryPackagePurpose": "CONTAINER"}
    evident = "evident-by: indicates the package's existence is evident by the given file"
    rels = [{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": ROOT, "relationshipType": "DESCRIBES"},
            {"spdxElementId": SSL, "relatedSpdxElement": ids["usr/lib64/libssl.so.3"], "relationshipType": "CONTAINS"},
            {"spdxElementId": WD2L, "relatedSpdxElement": ids["usr/bin/wd2l-sender"], "relationshipType": "CONTAINS"},
            {"spdxElementId": SSL, "relatedSpdxElement": WD2L, "relationshipType": "DEPENDENCY_OF"},
            {"spdxElementId": SSL, "relatedSpdxElement": ids["usr/lib/sysimage/rpm/rpmdb.sqlite"],
             "relationshipType": "OTHER", "comment": evident},
            {"spdxElementId": WD2L, "relatedSpdxElement": ids[SITE + "/" + DIST + "/METADATA"],
             "relationshipType": "OTHER", "comment": evident}]
    return {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "ghcr.io/joehazurmoney/wd2l",
            "documentNamespace": "https://anchore.com/syft/image/ghcr.io/joehazurmoney/wd2l-7bd83ef8",
            "creationInfo": {"licenseListVersion": "3.29", "created": "2026-10-18T01:10:35Z",
                             "creators": ["Organization: Anchore, Inc", "Tool: syft-1.54.1"]},
            "packages": [spdx_package("openssl-libs", "1:3.5.9-0.3.hum1", SSL_PURL, SSL),
                         spdx_package("wd2l", "9.9.0", "pkg:pypi/wd2l@9.9.0", WD2L), root],
            "files": files, "hasExtractedLicensingInfos": [], "relationships": rels}


def syft_cdx(os_name="hummingbird"):
    return {"$schema": "http://cyclonedx.org/schema/bom-1.7.schema.json", "bomFormat": "CycloneDX",
            "specVersion": "1.7", "serialNumber": "urn:uuid:7bd83ef8", "version": 1,
            "metadata": {"timestamp": "2026-10-18T01:10:35Z",
                         "tools": {"components": [{"type": "application", "author": "anchore",
                                                   "name": "syft", "version": "1.54.1"}]},
                         "component": {"bom-ref": "c0", "type": "container",
                                       "name": "ghcr.io/joehazurmoney/wd2l", "version": "9.9.0"}},
            "components": [{"bom-ref": SSL_PURL, "type": "library", "name": "openssl-libs",
                            "version": "1:3.5.9-0.3.hum1", "purl": SSL_PURL},
                           {"bom-ref": "pkg:pypi/wd2l@9.9.0", "type": "library", "name": "wd2l",
                            "version": "9.9.0", "purl": "pkg:pypi/wd2l@9.9.0"},
                           {"bom-ref": "os:%s@1" % os_name, "type": "operating-system", "name": os_name,
                            "version": "1"},
                           {"bom-ref": "f1", "type": "file", "name": "/usr/lib64/libssl.so.3",
                            "hashes": [{"alg": "SHA-256", "content": sha(b"\x7fELF ssl", "sha256")}]}],
            "dependencies": []}


def enrich(tmp_path, doc=None, sources=SOURCES):
    doc = syft_spdx() if doc is None else doc
    dist_info, rec = en.record(make_wheel(tmp_path / "wd2l-9.9.0-py3-none-any.whl", sources))
    done, gaps = en.complete_spdx(doc, dist_info, rec, "amd64", REPO_URL)
    return doc, done, gaps


def by_name(doc):
    return {f["fileName"]: f for f in doc["files"]}


def contained(doc, pkg):
    names = {f["SPDXID"]: f["fileName"] for f in doc["files"]}
    return sorted(names[r["relatedSpdxElement"]] for r in doc["relationships"]
                  if r["spdxElementId"] == pkg and r["relationshipType"] == "CONTAINS")


def package(doc, sid):
    return next(p for p in doc["packages"] if p["SPDXID"] == sid)


# --- Enrichment: SPDX ---

def test_every_component_gets_its_supplier_and_the_image_is_the_projects(tmp_path):
    doc, _, gaps = enrich(tmp_path)
    assert gaps == []
    assert package(doc, SSL)["supplier"] == "Organization: Red Hat, Inc."
    assert package(doc, WD2L)["supplier"] == "Organization: wd2l project"
    assert package(doc, ROOT)["supplier"] == "Organization: wd2l project"


def test_a_component_no_rule_covers_is_a_gap(tmp_path):
    doc = syft_spdx()
    doc["packages"].append(spdx_package("requests", "2.32.0", "pkg:pypi/requests@2.32.0", "SPDXRef-Package-x"))
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["no supplier rule for requests 2.32.0 (pkg:pypi/requests@2.32.0)"]
    assert package(doc, "SPDXRef-Package-x")["supplier"] == "NOASSERTION"


REQ_PURL, REQ_RPM_PURL = "pkg:pypi/requests@2.25.1", "pkg:rpm/redhat/python3-requests@2.25.1-10.el9?arch=noarch"


def with_rpm_installed_python(doc, owned_by_rpm=True):
    """UBI 9's case: an RPM (python3-requests) installed a Python package (requests), whose
    metadata Syft reads and records as the evidence for it."""
    meta = spdx_file("usr/lib/python3.9/site-packages/requests-2.25.1.dist-info/METADATA", b"Name: requests\n")
    doc["files"].append(meta)
    doc["packages"] += [spdx_package("requests", "2.25.1", REQ_PURL, "SPDXRef-Package-python-requests"),
                        spdx_package("python3-requests", "2.25.1-10.el9", REQ_RPM_PURL, "SPDXRef-Package-rpm-req")]
    doc["relationships"].append({"spdxElementId": "SPDXRef-Package-python-requests", "relatedSpdxElement": meta["SPDXID"],
                                 "relationshipType": "OTHER",
                                 "comment": "evident-by: indicates the package's existence is evident by the given file"})
    if owned_by_rpm:
        doc["relationships"].append({"spdxElementId": "SPDXRef-Package-rpm-req", "relatedSpdxElement": meta["SPDXID"],
                                     "relationshipType": "CONTAINS"})
    return doc


def test_a_language_package_an_os_package_installed_takes_that_package_s_supplier(tmp_path):
    doc, _, gaps = enrich(tmp_path, with_rpm_installed_python(syft_spdx()))
    assert gaps == []
    assert package(doc, "SPDXRef-Package-python-requests")["supplier"] == "Organization: Red Hat, Inc."


def test_a_language_package_no_os_package_installed_is_still_a_gap(tmp_path):
    _, _, gaps = enrich(tmp_path, with_rpm_installed_python(syft_spdx(), owned_by_rpm=False))
    assert gaps == ["no supplier rule for requests 2.25.1 (pkg:pypi/requests@2.25.1)"]


def test_a_language_package_two_suppliers_installed_is_still_a_gap(tmp_path):
    doc = with_rpm_installed_python(syft_spdx())
    meta = next(f for f in doc["files"] if f["fileName"].endswith("requests-2.25.1.dist-info/METADATA"))
    doc["relationships"].append({"spdxElementId": WD2L, "relatedSpdxElement": meta["SPDXID"],
                                 "relationshipType": "CONTAINS"})          # wd2l project's too
    doc, _, gaps = enrich(tmp_path, doc)
    assert "no supplier rule for requests 2.25.1 (pkg:pypi/requests@2.25.1)" in gaps


def test_cdx_gives_an_installed_language_package_the_same_supplier(tmp_path):
    cdx = syft_cdx()
    cdx["components"].append({"bom-ref": REQ_PURL + "?package-id=1", "type": "library", "name": "requests",
                              "version": "2.25.1", "purl": REQ_PURL})
    spdx = with_rpm_installed_python(syft_spdx())
    rc, _s, c = run_enrich(tmp_path, spdx, cdx)
    assert rc == 0
    assert next(x for x in c["components"] if x["name"] == "requests")["supplier"] == {"name": "Red Hat, Inc."}


def test_a_lookalike_package_id_gets_no_supplier(tmp_path):
    """The rules match a package ID's start: a wd2l-named package from elsewhere isn't ours."""
    doc = syft_spdx()
    doc["packages"].append(spdx_package("wd2lx", "1", "pkg:pypi/wd2lx@1", "SPDXRef-Package-y"))
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["no supplier rule for wd2lx 1 (pkg:pypi/wd2lx@1)"]


def test_wd2l_gets_every_file_of_its_record_its_dist_info_and_its_compiled_modules(tmp_path):
    doc, done, gaps = enrich(tmp_path)
    assert gaps == []
    assert contained(doc, WD2L) == sorted(
        ["usr/bin/wd2l-sender"] + [SITE + "/" + n for n in
                                   ("wd2l/__init__.py", "wd2l/sender.py", DIST + "/METADATA", DIST + "/RECORD",
                                    DIST + "/INSTALLER", "wd2l/__pycache__/__init__.cpython-312.pyc",
                                    "wd2l/__pycache__/sender.cpython-312.pyc")])
    assert "wd2l: 8 files (7 newly linked; every RECORD hash checked)" in done
    assert contained(doc, SSL) == ["usr/lib64/libssl.so.3"]


def test_wd2l_s_verification_code_covers_its_files(tmp_path):
    """SPDX 2.3, 7.9: the SHA-1 of its files' SHA-1s, sorted and joined."""
    doc, _, _ = enrich(tmp_path)
    data = [b"#!/usr/bin/python3\n"] + list(SOURCES.values()) + list(INSTALLED.values())
    want = hashlib.sha1("".join(sorted(sha(d, "sha1") for d in data)).encode()).hexdigest()
    assert package(doc, WD2L)["packageVerificationCode"] == {"packageVerificationCodeValue": want}
    assert package(doc, WD2L)["filesAnalyzed"] is True


def test_a_file_that_is_not_the_wheel_s_is_a_gap(tmp_path):
    doc = syft_spdx()
    f = by_name(doc)[SITE + "/wd2l/sender.py"]
    f["checksums"][1]["checksumValue"] = "f" * 64
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["not the wheel's file (SHA-256 differs): /%s/wd2l/sender.py" % SITE]
    assert SITE + "/wd2l/sender.py" not in contained(doc, WD2L)


def test_a_record_file_missing_from_the_image_is_a_gap(tmp_path):
    doc = syft_spdx()
    doc["files"] = [f for f in doc["files"] if f["fileName"] != SITE + "/wd2l/sender.py"]
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["in wd2l's RECORD but not in the SBOM: /%s/wd2l/sender.py" % SITE]


@pytest.mark.parametrize("extra", ["wd2l/added.py", "wd2l/__pycache__/added.cpython-312.pyc"])
def test_a_file_in_wd2l_s_directory_that_its_record_doesnt_list_is_a_gap(tmp_path, extra):
    doc = syft_spdx()
    doc["files"].append(spdx_file(SITE + "/" + extra, b"planted"))
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["in wd2l's directory but not in its RECORD: /%s/%s" % (SITE, extra)]


def test_another_package_beside_wd2l_in_site_packages_is_left_alone(tmp_path):
    doc = syft_spdx()
    doc["files"].append(spdx_file(SITE + "/other/__init__.py", b"other"))
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == []
    assert SITE + "/other/__init__.py" not in contained(doc, WD2L)


def test_wd2l_or_its_record_missing_is_a_gap(tmp_path):
    doc = syft_spdx()
    doc["files"] = [f for f in doc["files"] if not f["fileName"].endswith(DIST + "/RECORD")]
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["wd2l or its RECORD is not in the SBOM"]


def test_entries_without_a_sha256_are_dropped(tmp_path):
    doc, done, gaps = enrich(tmp_path)
    assert "usr/lib64" not in by_name(doc)
    assert "dropped 1 entries without a SHA-256 (directories and links)" in done
    assert all(any(c["algorithm"] == "SHA256" for c in f["checksums"]) for f in doc["files"])


def test_an_entry_without_a_sha256_that_has_a_relationship_is_kept_and_is_a_gap(tmp_path):
    doc = syft_spdx()
    d = by_name(doc)["usr/lib64"]
    doc["relationships"].append({"spdxElementId": SSL, "relatedSpdxElement": d["SPDXID"],
                                 "relationshipType": "CONTAINS"})
    _, _, gaps = enrich(tmp_path, doc)
    assert "usr/lib64" in by_name(doc)
    assert gaps == ["a file without a SHA-256 has relationships: usr/lib64"]


def test_the_author_tool_and_generation_context(tmp_path):
    doc, _, _ = enrich(tmp_path)
    info = doc["creationInfo"]
    assert info["creators"] == ["Organization: wd2l project", "Tool: syft-1.54.1"]
    assert info["comment"] == ("Generated after the build (post-build), from the built container image for "
                               "linux/amd64, by syft-1.54.1; completed by packaging/container/sbom_enrich.py.")
    assert info["created"] == "2026-10-18T01:10:35Z"


def test_the_namespace_is_the_repository_s_and_names_the_version_platform_and_digest(tmp_path):
    doc, _, _ = enrich(tmp_path)
    assert doc["documentNamespace"] == "https://github.com/o/r/sbom/wd2l-9.9.0-amd64-" + DIGEST


def test_no_image_digest_is_a_gap(tmp_path):
    doc = syft_spdx()
    package(doc, ROOT)["checksums"] = []
    _, _, gaps = enrich(tmp_path, doc)
    assert gaps == ["the image's digest is not in the SBOM"]


def test_completing_twice_changes_nothing_more(tmp_path):
    once, _, _ = enrich(tmp_path)
    twice, done, gaps = enrich(tmp_path, copy.deepcopy(once))
    assert gaps == [] and twice == once
    assert "wd2l: 8 files (0 newly linked; every RECORD hash checked)" in done


def test_files_in_no_package_are_counted(tmp_path):
    _, done, _ = enrich(tmp_path)
    assert done[-1] == "10 files, 1 of them in no package"           # the RPM database


# --- Enrichment: CycloneDX ---

@pytest.mark.parametrize("os_name", ["hummingbird", "rhel"])
def test_cdx_components_and_the_operating_system_get_their_suppliers(os_name):
    doc = syft_cdx(os_name)
    done, gaps = en.complete_cdx(doc)
    assert gaps == []
    assert [c.get("supplier") for c in doc["components"]] == [
        {"name": "Red Hat, Inc."}, {"name": "wd2l project"}, {"name": "Red Hat, Inc."}, None]
    assert done == ["suppliers: Red Hat, Inc. 2, wd2l project 1"]


def test_cdx_an_operating_system_no_rule_covers_is_a_gap():
    doc = syft_cdx("alpine")
    _, gaps = en.complete_cdx(doc)
    assert gaps == ["no supplier rule for alpine 1 (operating-system)"]


def test_cdx_the_author_and_the_lifecycle():
    doc = syft_cdx()
    en.complete_cdx(doc)
    meta = doc["metadata"]
    assert meta["authors"] == [{"name": "wd2l project"}]
    assert meta["manufacturer"] == meta["supplier"] == {"name": "wd2l project"}
    assert meta["lifecycles"] == [{"phase": "post-build"}]
    assert meta["component"]["supplier"] == {"name": "wd2l project"}
    assert meta["tools"]["components"][0]["name"] == "syft"


# --- Enrichment: the command ---

def write_json(path, doc):
    path.write_text(json.dumps(doc))
    return str(path)


def run_enrich(tmp_path, spdx, cdx):
    wheel = make_wheel(tmp_path / "wd2l-9.9.0-py3-none-any.whl")
    s, c = write_json(tmp_path / "s.json", spdx), write_json(tmp_path / "c.json", cdx)
    rc = en.main(["--spdx", s, "--cdx", c, "--wheel", wheel, "--arch", "amd64", "--repo-url", REPO_URL])
    return rc, json.loads((tmp_path / "s.json").read_text()), json.loads((tmp_path / "c.json").read_text())


def test_the_command_completes_both_files_in_place(tmp_path, capsys):
    rc, s, c = run_enrich(tmp_path, syft_spdx(), syft_cdx())
    assert rc == 0
    assert package(s, SSL)["supplier"] == "Organization: Red Hat, Inc."
    assert c["metadata"]["lifecycles"] == [{"phase": "post-build"}]
    assert "gap" not in capsys.readouterr().out


def test_the_command_fails_and_names_each_gap(tmp_path, capsys):
    doc = syft_spdx()
    doc["packages"].append(spdx_package("requests", "2.32.0", "pkg:pypi/requests@2.32.0", "SPDXRef-Package-x"))
    rc, _, _ = run_enrich(tmp_path, doc, syft_cdx("alpine"))
    assert rc == 1
    out = capsys.readouterr().out
    assert "no supplier rule for requests 2.32.0" in out and "no supplier rule for alpine 1" in out


# --- The report ---

rep = load_script("packaging/release/sbom_report.py")


def grype_doc(*matches):
    """Grype's JSON: (id, severity, package, version, fixed versions)."""
    return {"matches": [{"vulnerability": {"id": i, "severity": sev, "fix": {"versions": list(fix),
                                                                          "state": "fixed" if fix else ""}},
                         "artifact": {"name": pkg, "version": ver, "type": "rpm", "purl": "pkg:rpm/redhat/" + pkg}}
                        for i, sev, pkg, ver, fix in matches],
            "source": {"type": "image"}, "distro": {"name": "hummingbird", "version": "20251124"},
            "descriptor": {"name": "grype", "version": "0.119.0"}}


def trivy_doc(*vulns):
    """Trivy's JSON: (id, severity, package, version, fixed version)."""
    return {"SchemaVersion": 2, "Trivy": {"Version": "0.75.0"}, "ArtifactName": "/work/image/oci",
            "ArtifactType": "container_image", "Metadata": {"OS": {"Family": "none", "Name": ""}},
            "Results": [{"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg",
                         "Vulnerabilities": [{"VulnerabilityID": i, "Severity": sev, "PkgName": pkg,
                                              "InstalledVersion": ver, "FixedVersion": fix}
                                             for i, sev, pkg, ver, fix in vulns]}]}


def report_inputs(tmp_path, name="amd64", spdx=None):
    """An enriched SPDX and CycloneDX pair, written as the release names them."""
    doc = syft_spdx() if spdx is None else spdx
    dist_info, rec = en.record(make_wheel(tmp_path / "wd2l-9.9.0-py3-none-any.whl"))
    en.complete_spdx(doc, dist_info, rec, "amd64", REPO_URL)
    cdx = syft_cdx()
    en.complete_cdx(cdx)
    return (write_json(tmp_path / ("wd2l-9.9.0-image-%s.spdx.json" % name), doc),
            write_json(tmp_path / ("wd2l-9.9.0-image-%s.cdx.json" % name), cdx))


WD2L_ARGS = ["--version", "9.9.0", "--commit", "e" * 40, "--repo-url", REPO_URL]


def report(tmp_path, *args, release=True):
    out = tmp_path / "report.html"
    rc = rep.main(["--out", str(out)] + (WD2L_ARGS if release else []) + list(args))
    assert rc == 0
    return out.read_text(encoding="utf-8")


def one_view(tmp_path, *scans, spdx=None):
    s, c = report_inputs(tmp_path, spdx=spdx)
    args = ["--view", "amd64", "linux/amd64", s, c]
    for name, doc in scans:
        args += ["--scan", "amd64", "%s=%s" % (name, write_json(tmp_path / (name + ".json"), doc))]
    return args


def test_each_view_is_a_section_with_its_label_and_its_own_sbom_files(tmp_path):
    s1, c1 = report_inputs(tmp_path, "amd64")
    s2, c2 = report_inputs(tmp_path, "ubi9-amd64")
    html = report(tmp_path, "--view", "amd64", "linux/amd64", s1, c1,
                  "--view", "ubi9", "UBI 9 (amd64)", s2, c2)
    assert html.count('<section class="view"') == 2
    assert "<h2>linux/amd64</h2>" in html and "<h2>UBI 9 (amd64)</h2>" in html
    assert 'data-view="ubi9" data-label="UBI 9 (amd64)"' in html
    assert "<code>wd2l-9.9.0-image-ubi9-amd64.spdx.json</code> (SPDX 2.3)" in html
    assert "<code>wd2l-9.9.0-image-amd64.cdx.json</code> (CycloneDX 1.7)" in html


def test_a_scan_is_read_by_its_shape_and_shown_by_its_name(tmp_path):
    html = report(tmp_path, *one_view(tmp_path, ("trivy-redhat", trivy_doc(
        ("CVE-2026-1111", "HIGH", "openssl-libs", "3.5.9-0.3.hum1", "3.5.10-0.1.hum1")))))
    row = re.search(r'<tr><td><a href="https://www.cve.org/CVERecord\?id=CVE-2026-1111">.*?</tr>', html).group(0)
    assert "<td>openssl-libs</td>" in row and "<td>3.5.10-0.1.hum1</td>" in row
    assert row.endswith("<td>trivy-redhat</td></tr>")
    assert "From the scans with trivy-redhat." in html
    assert '<tr><td>trivy-redhat</td><td>not recognized</td><td class="ok-no">No</td>' in html


def test_the_same_finding_from_two_scanners_is_one_row_found_by_both(tmp_path):
    """Grype names the RPM's epoch and Trivy doesn't: the same finding all the same."""
    html = report(tmp_path, *one_view(
        tmp_path, ("grype", grype_doc(("CVE-2026-2222", "Medium", "openssl-libs", "1:3.5.9-0.3.hum1", ()))),
        ("trivy", trivy_doc(("CVE-2026-2222", "MEDIUM", "openssl-libs", "3.5.9-0.3.hum1", "")))))
    assert html.count("CVERecord?id=CVE-2026-2222") == 1
    assert "<td>grype, trivy</td>" in html
    assert "and the scan results of grype, trivy.</footer>" in html
    assert '<div class="tile"><b>1</b><span>known vulnerabilities</span></div>' in html


def test_findings_are_shown_on_their_component_and_unmatched_ones_are_counted(tmp_path):
    html = report(tmp_path, *one_view(tmp_path, ("grype", grype_doc(
        ("CVE-2026-3333", "High", "openssl-libs", "1:3.5.9-0.3.hum1", ()),
        ("CVE-2026-4444", "Low", "zlib", "1.3", ("1.3.1",))))))
    ssl = re.search(r'<details class="comp" role="listitem" data-search="openssl-libs .*?</summary>', html).group(0)
    assert '<span class="sev sev-high">High</span>' in ssl
    wd2l = re.search(r'<details class="comp" role="listitem" data-search="wd2l .*?</summary>', html).group(0)
    assert '<span class="muted">none</span>' in wd2l
    assert "1 of them name a component this SBOM doesn't list by that name and version." in html
    assert "1 High, 1 Low." in html


def test_what_each_scan_covered_is_shown_beside_the_findings(tmp_path):
    html = report(tmp_path, *one_view(tmp_path, ("grype", grype_doc()), ("trivy", trivy_doc())))
    table = re.search(r'<table class="coverage">.*?</table>', html).group(0)
    assert ('<tr><td>grype</td><td>hummingbird 20251124</td><td class="ok-yes">Yes</td>'
            '<td class="ok-yes">Yes</td><td>No</td></tr>') in table
    assert ('<tr><td>trivy</td><td>not recognized</td><td class="ok-no">No</td>'
            '<td class="ok-yes">Yes</td><td>Yes</td></tr>') in table
    assert "weren't checked" not in html


def test_when_no_scan_covered_the_os_packages_the_page_says_so(tmp_path):
    blind = grype_doc()
    blind["distro"] = None
    html = report(tmp_path, *one_view(tmp_path, ("grype", blind), ("trivy", trivy_doc())))
    assert ("No scan covered the operating system's packages, so they weren't checked for known "
            "vulnerabilities.") in html


def test_a_view_with_no_scans_says_so(tmp_path):
    html = report(tmp_path, *one_view(tmp_path))
    assert "No scan results were given for this view." in html
    assert "<p>None.</p>" not in html
    assert '<div class="tile"><b>&#8212;</b><span>not scanned for vulnerabilities</span></div>' in html
    assert "known vulnerabilities</span></div>" not in html


def test_text_from_the_sboms_is_escaped(tmp_path):
    doc = syft_spdx()
    doc["packages"].append(spdx_package('<script>alert("x")</script>', "1", "pkg:rpm/redhat/x@1", "SPDXRef-Package-x"))
    html = report(tmp_path, *one_view(tmp_path, spdx=doc))
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;" in html


def test_the_page_loads_nothing_from_outside(tmp_path):
    html = report(tmp_path, *one_view(tmp_path, ("grype", grype_doc())))
    assert not re.search(r"<link\b|\bsrc\s*=|@import|url\(", html, re.I)
    csp = re.search(r'<meta http-equiv="Content-Security-Policy" content="([^"]+)">', html).group(1)
    assert "default-src 'none'" in csp and "connect-src" not in csp
    assert html.count("<script>") == 1                    # the page's own, inline


def test_the_field_check_rates_each_field_from_the_components(tmp_path):
    full = report(tmp_path, *one_view(tmp_path))
    assert '<tr><td>Supplier</td><td class="ok-yes">Yes</td><td>2 of 2 components</td></tr>' in full
    doc = syft_spdx()
    doc["packages"].append(spdx_package("x", "1", "pkg:generic/x@1", "SPDXRef-Package-x"))
    s, c = report_inputs(tmp_path, spdx=doc)                      # x keeps NOASSERTION: a gap
    partial = report(tmp_path, "--view", "amd64", "linux/amd64", s, c)
    assert '<tr><td>Supplier</td><td class="ok-partly">Partly</td><td>2 of 3 components</td></tr>' in partial


def test_a_file_in_two_components_is_counted_once(tmp_path):
    doc = syft_spdx()
    lib = next(f for f in doc["files"] if f["fileName"] == "usr/lib64/libssl.so.3")
    doc["relationships"].append({"spdxElementId": WD2L, "relatedSpdxElement": lib["SPDXID"],
                                 "relationshipType": "CONTAINS"})
    html = report(tmp_path, *one_view(tmp_path, spdx=doc))
    assert '<div class="tile"><b>10</b><span>files, each with a SHA-256</span></div>' in html
    assert "1 files belong to two components, and are listed under both." in html


def test_wd2l_s_page_has_its_title_and_the_release_s_facts(tmp_path):
    html = report(tmp_path, *one_view(tmp_path))
    assert "<title>wd2l 9.9.0: software bill of materials</title>" in html
    assert "What is inside the wd2l 9.9.0 container image, for linux/amd64:" in html
    assert '<code>%s</code> of <a href="%s">' % ("e" * 40, REPO_URL) in html
    assert REPO_URL + "/blob/v9.9.0/docs/decisions/0009-sbom-content.md" in html
    assert "signed <code>SHA256SUMS</code>" in html


def test_a_page_for_another_system_has_its_own_title_and_none_of_wd2l_s_release_facts(tmp_path):
    html = report(tmp_path, "--title", "AlmaLinux 9 <Server>", "--intro", "A full server, for comparison.",
                  *one_view(tmp_path), release=False)
    assert "<title>AlmaLinux 9 &lt;Server&gt;</title>" in html and "<h1>AlmaLinux 9 &lt;Server&gt;</h1>" in html
    assert '<p class="lede">A full server, for comparison.</p>' in html
    for wd2l_only in ("SHA256SUMS", "release manifest", "Built from", "every week", "ADR-0009"):
        assert wd2l_only not in html, wd2l_only


@pytest.mark.parametrize("bad", [
    ["--scan", "arm64", "grype=G"],                               # no such view
    ["--scan", "amd64", "grype"],                                 # no file
])
def test_a_scan_that_names_no_view_or_file_is_refused(tmp_path, bad):
    with pytest.raises(SystemExit) as e:
        rep.main(["--out", str(tmp_path / "r.html")] + WD2L_ARGS + one_view(tmp_path) + bad)
    assert e.value.code == 2


def test_a_scan_file_that_is_neither_grype_nor_trivy_is_refused(tmp_path):
    args = one_view(tmp_path, ("grype", {"bomFormat": "CycloneDX"}))
    with pytest.raises(SystemExit) as e:
        rep.main(["--out", str(tmp_path / "r.html")] + WD2L_ARGS + args)
    assert e.value.code == 2


def test_without_a_title_the_version_is_required(tmp_path):
    with pytest.raises(SystemExit) as e:
        rep.main(["--out", str(tmp_path / "r.html")] + one_view(tmp_path))
    assert e.value.code == 2
