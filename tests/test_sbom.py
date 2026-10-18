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
