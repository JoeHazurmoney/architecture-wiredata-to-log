"""SBOMs of the release's own packages (packaging/release/package_sbom.py, #190): a set of RPMs, and
the Python package (the wheel and the sdist), in SPDX 2.3 and CycloneDX 1.7, written from the
packages' own metadata."""

import base64
import hashlib
import io
import json
import tarfile
import zipfile

import pytest

from helpers import INT16, INT32, STRING, STRING_ARRAY, I18N, load_script, rpm_file

ps = load_script("packaging/release/package_sbom.py")
REPO_URL = "https://github.com/o/r"
CREATED = "2026-10-18T00:00:00Z"
EQ, GE = 8, 12
RPMLIB = 1 << 24


def sha(data, algo="sha256"):
    return hashlib.new(algo, data).hexdigest()


def make_rpm(tmp_path, name, files, requires=(), provides=None, payload=None):
    """An RPM (version 9.9.0-1.el9, noarch) and the tar rpm2archive makes of its payload. files:
    (path, bytes), or (path, None) for a directory."""
    dirs = sorted({p.rsplit("/", 1)[0] + "/" for p, _ in files})
    main = [(1000, STRING, name), (1001, STRING, "9.9.0"), (1002, STRING, "1.el9"), (1022, STRING, "noarch"),
            (1004, I18N, "The %s package" % name), (1014, STRING, "MIT"), (1020, STRING, REPO_URL),
            (1044, STRING, "wd2l-9.9.0-1.el9.src.rpm"),
            (1047, STRING_ARRAY, list(provides if provides is not None else [name])),
            (1048, INT32, [f for _, f, _ in requires]), (1049, STRING_ARRAY, [n for n, _, _ in requires]),
            (1050, STRING_ARRAY, [v for _, _, v in requires]),
            (1030, INT16, [0o40755 if d is None else 0o100644 for _, d in files]),
            (1035, STRING_ARRAY, ["" if d is None else sha(d) for _, d in files]),
            (1116, INT32, [dirs.index(p.rsplit("/", 1)[0] + "/") for p, _ in files]),
            (1117, STRING_ARRAY, [p.rsplit("/", 1)[1] for p, _ in files]),
            (1118, STRING_ARRAY, dirs), (5011, INT32, [8]), (5092, STRING_ARRAY, ["cd" * 32]), (5093, INT32, [8])]
    if not requires:
        main = [t for t in main if t[0] not in (1048, 1049, 1050)]
    path = rpm_file(tmp_path / ("%s-9.9.0-1.el9.noarch.rpm" % name), main, sig=[(273, STRING, "ab" * 32)])
    with tarfile.open(path + ".tar", "w") as t:
        for p, d in (payload if payload is not None else files):
            info = tarfile.TarInfo("." + p)
            if d is None:
                info.type = tarfile.DIRTYPE
                t.addfile(info)
            else:
                info.size = len(d)
                t.addfile(info, io.BytesIO(d))
    return path


ENV, INIT, TOOL = b"PORT=5514\n", b"VERSION = '9.9.0'\n", b"#!/bin/sh\n"


def two_rpms(tmp_path):
    base = make_rpm(tmp_path, "wd2l", [("/usr/lib/python3.9/site-packages/wd2l", None),
                                        ("/usr/lib/python3.9/site-packages/wd2l/__init__.py", INIT)],
                    requires=[("rpmlib(PayloadIsZstd)", EQ | RPMLIB, "5.4.18-1"), ("python3", GE, "3.9"),
                              ("/bin/sh", 0, ""), ("/bin/sh", 0, "")])
    sender = make_rpm(tmp_path, "wd2l-sender", [("/etc/wd2l/sender.env", ENV), ("/usr/libexec/wd2l/egress", TOOL)],
                      requires=[("config(wd2l-sender)", EQ, "9.9.0-1.el9"), ("iproute", 0, ""),
                                ("wd2l", EQ, "9.9.0-1.el9")],
                      provides=["config(wd2l-sender)", "wd2l-sender"])
    return base, sender


def rpm_sboms(tmp_path, *rpms):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    args = ["rpms", "--set", "el9", "--version", "9.9.0", "--repo-url", REPO_URL, "--created", CREATED,
            "--out-spdx", str(out / "s.json"), "--out-cdx", str(out / "c.json")]
    for r in rpms:
        args += ["--rpm", r]
    rc = ps.main(args)
    return rc, (json.loads((out / "s.json").read_text()) if rc == 0 else None), \
        (json.loads((out / "c.json").read_text()) if rc == 0 else None)


def by_name(packages, name):
    return next(p for p in packages if p["name"] == name)


# --- RPMs: SPDX ---

def test_each_rpm_is_a_described_package_with_its_file_s_digests_and_identity(tmp_path):
    base, sender = two_rpms(tmp_path)
    rc, s, _c = rpm_sboms(tmp_path, base, sender)
    assert rc == 0
    p = by_name(s["packages"], "wd2l-sender")
    data = open(sender, "rb").read()
    assert p["versionInfo"] == "9.9.0-1.el9" and p["packageFileName"] == "wd2l-sender-9.9.0-1.el9.noarch.rpm"
    assert p["checksums"] == [{"algorithm": "SHA256", "checksumValue": sha(data)},
                              {"algorithm": "SHA1", "checksumValue": sha(data, "sha1")}]
    assert p["supplier"] == "Organization: wd2l project" and p["licenseDeclared"] == "MIT"
    assert p["primaryPackagePurpose"] == "INSTALL"
    assert p["downloadLocation"] == REPO_URL + "/releases/download/v9.9.0/wd2l-sender-9.9.0-1.el9.noarch.rpm"
    assert [r["referenceLocator"] for r in p["externalRefs"]] == ["pkg:rpm/wd2l/wd2l-sender@9.9.0-1.el9?arch=noarch&distro=el9"]
    assert "payload SHA-256 " + "cd" * 32 in p["comment"] and "header SHA-256 " + "ab" * 32 in p["comment"]
    described = {r["relatedSpdxElement"] for r in s["relationships"] if r["relationshipType"] == "DESCRIBES"}
    assert described == {by_name(s["packages"], "wd2l")["SPDXID"], p["SPDXID"]}


def test_each_rpm_s_files_are_hashed_from_its_payload(tmp_path):
    base, sender = two_rpms(tmp_path)
    _rc, s, _c = rpm_sboms(tmp_path, base, sender)
    p = by_name(s["packages"], "wd2l-sender")
    files = {f["SPDXID"]: f for f in s["files"]}
    mine = sorted(files[r["relatedSpdxElement"]]["fileName"] for r in s["relationships"]
                  if r["spdxElementId"] == p["SPDXID"] and r["relationshipType"] == "CONTAINS")
    assert mine == ["/etc/wd2l/sender.env", "/usr/libexec/wd2l/egress"]
    env = next(f for f in s["files"] if f["fileName"] == "/etc/wd2l/sender.env")
    assert env["checksums"] == [{"algorithm": "SHA1", "checksumValue": sha(ENV, "sha1")},
                                {"algorithm": "SHA256", "checksumValue": sha(ENV)}]
    want = hashlib.sha1("".join(sorted([sha(ENV, "sha1"), sha(TOOL, "sha1")])).encode()).hexdigest()
    assert p["packageVerificationCode"] == {"packageVerificationCodeValue": want}
    assert all(not f["fileName"].endswith("/wd2l") for f in s["files"])        # directories aren't files


def test_requirements_are_host_packages_and_the_set_s_own_rpms_are_dependencies(tmp_path):
    base, sender = two_rpms(tmp_path)
    _rc, s, _c = rpm_sboms(tmp_path, base, sender)
    ids = {p["SPDXID"]: p for p in s["packages"]}
    deps = {}
    for r in s["relationships"]:
        if r["relationshipType"] == "DEPENDS_ON":
            deps.setdefault(ids[r["spdxElementId"]]["name"], []).append(
                (ids[r["relatedSpdxElement"]]["name"], ids[r["relatedSpdxElement"]]["versionInfo"]))
    assert sorted(deps["wd2l"]) == [("/bin/sh", "NOASSERTION"), ("python3", ">= 3.9")]       # once, no rpmlib()
    assert sorted(deps["wd2l-sender"]) == [("iproute", "NOASSERTION"), ("wd2l", "9.9.0-1.el9")]  # no config()
    py = by_name(s["packages"], "python3")
    assert py["SPDXID"].startswith("SPDXRef-Requirement-") and py["filesAnalyzed"] is False
    assert py["supplier"] == "NOASSERTION" and py["comment"] == "Required from the host, not shipped in this release: python3 >= 3.9"


def test_the_author_context_and_namespace_are_fixed_by_the_inputs(tmp_path):
    base, sender = two_rpms(tmp_path)
    _rc, s, c = rpm_sboms(tmp_path, base, sender)
    info = s["creationInfo"]
    assert info["created"] == CREATED and info["creators"][0] == "Organization: wd2l project"
    assert "(build)" in info["comment"]
    digest = sha("".join(sorted(sha(open(r, "rb").read()) for r in (base, sender))).encode())
    assert s["documentNamespace"] == REPO_URL + "/sbom/rpms-el9-9.9.0-" + digest
    first = (json.dumps(s, sort_keys=True), json.dumps(c, sort_keys=True))
    (tmp_path / "out" / "s.json").unlink()
    _rc, s2, c2 = rpm_sboms(tmp_path, base, sender)
    assert (json.dumps(s2, sort_keys=True), json.dumps(c2, sort_keys=True)) == first


def test_a_file_the_payload_hardlinks_is_hashed_through_its_link(tmp_path):
    # Found on 1.1.0's RPMs: rpm's build hardlinks identical .pyc files (opt-1 and plain), and
    # rpm2archive's tar keeps the second as a link to the first.
    pyc = b"\x61\x0d\x0d\x0a compiled"
    files = [("/usr/lib/wd2l/__pycache__/a.cpython-39.opt-1.pyc", pyc), ("/usr/lib/wd2l/__pycache__/a.cpython-39.pyc", pyc)]
    path = make_rpm(tmp_path, "wd2l", files, payload=files[:1])
    with tarfile.open(path + ".tar", "a") as t:
        link = tarfile.TarInfo("./usr/lib/wd2l/__pycache__/a.cpython-39.pyc")
        link.type, link.linkname = tarfile.LNKTYPE, "./usr/lib/wd2l/__pycache__/a.cpython-39.opt-1.pyc"
        t.addfile(link)
    rc, s, _c = rpm_sboms(tmp_path, path)
    assert rc == 0
    got = {f["fileName"]: f["checksums"][1]["checksumValue"] for f in s["files"]}
    assert got == {p: sha(pyc) for p, _ in files}


def test_a_payload_file_that_isn_t_the_header_s_is_refused(tmp_path, capsys):
    bad = make_rpm(tmp_path, "wd2l-sender", [("/etc/wd2l/sender.env", ENV)],
                   payload=[("/etc/wd2l/sender.env", b"changed\n")])
    rc, _s, _c = rpm_sboms(tmp_path, bad)
    assert rc == 1 and "/etc/wd2l/sender.env: not the file the RPM's header names (SHA-256 differs)" in capsys.readouterr().err


def test_a_file_missing_from_the_payload_is_refused(tmp_path, capsys):
    bad = make_rpm(tmp_path, "wd2l-sender", [("/etc/wd2l/sender.env", ENV), ("/usr/libexec/wd2l/egress", TOOL)],
                   payload=[("/etc/wd2l/sender.env", ENV)])
    rc, _s, _c = rpm_sboms(tmp_path, bad)
    assert rc == 1 and "/usr/libexec/wd2l/egress: in the header, not in the payload" in capsys.readouterr().err


# --- RPMs: CycloneDX ---

def test_cdx_rpms_their_hashes_requirements_files_and_dependencies(tmp_path):
    base, sender = two_rpms(tmp_path)
    _rc, _s, c = rpm_sboms(tmp_path, base, sender)
    assert c["specVersion"] == "1.7" and c["metadata"]["lifecycles"] == [{"phase": "build"}]
    assert c["metadata"]["authors"] == [{"name": "wd2l project"}] and c["metadata"]["timestamp"] == CREATED
    comps = {x["bom-ref"]: x for x in c["components"]}
    send = comps["pkg:rpm/wd2l/wd2l-sender@9.9.0-1.el9?arch=noarch&distro=el9"]
    assert send["hashes"] == [{"alg": "SHA-256", "content": sha(open(sender, "rb").read())}]
    assert send["supplier"] == {"name": "wd2l project"} and send["licenses"] == [{"license": {"id": "MIT"}}]
    py = next(x for x in c["components"] if x["name"] == "python3")
    assert py["isExternal"] is True and py["versionRange"] == "vers:rpm/>=3.9" and py["scope"] == "required"
    dep = next(d for d in c["dependencies"] if d["ref"] == send["bom-ref"])
    assert sorted(comps[r]["name"] for r in dep["dependsOn"]) == ["iproute", "wd2l"]
    env = next(x for x in c["components"] if x.get("type") == "file" and x["name"] == "/etc/wd2l/sender.env")
    assert env["hashes"] == [{"alg": "SHA-1", "content": sha(ENV, "sha1")}, {"alg": "SHA-256", "content": sha(ENV)}]
    assert c["serialNumber"].startswith("urn:uuid:")


# --- The Python package ---

WHL_FILES = {"wd2l/__init__.py": INIT, "wd2l/sender.py": b"def main(): pass\n",
             "wd2l-9.9.0.dist-info/METADATA": b"Name: wd2l\nVersion: 9.9.0\n"}
REQS = ("# hash-pinned build tools\nbuild==1.6.1 \\\n    --hash=sha256:%s\nsetuptools==84.0.0 \\\n"
        "    --hash=sha256:%s\n" % ("e" * 64, "f" * 64))


def python_inputs(tmp_path, record_override=None):
    whl = tmp_path / "wd2l-9.9.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as z:
        rows = []
        for name, data in WHL_FILES.items():
            z.writestr(name, data)
            digest = record_override.get(name) if record_override and name in record_override else data
            b64 = base64.urlsafe_b64encode(hashlib.sha256(digest).digest()).rstrip(b"=").decode()
            rows.append("%s,sha256=%s,%d" % (name, b64, len(data)))
        z.writestr("wd2l-9.9.0.dist-info/RECORD", "\n".join(rows + ["wd2l-9.9.0.dist-info/RECORD,,"]) + "\n")
    sd = tmp_path / "wd2l-9.9.0.tar.gz"
    with tarfile.open(str(sd), "w:gz") as t:
        for name, data in (("wd2l-9.9.0/wd2l/__init__.py", INIT), ("wd2l-9.9.0/PKG-INFO", b"Name: wd2l\n")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    reqs = tmp_path / "requirements.txt"
    reqs.write_text(REQS)
    return str(whl), str(sd), str(reqs)


def python_sboms(tmp_path, **kw):
    whl, sd, reqs = python_inputs(tmp_path, **kw)
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    rc = ps.main(["python", "--version", "9.9.0", "--wheel", whl, "--sdist", sd, "--build-tools", reqs,
                  "--repo-url", REPO_URL, "--created", CREATED, "--out-spdx", str(out / "s.json"),
                  "--out-cdx", str(out / "c.json")])
    if rc:
        return rc, None, None, whl, sd
    return rc, json.loads((out / "s.json").read_text()), json.loads((out / "c.json").read_text()), whl, sd


def test_the_wheel_and_the_sdist_are_packages_with_their_files(tmp_path):
    rc, s, _c, whl, sd = python_sboms(tmp_path)
    assert rc == 0
    wheel = next(p for p in s["packages"] if p.get("packageFileName") == "wd2l-9.9.0-py3-none-any.whl")
    sdist = next(p for p in s["packages"] if p.get("packageFileName") == "wd2l-9.9.0.tar.gz")
    assert wheel["name"] == sdist["name"] == "wd2l"
    assert (wheel["primaryPackagePurpose"], sdist["primaryPackagePurpose"]) == ("INSTALL", "SOURCE")
    assert wheel["checksums"][0] == {"algorithm": "SHA256", "checksumValue": sha(open(whl, "rb").read())}
    assert [r["referenceLocator"] for r in wheel["externalRefs"]] == ["pkg:pypi/wd2l@9.9.0?file_name=wd2l-9.9.0-py3-none-any.whl"]
    files = {f["SPDXID"]: f["fileName"] for f in s["files"]}
    def contained(pkg):
        return sorted(files[r["relatedSpdxElement"]] for r in s["relationships"]
                      if r["spdxElementId"] == pkg["SPDXID"] and r["relationshipType"] == "CONTAINS")
    assert contained(wheel) == sorted(list(WHL_FILES) + ["wd2l-9.9.0.dist-info/RECORD"])
    assert contained(sdist) == ["wd2l-9.9.0/PKG-INFO", "wd2l-9.9.0/wd2l/__init__.py"]


def test_the_build_tools_are_build_dependencies_by_their_pinned_hash(tmp_path):
    _rc, s, c, _w, _s = python_sboms(tmp_path)
    tool = by_name(s["packages"], "setuptools")
    assert tool["versionInfo"] == "84.0.0" and tool["checksums"] == [{"algorithm": "SHA256", "checksumValue": "f" * 64}]
    assert "a build tool" in tool["comment"] and "not shipped" in tool["comment"]
    builds = [r for r in s["relationships"] if r["spdxElementId"] == tool["SPDXID"]]
    assert {r["relationshipType"] for r in builds} == {"BUILD_DEPENDENCY_OF"} and len(builds) == 2
    cdx_tool = next(x for x in c["components"] if x["name"] == "setuptools")
    assert cdx_tool["scope"] == "excluded" and cdx_tool["hashes"] == [{"alg": "SHA-256", "content": "f" * 64}]


def test_a_wheel_file_that_isn_t_its_record_s_is_refused(tmp_path, capsys):
    rc, *_ = python_sboms(tmp_path, record_override={"wd2l/sender.py": b"something else"})
    assert rc == 1 and "wd2l/sender.py: not the file the wheel's RECORD names (SHA-256 differs)" in capsys.readouterr().err
