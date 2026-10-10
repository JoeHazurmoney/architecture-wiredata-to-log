import json
import os
import subprocess

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
cc = load_script("packaging/container/check_containerfile.py")
D1, D2 = "sha256:" + "1" * 64, "sha256:" + "2" * 64
B = "registry.access.redhat.com/hi/python"
GOOD = ("FROM %s:3.12-fips-builder@%s AS build\nRUN true\nFROM %s:3.12-fips@%s\n"
        "COPY --from=build /out/ /\n") % (B, D1, B, D2)


def real():
    with open(os.path.join(REPO, "packaging", "container", "Containerfile")) as f:
        return f.read()


def test_the_real_containerfile_passes():
    assert cc.problems(real()) == []
    assert cc.base(real()).startswith(B + ":3.12-fips@sha256:")


def test_good():
    assert cc.problems(GOOD) == []
    assert cc.base(GOOD) == "%s:3.12-fips@%s" % (B, D2)
    assert [f["stage"] for f in cc.froms(GOOD)] == ["build", None]


def test_unpinned_base_is_refused():
    assert any("not pinned" in p for p in cc.problems(GOOD.replace("@" + D2, "")))


def test_other_registry_is_refused():
    bad = GOOD.replace(B + ":3.12-fips@", "docker.io/library/python:3.12-fips@")
    assert any("not a Red Hat Hardened Image" in p for p in cc.problems(bad))


def test_non_fips_variant_is_refused():
    assert any("not a FIPS variant" in p for p in cc.problems(GOOD.replace(":3.12-fips@", ":3.12@")))


def test_builder_as_the_last_stage_is_refused():
    bad = "FROM %s:3.12-fips-builder@%s\n" % (B, D1)
    assert any("last stage" in p for p in cc.problems(bad))


def test_copy_from_an_image_instead_of_a_stage_is_refused():
    bad = GOOD + "COPY --from=quay.io/someone/tools:1 /bin/x /bin/x\n"
    assert any("copies from" in p for p in cc.problems(bad))


def test_json_lists_every_from(tmp_path):
    f = tmp_path / "Containerfile"
    f.write_text(GOOD)
    r = subprocess.run(["python3", os.path.join(REPO, "packaging", "container",
                                                "check_containerfile.py"), str(f), "--json"],
                       stdout=subprocess.PIPE)
    got = json.loads(r.stdout)
    assert [x["tag"] for x in got] == ["3.12-fips-builder", "3.12-fips"] and got[1]["digest"] == D2


def test_build_script_passes_labels_and_removes_the_base_product_labels(tmp_path):
    log = tmp_path / "args"
    fake = tmp_path / "podman"
    fake.write_text('#!/bin/sh\nfor a in "$@"; do echo "$a"; done > "%s"\n' % log)
    fake.chmod(0o755)
    dist = tmp_path / "dist"
    dist.mkdir()
    sha = "c" * 40
    r = subprocess.run(["bash", os.path.join(REPO, "packaging", "container", "build.sh"),
                        str(dist), "localhost/wd2l:test"],
                       env=dict(os.environ, PODMAN=str(fake), REVISION=sha, EPOCH="1791209000"),
                       stderr=subprocess.PIPE)
    assert r.returncode == 0, r.stderr
    args = log.read_text().splitlines()
    assert args[0] == "build" and args[-1] == str(dist)
    assert args[args.index("--timestamp") + 1] == "1791209000"
    build_args = [args[i + 1] for i, a in enumerate(args) if a == "--build-arg"]
    base = cc.base(real())
    assert "BASE_NAME=" + base.split("@")[0] in build_args
    assert "BASE_DIGEST=" + base.split("@")[1] in build_args
    assert "REVISION=" + sha in build_args
    assert "VERSION=" + __import__("wd2l").__version__ in build_args
    unset = [args[i + 1] for i, a in enumerate(args) if a == "--unsetlabel"]
    for label in ("cpe", "com.redhat.component", "io.hummingbird-project.variant"):
        assert label in unset


import base64
import hashlib

br = load_script("packaging/container/base_record.py")


def write_evidence(d, i, ref_name, tag, sign_digest=None, prov_digest=None, fips=True,
                   index_bytes=None):
    """Evidence files for FROM number i, as the base-verify job writes them. Returns the
    index digest the Containerfile must name."""
    amd = "sha256:" + hashlib.sha256(b"amd%d" % i).hexdigest()
    arm = "sha256:" + hashlib.sha256(b"arm%d" % i).hexdigest()
    index = index_bytes or json.dumps({"manifests": [
        {"digest": amd, "platform": {"os": "linux", "architecture": "amd64"}},
        {"digest": arm, "platform": {"os": "linux", "architecture": "arm64"}}]}).encode()
    digest = "sha256:" + hashlib.sha256(index).hexdigest()
    (d / ("index-%d.json" % i)).write_bytes(index)
    labels = {"version": "3.12.15", "release": "1791414125"}
    if fips:
        labels["io.hummingbird-project.variant.fips"] = "true"
    (d / ("config-%d.json" % i)).write_text(json.dumps({"config": {"Labels": labels}}))
    (d / ("signature-%d.json" % i)).write_text(json.dumps([{"critical": {
        "image": {"docker-manifest-digest": sign_digest or digest}}}]))
    statement = {"_type": "https://in-toto.io/Statement/v0.1",
                 "predicateType": "https://slsa.dev/provenance/v0.2",
                 "subject": [{"name": "quay.io/hummingbird/python",
                              "digest": {"sha256": (prov_digest or amd).split(":")[1]}}]}
    (d / ("provenance-%d.json" % i)).write_text(json.dumps({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n")
    (d / ("sbom-%d.spdx.json" % i)).write_text(json.dumps({
        "spdxVersion": "SPDX-2.3", "packages": [{"name": "python3.12"}, {"name": "glibc"}]}))
    return digest


def evidence(tmp_path, **kw):
    d = tmp_path / "evidence"
    d.mkdir()
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "redhat-release3.pub").write_text("rh")
    (keys / "hummingbird-ci.pub").write_text("hb")
    d0 = write_evidence(d, 0, B, "3.12-fips-builder")
    d1 = write_evidence(d, 1, B, "3.12-fips", **kw)
    froms = [{"ref": "%s:3.12-fips-builder@%s" % (B, d0), "stage": "build", "name": B,
              "tag": "3.12-fips-builder", "digest": d0},
             {"ref": "%s:3.12-fips@%s" % (B, d1), "stage": None, "name": B,
              "tag": "3.12-fips", "digest": d1}]
    return froms, d, keys


def test_record_from_good_evidence(tmp_path):
    froms, d, keys = evidence(tmp_path)
    rec, probs = br.record(froms, str(d), str(keys), "2026-10-07T00:00:00Z")
    assert probs == []
    img = rec["images"][1]
    assert img["index_digest"] == froms[1]["digest"] and set(img["platforms"]) == {"amd64", "arm64"}
    assert img["source_image"] == B + ":1791414125-source"
    assert img["mirror"] == "quay.io/hummingbird/python@" + froms[1]["digest"]
    assert img["signature"]["verified"] and img["provenance"]["predicate_type"].endswith("v0.2")
    assert img["sbom"]["packages"] == 2
    assert rec["keys"]["redhat-release3.pub"] == hashlib.sha256(b"rh").hexdigest()


def test_record_refuses_a_signature_for_another_digest(tmp_path):
    froms, d, keys = evidence(tmp_path, sign_digest="sha256:" + "9" * 64)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("signature" in p and froms[1]["digest"] in p for p in probs)


def test_record_refuses_provenance_for_another_digest(tmp_path):
    froms, d, keys = evidence(tmp_path, prov_digest="sha256:" + "8" * 64)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("provenance" in p for p in probs)


def test_record_refuses_an_index_that_is_not_the_pinned_digest(tmp_path):
    froms, d, keys = evidence(tmp_path)
    (d / "index-1.json").write_bytes(b'{"manifests": []}')
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("index" in p and "pinned" in p for p in probs)


def test_record_refuses_a_fips_tag_without_the_fips_label(tmp_path):
    froms, d, keys = evidence(tmp_path, fips=False)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("FIPS" in p for p in probs)


def test_record_refuses_missing_evidence(tmp_path):
    froms, d, keys = evidence(tmp_path)
    (d / "sbom-1.spdx.json").unlink()
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("sbom-1.spdx.json" in p for p in probs)


import stat
import zipfile

ci = load_script("packaging/container/check_image.py")
SHA = "a" * 40


def wheel_and_rootfs(tmp_path, build=SHA):
    """A wheel and a rootfs that installed it, plus a base rootfs with the same rpmdb."""
    files = {"wd2l/__init__.py": b'__version__ = "0.3.0"\n', "wd2l/BUILD": (build + "\n").encode()}
    whl = tmp_path / "wd2l-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as z:
        rec = []
        for name, data in files.items():
            z.writestr(name, data)
            h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rec.append("%s,sha256=%s,%d" % (name, h, len(data)))
        rec.append("wd2l-0.3.0.dist-info/RECORD,,")
        z.writestr("wd2l-0.3.0.dist-info/RECORD", "\n".join(rec) + "\n")
    roots = []
    for name in ("rootfs", "base"):
        root = tmp_path / name
        (root / "etc/crypto-policies").mkdir(parents=True)
        (root / "etc/crypto-policies/config").write_text("FIPS\n")
        (root / "usr/lib/sysimage/rpm").mkdir(parents=True)
        (root / ci.RPMDB).write_bytes(b"the same rpmdb")
        (root / "tmp").mkdir()
        os.chmod(str(root / "tmp"), 0o1777)
        roots.append(root)
    site = roots[0] / "usr/lib/python3.12/site-packages"
    for name, data in files.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_bytes(data)
    return str(whl), str(roots[0]), str(roots[1])


def config(**over):
    labels = {"name": "wd2l", "vendor": "wd2l project",
              "org.opencontainers.image.title": "wd2l", "org.opencontainers.image.version": "0.3.0",
              "org.opencontainers.image.revision": SHA,
              "org.opencontainers.image.source": "https://github.com/x/y",
              "org.opencontainers.image.licenses": "MIT",
              "org.opencontainers.image.base.name": B + ":3.12-fips",
              "org.opencontainers.image.base.digest": D2}
    labels.update(over.pop("labels", {}))
    c = {"User": "65532", "Cmd": ["wd2l-receiver", "--help"], "Labels": labels}
    c.update(over)
    return [{"Config": c}]


BASE_REF = "%s:3.12-fips@%s" % (B, D2)


def test_good_image_passes(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    assert ci.check_config(config(), "0.3.0", SHA, BASE_REF) == []
    assert ci.check_filesystem(root, base) == []
    assert ci.check_wheel_files(root, whl, SHA) == []


def test_config_problems(tmp_path):
    probs = ci.check_config(config(User="0", Entrypoint=["/bin/sh", "-c"],
                                   labels={"cpe": "cpe:/a:redhat:hummingbird:1",
                                           "io.hummingbird-project.variant": "fips",
                                           "name": "hi/python",
                                           "org.opencontainers.image.base.digest": D1}),
                            "0.3.0", SHA, BASE_REF)
    text = "\n".join(probs)
    for word in ("65532", "shell", "cpe", "io.hummingbird-project.variant", "name", "base.digest"):
        assert word in text, word


def test_shell_and_package_manager_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    for p in ("usr/bin/bash", "usr/bin/dnf"):
        os.makedirs(os.path.join(root, os.path.dirname(p)), exist_ok=True)
        open(os.path.join(root, p), "w").close()
    text = "\n".join(ci.check_filesystem(root, base))
    assert "shell present: /usr/bin/bash" in text and "package manager present: /usr/bin/dnf" in text


def test_pip_is_refused(tmp_path):
    # The base installs pip with ensurepip (not an RPM); the Containerfile removes it.
    whl, root, base = wheel_and_rootfs(tmp_path)
    os.makedirs(os.path.join(root, "usr/local/bin"))
    open(os.path.join(root, "usr/local/bin/pip3"), "w").close()
    os.makedirs(os.path.join(root, "usr/local/lib/python3.12/site-packages/pip/_vendor"))
    text = "\n".join(ci.check_filesystem(root, base))
    assert "package manager present: /usr/local/bin/pip3" in text
    assert "package manager present: /usr/local/lib/python3.12/site-packages/pip" in text


def test_setuid_and_world_writable_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    os.makedirs(os.path.join(root, "usr/bin"), exist_ok=True)
    su = os.path.join(root, "usr/bin/su")
    open(su, "w").close()
    os.chmod(su, 0o4755)
    ww = os.path.join(root, "etc/open")
    open(ww, "w").close()
    os.chmod(ww, 0o666)
    text = "\n".join(ci.check_filesystem(root, base))
    assert "setuid/setgid file: /usr/bin/su" in text and "world-writable: /etc/open" in text
    assert "/tmp" not in text


def test_non_fips_policy_and_changed_rpmdb_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    with open(os.path.join(root, "etc/crypto-policies/config"), "w") as f:
        f.write("DEFAULT\n")
    with open(os.path.join(root, ci.RPMDB), "wb") as f:
        f.write(b"one more package")
    text = "\n".join(ci.check_filesystem(root, base))
    assert "not FIPS" in text and "rpm database differs" in text


def test_changed_wd2l_file_and_wrong_build_are_refused(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    with open(os.path.join(root, "usr/lib/python3.12/site-packages/wd2l/__init__.py"), "a") as f:
        f.write("# changed\n")
    text = "\n".join(ci.check_wheel_files(root, whl, "b" * 40))
    assert "changed: " in text and "wd2l/__init__.py" in text and "BUILD" in text


vg = load_script("packaging/container/vuln_gate.py")
TODAY = "2026-10-07"


def grype_doc(*matches):
    return {"matches": [{"vulnerability": {"id": i, "severity": s, "fix": {"state": st, "versions": ["9"]}},
                         "artifact": {"name": p, "version": "1"}} for i, s, st, p in matches]}


def trivy_doc(vulns=(), secrets=()):
    return {"Results": [{"Target": "img", "Vulnerabilities": [
        {"VulnerabilityID": i, "PkgName": p, "InstalledVersion": "1", "Severity": s, "FixedVersion": f}
        for i, s, f, p in vulns], "Secrets": [{"RuleID": r} for r in secrets]}]}


def exc(id_, package, expires="2026-12-31", **kw):
    e = {"id": id_, "package": package, "reason": "r", "expires": expires, "approved_by": "security owner"}
    e.update(kw)
    return e


def run_gate(grype, trivy, exceptions):
    found = vg.grype_findings(grype) + vg.trivy_findings(trivy)
    valid, probs = vg.load_exceptions({"exceptions": exceptions}, TODAY)
    gated, excepted = vg.gate(found, valid)
    return gated, excepted, probs


def test_only_fixable_high_and_critical_are_gated():
    gated, _e, probs = run_gate(
        grype_doc(("CVE-1", "High", "fixed", "openssl-libs"), ("CVE-2", "High", "not-fixed", "glibc"),
                  ("CVE-3", "Medium", "fixed", "zlib")),
        trivy_doc([("CVE-4", "CRITICAL", "2.0", "python3.12"), ("CVE-5", "LOW", "1.1", "x")]), [])
    assert sorted(f["id"] for f in gated) == ["CVE-1", "CVE-4"] and probs == []


def test_secrets_are_always_gated():
    gated, _e, _p = run_gate(grype_doc(), trivy_doc(secrets=["aws-access-key-id"]), [])
    assert [f["id"] for f in gated] == ["aws-access-key-id"]


def test_an_exception_covers_its_cve_in_its_package():
    gated, excepted, probs = run_gate(grype_doc(("CVE-1", "High", "fixed", "openssl-libs")),
                                      trivy_doc(), [exc("CVE-1", "openssl-libs")])
    assert gated == [] and [f["id"] for f in excepted] == ["CVE-1"] and probs == []


def test_exception_only_covers_its_package():
    gated, _e, _p = run_gate(grype_doc(("CVE-1", "High", "fixed", "glibc")), trivy_doc(),
                             [exc("CVE-1", "openssl-libs")])
    assert [f["package"] for f in gated] == ["glibc"]


def test_expired_exception_fails_even_unused():
    gated, _e, probs = run_gate(grype_doc(), trivy_doc(), [exc("CVE-9", "x", expires="2026-10-01")])
    assert gated == [] and any("expired" in p and "CVE-9" in p for p in probs)


def test_an_expired_exception_no_longer_covers():
    gated, _e, _p = run_gate(grype_doc(("CVE-1", "High", "fixed", "openssl-libs")), trivy_doc(),
                             [exc("CVE-1", "openssl-libs", expires="2026-10-06")])
    assert [f["id"] for f in gated] == ["CVE-1"]


def test_incomplete_exception_is_a_problem():
    _g, _e, probs = run_gate(grype_doc(), trivy_doc(), [{"id": "CVE-1", "package": "x"}])
    assert any("reason" in p for p in probs)


def test_cli_exit_codes_summary_and_predicate(tmp_path):
    g, t, e = tmp_path / "g.json", tmp_path / "t.json", tmp_path / "e.json"
    g.write_text(json.dumps(grype_doc(("CVE-1", "Critical", "fixed", "openssl-libs"))))
    t.write_text(json.dumps(trivy_doc()))
    e.write_text(json.dumps({"exceptions": []}))
    s, p = tmp_path / "s.md", tmp_path / "p.json"
    args = ["--grype", str(g), "--trivy", str(t), "--exceptions", str(e), "--today", TODAY,
            "--summary", str(s), "--predicate", str(p)]
    assert vg.main(args) == 1
    assert "CVE-1" in s.read_text() and json.loads(p.read_text())["gate"]["passed"] is False
    e.write_text(json.dumps({"exceptions": [exc("CVE-1", "openssl-libs")]}))
    assert vg.main(args) == 0


def test_the_committed_exceptions_file_is_valid():
    with open(os.path.join(REPO, "packaging", "container", "vuln-exceptions.json")) as f:
        _valid, probs = vg.load_exceptions(json.load(f), TODAY)
    assert probs == []


sd = load_script("packaging/container/sbom_diff.py")


def spdx(*purls):
    return {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": p.split("/")[-1], "externalRefs": [{"referenceType": "purl", "referenceLocator": p}]}
        for p in purls] + [{"name": "the image itself"}]}


BASE_PKGS = ("pkg:rpm/hummingbird/glibc@2.42-1?arch=x86_64", "pkg:rpm/hummingbird/python3.12@3.12.15-1?arch=x86_64")


def test_adding_only_wd2l_passes():
    added, removed = sd.diff(spdx(*BASE_PKGS), spdx(*BASE_PKGS + ("pkg:pypi/wd2l@0.3.0",)),
                             ["pkg:pypi/wd2l@"])
    assert added == [] and removed == []


def test_anything_else_added_or_removed_is_named():
    added, removed = sd.diff(spdx(*BASE_PKGS),
                             spdx(BASE_PKGS[0], "pkg:pypi/wd2l@0.3.0", "pkg:rpm/hummingbird/bash@5.3-1?arch=x86_64"),
                             ["pkg:pypi/wd2l@"])
    assert added == ["pkg:rpm/hummingbird/bash@5.3-1?arch=x86_64"] and removed == [BASE_PKGS[1]]


def test_removing_the_base_pip_is_allowed():
    base = spdx(*BASE_PKGS + ("pkg:pypi/pip@26.2",))
    image = spdx(*BASE_PKGS + ("pkg:pypi/wd2l@0.3.0",))
    assert sd.diff(base, image, ["pkg:pypi/wd2l@"], ["pkg:pypi/pip@"]) == ([], [])
    assert sd.diff(base, image, ["pkg:pypi/wd2l@"]) == ([], ["pkg:pypi/pip@26.2"])


def test_cli(tmp_path):
    b, i = tmp_path / "b.json", tmp_path / "i.json"
    b.write_text(json.dumps(spdx(*BASE_PKGS)))
    i.write_text(json.dumps(spdx(*BASE_PKGS + ("pkg:pypi/requests@2.0",))))
    assert sd.main([str(b), str(i)]) == 1
    i.write_text(json.dumps(spdx(*BASE_PKGS + ("pkg:pypi/wd2l@0.3.0",))))
    assert sd.main([str(b), str(i)]) == 0
    b.write_text(json.dumps(spdx(*BASE_PKGS + ("pkg:pypi/pip@26.2",))))
    assert sd.main([str(b), str(i)]) == 0
    assert sd.main([str(b), str(i), "--allow-removed", "pkg:pypi/nothing@"]) == 1


def described(doc, root_purl):
    """Syft's SPDX: the image itself is a package (pkg:oci/...) the document DESCRIBES."""
    doc["packages"].append({"SPDXID": "SPDXRef-DocumentRoot-Image", "name": "img",
                            "externalRefs": [{"referenceType": "purl", "referenceLocator": root_purl}]})
    doc["relationships"] = [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
                             "relatedSpdxElement": "SPDXRef-DocumentRoot-Image"}]
    return doc


def test_the_described_image_itself_is_not_a_package_difference():
    base = described(spdx(*BASE_PKGS), "pkg:oci/base.tar@sha256%3Aaaa?arch=amd64")
    image = described(spdx(*BASE_PKGS + ("pkg:pypi/wd2l@0.3.0",)), "pkg:oci/img.tar@sha256%3Abbb?arch=amd64")
    assert sd.diff(base, image, ["pkg:pypi/wd2l@"]) == ([], [])
