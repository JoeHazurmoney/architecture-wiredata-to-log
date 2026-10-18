import json
import os
import subprocess

import pytest

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
                   index_bytes=None, releases=None):
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
    releases = releases or {}
    for arch in ("amd64", "arm64"):
        (d / ("config-%d-%s.json" % (i, arch))).write_text(json.dumps({"config": {"Labels": dict(
            labels, release=releases.get(arch, labels["release"]))}}))
        (d / ("sbom-%d-%s.spdx.json" % (i, arch))).write_text(json.dumps({
            "spdxVersion": "SPDX-2.3", "packages": [{"name": "python3.12"}, {"name": "glibc"}]}))
    (d / ("signature-%d.json" % i)).write_text(json.dumps([{"critical": {
        "image": {"docker-manifest-digest": sign_digest or digest}}}]))
    statement = {"_type": "https://in-toto.io/Statement/v0.1",
                 "predicateType": "https://slsa.dev/provenance/v0.2",
                 "subject": [{"name": "quay.io/hummingbird/python",
                              "digest": {"sha256": (prov_digest or amd).split(":")[1]}}]}
    (d / ("provenance-%d.json" % i)).write_text(json.dumps({
        "payloadType": "application/vnd.in-toto+json",
        "payload": base64.b64encode(json.dumps(statement).encode()).decode()}) + "\n")
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
    assert set(img["sboms"]) == {"amd64", "arm64"} and img["sboms"]["arm64"]["packages"] == 2
    assert img["configs"]["arm64"]["release"] == "1791414125" and img["release"] == "1791414125"
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
    (d / "sbom-1-arm64.spdx.json").unlink()
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("sbom-1-arm64.spdx.json" in p for p in probs)


def test_record_refuses_platforms_with_different_releases(tmp_path):
    froms, d, keys = evidence(tmp_path, releases={"arm64": "1791000000"})
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("release" in p and "arm64" in p for p in probs)


def test_record_refuses_an_index_without_arm64(tmp_path):
    index = json.dumps({"manifests": [{"digest": "sha256:" + "a" * 64,
                                       "platform": {"os": "linux", "architecture": "amd64"}}]}).encode()
    froms, d, keys = evidence(tmp_path, index_bytes=index)
    _rec, probs = br.record(froms, str(d), str(keys), "now")
    assert any("arm64" in p and "index" in p for p in probs)


import stat
import shutil
import zipfile

ci = load_script("packaging/container/check_image.py")
SHA = "a" * 40


COMMANDS = {"wd2l-sender": "wd2l.sender:main", "wd2l-receiver": "wd2l.receiver:main"}


def wrapper(target, shebang="#!/usr/sbin/python3"):
    """The console script pip writes for TARGET (pip 25's form, the builder's interpreter)."""
    module, attr = target.split(":")
    return ("%s\nimport sys\nfrom %s import %s\nif __name__ == '__main__':\n"
            "    sys.argv[0] = sys.argv[0].removesuffix('.exe')\n    sys.exit(%s())\n"
            % (shebang, module, attr, attr))


def wheel_and_rootfs(tmp_path, build=SHA):
    """A wheel and a rootfs that installed it, plus a base rootfs with the same rpmdb."""
    files = {"wd2l/__init__.py": b'__version__ = "0.3.0"\n', "wd2l/sender.py": b"def main(): pass\n",
             "wd2l/BUILD": (build + "\n").encode()}
    whl = tmp_path / "wd2l-0.3.0-py3-none-any.whl"
    with zipfile.ZipFile(str(whl), "w") as z:
        rec = []
        for name, data in files.items():
            z.writestr(name, data)
            h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
            rec.append("%s,sha256=%s,%d" % (name, h, len(data)))
        z.writestr("wd2l-0.3.0.dist-info/entry_points.txt", "[console_scripts]\n"
                   + "".join("%s = %s\n" % kv for kv in COMMANDS.items()))
        rec.append("wd2l-0.3.0.dist-info/entry_points.txt,,")
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
        (root / "usr/bin").mkdir()
        (root / "usr/bin/python3.12").write_bytes(b"\x7fELF")
        os.chmod(str(root / "usr/bin/python3.12"), 0o755)
        os.symlink("python3.12", str(root / "usr/bin/python3"))
        os.symlink("bin", str(root / "usr/sbin"))
        roots.append(root)
    site = roots[0] / "usr/lib/python3.12/site-packages"
    for name, data in files.items():
        (site / name).parent.mkdir(parents=True, exist_ok=True)
        (site / name).write_bytes(data)
    (site / "wd2l/__pycache__").mkdir()
    for stem in ("__init__", "sender"):
        (site / "wd2l/__pycache__" / (stem + ".cpython-312.pyc")).write_bytes(b"pyc")
    for command, target in COMMANDS.items():
        (roots[0] / "usr/bin" / command).write_text(wrapper(target))
        os.chmod(str(roots[0] / "usr/bin" / command), 0o755)
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


def test_files_the_wheel_does_not_have_are_refused(tmp_path):
    # Only the wheel's own rows were checked: anything added beside them passed (#159).
    whl, root, base = wheel_and_rootfs(tmp_path)
    wd2l = os.path.join(root, "usr/lib/python3.12/site-packages/wd2l")
    for rel in ("extra.py", "__pycache__/gone.cpython-312.pyc",
                "__pycache__/sender.cpython-312.opt-1.pyc", "data/x.txt"):
        os.makedirs(os.path.dirname(os.path.join(wd2l, rel)), exist_ok=True)
        open(os.path.join(wd2l, rel), "w").close()
    os.symlink("/etc", os.path.join(wd2l, "etc"))
    # A wheel file swapped for a link to the same bytes passes the hash check, read through it.
    shutil.move(os.path.join(wd2l, "sender.py"), os.path.join(root, "sender.py"))
    os.symlink(os.path.join(root, "sender.py"), os.path.join(wd2l, "sender.py"))
    probs = ci.check_wheel_files(root, whl, SHA)
    shown = "not in the wheel: /usr/lib/python3.12/site-packages/wd2l/"
    linked = "a symlink, not the wheel's file: /usr/lib/python3.12/site-packages/wd2l/"
    assert sorted(probs) == sorted([shown + rel for rel in (
        "extra.py", "__pycache__/gone.cpython-312.pyc", "__pycache__/sender.cpython-312.opt-1.pyc",
        "data", "data/x.txt")] + [linked + "etc", linked + "sender.py"])


def test_each_command_runs_its_entry_point_with_the_images_python(tmp_path):
    # The console scripts in /usr/bin weren't checked at all (#159).
    whl, root, base = wheel_and_rootfs(tmp_path)
    bin_ = os.path.join(root, "usr/bin")
    os.remove(os.path.join(bin_, "wd2l-sender"))
    with open(os.path.join(bin_, "wd2l-receiver"), "w") as f:
        f.write(wrapper("wd2l.sender:main", shebang="#!/usr/local/bin/python3"))
    with open(os.path.join(bin_, "wd2l-extra"), "w") as f:
        f.write(wrapper("wd2l.sender:main"))
    os.chmod(os.path.join(bin_, "wd2l-extra"), 0o644)
    assert sorted(ci.check_wheel_files(root, whl, SHA)) == sorted([
        "missing command: /usr/bin/wd2l-sender",
        "/usr/bin/wd2l-receiver runs '/usr/local/bin/python3', which the image doesn't have",
        "/usr/bin/wd2l-receiver doesn't run wd2l.receiver:main",
        "not in the wheel's entry points: /usr/bin/wd2l-extra"])


def test_a_command_must_import_and_call_its_entry_point(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    bin_ = os.path.join(root, "usr/bin")
    with open(os.path.join(bin_, "wd2l-sender"), "w") as f:
        f.write("#!/usr/sbin/python3\nimport sys\nfrom wd2l.sender import main\nsys.exit(0)\n")
    with open(os.path.join(bin_, "wd2l-receiver"), "w") as f:
        f.write("#!/usr/sbin/python3\nimport sys\nfrom wd2l import receiver as main\nsys.exit(main())\n")
    assert sorted(ci.check_wheel_files(root, whl, SHA)) == [
        "/usr/bin/wd2l-receiver doesn't run wd2l.receiver:main",
        "/usr/bin/wd2l-sender doesn't run wd2l.sender:main"]


def test_a_command_must_be_an_executable_python_file(tmp_path):
    whl, root, base = wheel_and_rootfs(tmp_path)
    bin_ = os.path.join(root, "usr/bin")
    os.chmod(os.path.join(bin_, "wd2l-sender"), 0o644)
    os.remove(os.path.join(bin_, "wd2l-receiver"))
    os.symlink("python3", os.path.join(bin_, "wd2l-receiver"))
    assert sorted(ci.check_wheel_files(root, whl, SHA)) == sorted([
        "not executable: /usr/bin/wd2l-sender",
        "/usr/bin/wd2l-receiver is a symlink, not pip's script"])


def test_the_interpreter_is_looked_up_inside_the_image(tmp_path):
    # An absolute symlink points into the image, not at the runner's own files.
    whl, root, base = wheel_and_rootfs(tmp_path)
    os.remove(os.path.join(root, "usr/bin/python3"))
    os.symlink("/usr/bin/python3.12", os.path.join(root, "usr/bin/python3"))
    assert ci.check_wheel_files(root, whl, SHA) == []
    os.remove(os.path.join(root, "usr/bin/python3.12"))
    probs = ci.check_wheel_files(root, whl, SHA)
    assert len(probs) == 2 and all("which the image doesn't have" in p for p in probs)


vg = load_script("packaging/container/vuln_gate.py")
TODAY = "2026-10-07"


def grype_doc(*matches, distro="hummingbird"):
    """Grype's JSON: it names the OS it found (null if none), and each match's package type."""
    return {"matches": [{"vulnerability": {"id": i, "severity": s,
                                           "fix": {"state": st, "versions": ["9"] if st == "fixed" else []}},
                         "artifact": {"name": p, "version": "1", "type": "rpm"}} for i, s, st, p in matches],
            "distro": {"name": distro, "version": "20251124", "idLike": ["fedora", "redhat"]} if distro else None,
            "descriptor": {"name": "grype", "version": "0.119.0"}}


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


def test_an_exception_lasts_90_days_at_most():
    # Policy said 90 days; only expiry was checked, so 2099 passed (#177). Counted from the scan:
    # an exception approved for at most 90 days never trips it later.
    _g, _e, probs = run_gate(grype_doc(), trivy_doc(), [exc("CVE-1", "x", expires="2027-01-05")])
    assert probs == []                                          # TODAY + 90 days
    _g, _e, probs = run_gate(grype_doc(), trivy_doc(), [exc("CVE-1", "x", expires="2027-01-06")])
    assert len(probs) == 1 and "CVE-1" in probs[0] and "more than 90 days" in probs[0]
    gated, _e, _p = run_gate(grype_doc(("CVE-1", "High", "fixed", "x")), trivy_doc(),
                             [exc("CVE-1", "x", expires="2099-01-01")])
    assert [f["id"] for f in gated] == ["CVE-1"]                # and it covers nothing


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
    # Findings never fail the build: they're recorded, and a review decides (#175).
    assert vg.main(args) == 0
    pred = json.loads(p.read_text())["gate"]
    assert pred["review_needed"] is True and pred["passed"] is False
    assert s.read_text().startswith("### Vulnerability scan: security review needed")
    assert "CVE-1" in s.read_text()
    assert vg.main(args + ["--exit-code", "3"]) == 3          # the weekly rescan's issue trigger
    e.write_text(json.dumps({"exceptions": [exc("CVE-1", "openssl-libs")]}))
    assert vg.main(args + ["--exit-code", "3"]) == 0
    assert json.loads(p.read_text())["gate"]["review_needed"] is False
    assert s.read_text().startswith("### Vulnerability scan: no review needed")


def test_an_exception_problem_needs_a_review_too(tmp_path):
    g, t, e = tmp_path / "g.json", tmp_path / "t.json", tmp_path / "e.json"
    g.write_text(json.dumps(grype_doc()))
    t.write_text(json.dumps(trivy_doc()))
    e.write_text(json.dumps({"exceptions": [exc("CVE-9", "x", expires="2026-10-01")]}))
    p, sm = tmp_path / "p.json", tmp_path / "s.md"
    args = ["--grype", str(g), "--trivy", str(t), "--exceptions", str(e), "--today", TODAY,
            "--predicate", str(p), "--summary", str(sm)]
    assert vg.main(args) == 0 and vg.main(args + ["--exit-code", "3"]) == 3
    assert json.loads(p.read_text())["gate"]["review_needed"] is True
    text = sm.read_text()
    assert text.startswith("### Vulnerability scan: security review needed")
    assert "**Exceptions to review**" in text and "CVE-9" in text


def test_the_summary_lists_every_finding_and_why_it_passed_the_gate():
    # The run's Summary tab and the release's vuln-summary.md show what was found, not only
    # what was gated.
    found = vg.grype_findings(grype_doc(("CVE-1", "Medium", "fixed", "zlib"),
                                        ("CVE-2", "High", "not-fixed", "glibc"),
                                        ("CVE-3", "Critical", "fixed", "openssl-libs"))) \
        + vg.trivy_findings(trivy_doc([("CVE-4", "LOW", "", "x")]))
    valid, probs = vg.load_exceptions({"exceptions": [exc("CVE-3", "openssl-libs")]}, TODAY)
    gated, excepted = vg.gate(found, valid)
    text = vg.summary(gated, excepted, probs, {"grype": 3, "trivy": 1}, found)
    rows = [line for line in text.splitlines() if line.startswith("| grype") or line.startswith("| trivy")]
    every = rows[-4:]                                   # the last table: every finding, worst first
    assert [r.split(" | ")[1] for r in every] == ["CVE-3", "CVE-2", "CVE-1", "CVE-4"]
    assert every[0].endswith("| exception |")
    assert every[1].endswith("| passed: no fix yet |")
    assert every[2].endswith("| passed: below High |")
    assert every[3].endswith("| passed: below High |")


def trivy_real(os_family="none", os_pkgs=(), lang_pkgs=()):
    """Trivy's JSON as 0.75 writes it: the OS it recognized ("none" if none), then one result per
    kind of package: (id, severity, package, version, fixed version)."""
    def vulns(rows):
        return [{"VulnerabilityID": i, "Severity": s, "PkgName": p, "InstalledVersion": v, "FixedVersion": f}
                for i, s, p, v, f in rows]
    results = [{"Target": "Python", "Class": "lang-pkgs", "Type": "python-pkg", "Vulnerabilities": vulns(lang_pkgs)}]
    if os_family != "none":
        results.insert(0, {"Target": "img (%s 1)" % os_family, "Class": "os-pkgs", "Type": os_family,
                           "Vulnerabilities": vulns(os_pkgs)})
    return {"SchemaVersion": 2, "ArtifactName": "/work/image/oci", "Results": results,
            "Metadata": {"OS": {"Family": os_family, "Name": "20251124" if os_family != "none" else ""}}}


def grype_python(*matches):
    """Grype finding language packages: (id, severity, package, version, fix state)."""
    doc = grype_doc()
    doc["matches"] = [{"vulnerability": {"id": i, "severity": s,
                                         "fix": {"state": st, "versions": ["9"] if st == "fixed" else []}},
                       "artifact": {"name": p, "version": v, "type": "python"}} for i, s, p, v, st in matches]
    return doc


def test_each_finding_has_a_kind():
    g = vg.grype_findings(grype_python(("CVE-1", "High", "urllib3", "2.7.0", "fixed")))
    g += vg.grype_findings(grype_doc(("CVE-2", "High", "fixed", "glibc")))
    t = vg.trivy_findings(trivy_real("redhat", os_pkgs=[("CVE-3", "HIGH", "glibc", "1", "2")],
                                     lang_pkgs=[("CVE-4", "LOW", "pip", "26.2", "")]))
    t += vg.trivy_findings(trivy_doc(secrets=["aws-access-key-id"]))
    assert [f["kind"] for f in g + t] == ["language", "os", "os", "language", "secret"]


def test_the_same_finding_from_both_scanners_is_merged_with_both_named():
    # Grype names an RPM's epoch and Trivy doesn't; the more severe rating and any fix win.
    found = vg.grype_findings(grype_doc(("CVE-1", "Medium", "not-fixed", "openssl-libs")))
    found[0]["version"] = "1:3.5.9-0.3.hum1"
    found += vg.trivy_findings(trivy_real("redhat", os_pkgs=[("CVE-1", "HIGH", "openssl-libs", "3.5.9-0.3.hum1",
                                                              "3.5.10-0.1.hum1")]))
    (m,) = vg.merge(found)
    assert m["scanners"] == ["grype", "trivy"] and m["scanner"] == "grype, trivy"
    assert (m["severity"], m["fixable"], m["fixed_in"]) == ("HIGH", True, "3.5.10-0.1.hum1")


@pytest.mark.parametrize("name, doc, os_name, covered", [
    ("grype", grype_doc(), "hummingbird 20251124", True),
    ("grype", grype_doc(distro=None), "", False),                          # no OS found
    ("grype", grype_doc(distro="wolfi"), "wolfi 20251124", False),         # an OS we have no evidence for
    ("trivy", trivy_real("none"), "", False),                              # upstream Trivy on Hummingbird
    ("trivy", trivy_real("hummingbird"), "hummingbird 20251124", False),   # Red Hat's build: recognized, no data
])
def test_coverage_is_judged_by_the_scanner_s_data_not_by_recognizing_the_os(name, doc, os_name, covered):
    c = vg.coverage(name, doc)
    assert (c["scanner"], c["os"], c["os_packages"]) == (name, os_name, covered)
    assert c["language_packages"] is True and c["secrets"] is (name == "trivy")


def test_no_scanner_covering_the_os_packages_needs_a_review(tmp_path):
    e = tmp_path / "e.json"
    e.write_text(json.dumps({"exceptions": []}))
    args = ["--exceptions", str(e), "--today", TODAY, "--summary", str(tmp_path / "s.md"),
            "--predicate", str(tmp_path / "p.json")]
    for name, doc in (("g", grype_doc(distro=None)), ("t", trivy_real("none"))):
        (tmp_path / (name + ".json")).write_text(json.dumps(doc))
    assert vg.main(args + ["--grype", str(tmp_path / "g.json"), "--trivy", str(tmp_path / "t.json"),
                           "--exit-code", "3"]) == 3
    pred = json.loads((tmp_path / "p.json").read_text())
    assert pred["gate"]["review_needed"] is True and pred["gate"]["uncovered_os"] is True
    assert "No scanner covered the operating system's packages" in (tmp_path / "s.md").read_text()
    (tmp_path / "g.json").write_text(json.dumps(grype_doc()))               # Grype covers them
    assert vg.main(args + ["--grype", str(tmp_path / "g.json"), "--trivy", str(tmp_path / "t.json"),
                           "--exit-code", "3"]) == 0
    pred = json.loads((tmp_path / "p.json").read_text())
    assert pred["gate"]["uncovered_os"] is False
    assert [(c["scanner"], c["os_packages"]) for c in pred["coverage"]] == [("grype", True), ("trivy", False)]


def test_a_finding_one_scanner_missed_though_it_covers_that_kind_is_a_disagreement():
    # The oldest base: Trivy found pip's vendored urllib3, which Syft (so Grype) never catalogs;
    # Grype found an RPM finding Trivy can't see, which is no disagreement: Trivy has no OS data.
    g = grype_doc(("CVE-2026-107708", "Medium", "fixed", "krb5-libs"))
    t = trivy_real("none", lang_pkgs=[("CVE-2026-97687", "HIGH", "urllib3", "2.7.0", "2.8.0")])
    covers = [vg.coverage("grype", g), vg.coverage("trivy", t)]
    merged = vg.merge(vg.grype_findings(g) + vg.trivy_findings(t))
    (d,) = vg.disagreements(merged, covers)
    assert (d["id"], d["package"], d["found_by"], d["missed_by"]) == ("CVE-2026-97687", "urllib3", ["trivy"], ["grype"])


def test_annotations_name_each_scanner_without_os_data(tmp_path, capsys):
    for name, doc in (("g", grype_doc()), ("t", trivy_real("none")), ("e", {"exceptions": []})):
        (tmp_path / (name + ".json")).write_text(json.dumps(doc))
    vg.main(["--grype", str(tmp_path / "g.json"), "--trivy", str(tmp_path / "t.json"), "--exceptions",
             str(tmp_path / "e.json"), "--today", TODAY, "--summary", str(tmp_path / "s.md"), "--annotate"])
    out = capsys.readouterr().out
    assert out == ("::warning title=trivy::trivy has no advisory data for this image's operating system "
                   "(not recognized), so it checked only language packages and secrets. grype covered the "
                   "OS packages.\n")


def test_the_summary_shows_coverage_found_by_and_disagreements():
    g = grype_doc(("CVE-1", "High", "not-fixed", "krb5-libs"))
    t = trivy_real("none", lang_pkgs=[("CVE-2", "HIGH", "urllib3", "2.7.0", "2.8.0")])
    covers = [vg.coverage("grype", g), vg.coverage("trivy", t)]
    merged = vg.merge(vg.grype_findings(g) + vg.trivy_findings(t))
    gated, excepted = vg.gate(merged, [])
    text = vg.summary(gated, excepted, [], {"grype": 1, "trivy": 1}, merged, coverage=covers,
                      disagreements=vg.disagreements(merged, covers))
    assert "| grype | hummingbird 20251124 | yes | yes | no |" in text
    assert "| trivy | not recognized | **no** | yes | yes |" in text
    assert "**Found by one scanner, missed by another that covers it**" in text
    assert "| CVE-2 | urllib3 | 2.7.0 | trivy | grype |" in text
    assert "| Found by | ID | Package | Version | Severity | Fixed in | Gate |" in text


def test_without_a_summary_file_the_summary_goes_to_stdout_and_with_one_it_doesnt(tmp_path, capsys):
    for name, doc in (("g", grype_doc()), ("t", trivy_real("none")), ("e", {"exceptions": []})):
        (tmp_path / (name + ".json")).write_text(json.dumps(doc))
    args = ["--grype", str(tmp_path / "g.json"), "--trivy", str(tmp_path / "t.json"),
            "--exceptions", str(tmp_path / "e.json"), "--today", TODAY]
    vg.main(args)
    assert capsys.readouterr().out.startswith("### Vulnerability scan: no review needed")
    vg.main(args + ["--summary", str(tmp_path / "s.md")])
    assert capsys.readouterr().out == ""


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
