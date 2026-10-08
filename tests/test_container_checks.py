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
