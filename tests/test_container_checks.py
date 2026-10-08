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
