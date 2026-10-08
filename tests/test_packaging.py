import io
import os
import re
import tarfile
import zipfile

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
check_dist = load_script("packaging/check_dist.py")


def read(rel):
    with open(os.path.join(REPO, rel)) as f:
        return f.read()


def test_version_has_one_source():
    py = read("pyproject.toml")
    project = py.split("[project]", 1)[1].split("\n[", 1)[0]
    assert 'dynamic = ["version"]' in project
    assert not re.search(r"^version\s*=", project, re.M)
    assert 'version = {attr = "wd2l.__version__"}' in py
    assert check_dist.repo_version() == __import__("wd2l").__version__


def test_license_is_mit():
    assert read("LICENSE").startswith("MIT License\n\nCopyright (c) 2026 ")
    py = read("pyproject.toml")
    assert 'license = "MIT"' in py and 'license-files = ["LICENSE"]' in py
    assert 'requires = ["setuptools>=77"]' in py


def test_build_file_and_rpm_sources_ship_in_the_sdist():
    assert 'wd2l = ["BUILD"]' in read("pyproject.toml")
    manifest = read("MANIFEST.in").splitlines()
    for line in ("include LICENSE", "include wd2l/BUILD", "graft deploy", "graft packaging",
                 "global-exclude __pycache__ *.py[cod]"):
        assert line in manifest, line


def make_wheel(path, version="0.3.0", build="abc123", scripts=check_dist.SCRIPTS,
               license_expr="MIT", license_file=True):
    di = "wd2l-%s.dist-info/" % version
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("wd2l/__init__.py", '__version__ = "%s"\n' % version)
        if build is not None:
            z.writestr("wd2l/BUILD", build + "\n")
        z.writestr(di + "entry_points.txt",
                   "[console_scripts]\n" + "".join("%s = m:main\n" % s for s in scripts))
        z.writestr(di + "METADATA", "Metadata-Version: 2.4\nName: wd2l\nVersion: %s\n"
                                    "License-Expression: %s\n" % (version, license_expr))
        if license_file:
            z.writestr(di + "licenses/LICENSE", "MIT License\n")


def make_sdist(path, version="0.3.0", members=check_dist.SDIST_NEEDS):
    with tarfile.open(path, "w:gz") as t:
        for m in members:
            info = tarfile.TarInfo("wd2l-%s/%s" % (version, m))
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))


def good_dist(tmp_path, version="0.3.0"):
    make_wheel(str(tmp_path / ("wd2l-%s-py3-none-any.whl" % version)), version)
    make_sdist(str(tmp_path / ("wd2l-%s.tar.gz" % version)), version)


def test_good_dist_passes(tmp_path):
    good_dist(tmp_path)
    assert check_dist.check(str(tmp_path), "0.3.0", "abc123") == []


def test_prerelease_names_pass(tmp_path):
    good_dist(tmp_path, "0.3.0rc1")
    assert check_dist.check(str(tmp_path), "0.3.0rc1", "abc123") == []


def test_wheel_problems_are_each_named(tmp_path):
    make_wheel(str(tmp_path / "wd2l-0.3.0-py3-none-any.whl"), build=None,
               scripts=("wd2l-sender",), license_expr="Proprietary", license_file=False)
    make_sdist(str(tmp_path / "wd2l-0.3.0.tar.gz"))
    probs = "\n".join(check_dist.check(str(tmp_path), "0.3.0", "abc123"))
    for word in ("BUILD", "wd2l-receiver", "wd2l-audit-report", "License-Expression",
                 "licenses/LICENSE"):
        assert word in probs, word


def test_wrong_commit_and_wrong_version(tmp_path):
    good_dist(tmp_path)
    assert any("BUILD" in p for p in check_dist.check(str(tmp_path), "0.3.0", "def456"))
    probs = check_dist.check(str(tmp_path), "0.4.0", "abc123")
    assert any("wheel name" in p for p in probs) and any("sdist name" in p for p in probs)


def test_sdist_must_carry_the_deploy_tree(tmp_path):
    make_wheel(str(tmp_path / "wd2l-0.3.0-py3-none-any.whl"))
    make_sdist(str(tmp_path / "wd2l-0.3.0.tar.gz"),
               members=[m for m in check_dist.SDIST_NEEDS if not m.startswith("deploy/")])
    probs = check_dist.check(str(tmp_path), "0.3.0", "abc123")
    assert any("deploy/log-server/wd2l-sender.service" in p for p in probs)


def test_exactly_one_wheel_and_one_sdist(tmp_path):
    probs = check_dist.check(str(tmp_path), "0.3.0", "abc123")
    assert any("one wheel" in p for p in probs) and any("one sdist" in p for p in probs)
