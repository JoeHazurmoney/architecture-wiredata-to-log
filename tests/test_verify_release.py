"""verify-release (packaging/release/verify_release.py): a customer checks a release offline,
from its files alone (docs/decisions/0008-release-manifest.md)."""

import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tarfile

import pytest

from helpers import load_script

vr = load_script("packaging/release/verify_release.py")
pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def git(cwd, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com")
    return subprocess.run(("git", "-c", "init.defaultBranch=main", "-c", "tag.gpgSign=false",
                           "-c", "commit.gpgSign=false") + args, cwd=cwd, env=env, check=True,
                          capture_output=True, text=True).stdout.strip()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def release_dir(tmp_path, dry_run=False, commit=None):
    """A release's files: a wheel, the source bundle, the manifest and SHA256SUMS."""
    src, d = tmp_path / "src", tmp_path / "release"
    src.mkdir()
    d.mkdir()
    git(src, "init", "-q")
    (src / "README").write_text("wd2l\n")
    git(src, "add", "README")
    git(src, "commit", "-q", "-m", "Initial commit")
    git(src, "tag", "-a", "v1.0.0", "-m", "1.0.0")
    head = git(src, "rev-parse", "HEAD")
    git(src, "bundle", "create", str(d / "wd2l-1.0.0-source.bundle"), "HEAD", "v1.0.0")
    (d / "wd2l-1.0.0-py3-none-any.whl").write_bytes(b"wheel")
    files = ["wd2l-1.0.0-py3-none-any.whl", "wd2l-1.0.0-source.bundle"]
    man = {"release": {"tag": "v1.0.0", "dry_run": dry_run}, "source": {"commit": commit or head},
           "deliverables": [{"name": n, "size": (d / n).stat().st_size, "sha256": sha((d / n).read_bytes())}
                            for n in files]}
    (d / "wd2l-1.0.0-release-manifest.json").write_text(json.dumps(man))
    files.append("wd2l-1.0.0-release-manifest.json")
    (d / "SHA256SUMS").write_text("".join("%s  %s\n" % (sha((d / n).read_bytes()), n) for n in files))
    (d / "SHA256SUMS.sigstore.json").write_text("{}")
    return d


def fake_cosign(tmp_path, code=0):
    p = tmp_path / ("cosign%d" % code)
    p.write_text("#!/bin/sh\necho fake cosign >&2\nexit %d\n" % code)
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def by_check(results):
    return {check: (status, detail) for status, check, detail in results}


@pytest.fixture(autouse=True)
def outside_any_repository(tmp_path, monkeypatch):
    # A customer runs it in a directory of release files, not in a git checkout: `git bundle
    # verify` refuses to run outside a repository (found on a dry run's files, offline).
    monkeypatch.chdir(tmp_path)


def test_a_good_release_passes_every_check(tmp_path):
    d = release_dir(tmp_path)
    r = by_check(vr.verify(str(d), "cosign.pub", cosign=fake_cosign(tmp_path)))
    assert [r[c][0] for c in ("signature", "checksums", "manifest", "source")] == ["ok"] * 4
    assert r["image"][0] == "skip"
    assert "v1.0.0 is the manifest's commit" in r["source"][1]


def test_a_changed_byte_fails_the_checksums_and_the_manifest(tmp_path):
    d = release_dir(tmp_path)
    (d / "wd2l-1.0.0-py3-none-any.whl").write_bytes(b"whee!")
    r = by_check(vr.verify(str(d), None, skip_signature=True))
    assert r["checksums"] == ("FAIL", "wd2l-1.0.0-py3-none-any.whl differs")
    assert r["manifest"][0] == "ok"      # the manifest still agrees with the signed SHA256SUMS


def test_a_manifest_that_disagrees_with_sha256sums_fails(tmp_path):
    d = release_dir(tmp_path)
    man = json.loads((d / "wd2l-1.0.0-release-manifest.json").read_text())
    man["deliverables"][0]["sha256"] = "0" * 64
    (d / "wd2l-1.0.0-release-manifest.json").write_text(json.dumps(man))
    r = by_check(vr.verify(str(d), None, skip_signature=True))
    assert r["manifest"][0] == "FAIL" and "not as in SHA256SUMS" in r["manifest"][1]
    assert r["checksums"][0] == "FAIL"   # and SHA256SUMS no longer matches the manifest file


def test_a_bundle_whose_tag_isnt_the_manifests_commit_fails(tmp_path):
    d = release_dir(tmp_path, commit="1" * 40)
    r = by_check(vr.verify(str(d), None, skip_signature=True))
    assert r["source"][0] == "FAIL" and "the manifest says 1111" in r["source"][1]


def test_a_dry_runs_bundle_is_checked_at_head(tmp_path):
    r = by_check(vr.verify(str(release_dir(tmp_path, dry_run=True)), None, skip_signature=True))
    assert r["source"][0] == "ok" and "HEAD" in r["source"][1]


def test_the_signature_needs_a_key_cosign_and_its_verdict(tmp_path):
    d = str(release_dir(tmp_path))
    assert by_check(vr.verify(d, None))["signature"] == ("FAIL", "no --key given")
    assert "not found" in by_check(vr.verify(d, "k", cosign="no-such-cosign"))["signature"][1]
    assert by_check(vr.verify(d, "k", cosign=fake_cosign(tmp_path, 1)))["signature"][0] == "FAIL"


def image_tar(path, names):
    with tarfile.open(path, "w") as t:
        for n in names:
            info = tarfile.TarInfo(n)
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))


def test_the_image_tar_is_checked_with_cosign_and_unsafe_paths_are_refused(tmp_path):
    d = release_dir(tmp_path)
    image_tar(d / "good-oci.tar", ["wd2l-oci/index.json"])
    image_tar(d / "evil-oci.tar", ["../evil"])
    ok = fake_cosign(tmp_path)
    assert by_check(vr.verify(str(d), "k", "good-oci.tar", cosign=ok))["image"][0] == "ok"
    assert "unsafe path" in by_check(vr.verify(str(d), "k", "evil-oci.tar", cosign=ok))["image"][1]


def container_cosign(tmp_path):
    """cosign as it runs from the saved image (releasing.md): only the current directory is
    mounted, so it fails on any absolute path, and on an OCI layout it can't see from there."""
    p = tmp_path / "container-cosign"
    p.write_text('#!/bin/sh\n'
                 'for a; do case "$a" in /*) echo "not mounted: $a" >&2; exit 1;; esac; done\n'
                 'while [ $# -gt 0 ]; do\n'
                 '  if [ "$1" = --local-image ] && [ ! -f "$2/index.json" ]; then\n'
                 '    echo "no $2/index.json" >&2; exit 1\n'
                 '  fi\n'
                 '  shift\n'
                 'done\n')
    p.chmod(p.stat().st_mode | stat.S_IEXEC)
    return str(p)


def test_cosign_from_a_container_that_mounts_only_the_release_dir_passes(tmp_path, monkeypatch):
    # The retrieval drill (#38, #109): the image check extracted to /tmp and gave cosign that
    # absolute path, which the container doesn't have.
    d = release_dir(tmp_path)
    image_tar(d / "good-oci.tar", ["wd2l-oci/index.json"])
    monkeypatch.chdir(d)
    results = vr.verify(".", "cosign.pub", "good-oci.tar", cosign=container_cosign(tmp_path))
    assert [(s, c) for s, c, _ in results] == [("ok", c) for _, c, _ in results], results
    assert not list(d.glob(".verify-release-*"))      # the extracted image is cleaned up


def test_release_files_on_read_only_media_are_extracted_to_the_temp_dir(tmp_path, monkeypatch):
    d = release_dir(tmp_path)
    image_tar(d / "good-oci.tar", ["wd2l-oci/index.json"])
    real = vr.tempfile.TemporaryDirectory

    def read_only(*args, **kwargs):
        if kwargs.get("dir") is not None:
            raise PermissionError(13, "Read-only file system", kwargs["dir"])
        return real(*args, **kwargs)

    monkeypatch.setattr(vr.tempfile, "TemporaryDirectory", read_only)
    r = by_check(vr.verify(str(d), "k", "good-oci.tar", cosign=fake_cosign(tmp_path)))
    assert r["image"][0] == "ok", r["image"]


def test_cli_prints_one_line_per_check_and_fails_on_any_failure(tmp_path, capsys):
    d = release_dir(tmp_path)
    assert vr.main(["--dir", str(d), "--skip-signature"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[-1] == "release: verified" and out.count("\n") == 6
    (d / "wd2l-1.0.0-source.bundle").unlink()
    assert vr.main(["--dir", str(d), "--skip-signature"]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_without_a_manifest_nothing_is_checked(tmp_path):
    (tmp_path / "SHA256SUMS").write_text("")
    assert vr.verify(str(tmp_path), None)[0][0] == "FAIL"
