import json
import os

import pytest

from helpers import load_script

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
versions = load_script("packaging/release/versions.py")
prov = load_script("packaging/release/provenance.py")


def test_final_release_names():
    assert versions.names("0.3.0") == {"pep440": "0.3.0", "tag": "v0.3.0", "rpm": "0.3.0",
                                       "image_tags": ["0.3.0", "0.3"], "prerelease": False}


@pytest.mark.parametrize("v, rpm", [("0.3.0rc1", "0.3.0~rc1"), ("1.0.0a2", "1.0.0~a2"),
                                    ("1.0.0b1", "1.0.0~b1")])
def test_prerelease_names(v, rpm):
    n = versions.names(v)
    assert n["rpm"] == rpm and n["tag"] == "v" + v and n["image_tags"] == [v] and n["prerelease"]


@pytest.mark.parametrize("bad", ["0.3", "v0.3.0", "0.3.0-rc.1", "0.3.0.post1", "0.3.0rc"])
def test_versions_outside_the_scheme_are_refused(bad):
    with pytest.raises(ValueError):
        versions.names(bad)


def rpmvercmp(a, b):
    """RPM's version comparison, enough for X.Y.Z[~preN] (tilde sorts before anything)."""
    def key(v):
        main, _, pre = v.partition("~")
        return ([int(x) for x in main.split(".")], 0 if pre else 1, pre)
    return (key(a) > key(b)) - (key(a) < key(b))


def test_a_prerelease_rpm_sorts_before_the_release():
    assert rpmvercmp(versions.names("0.3.0rc1")["rpm"], versions.names("0.3.0")["rpm"]) < 0
    assert rpmvercmp(versions.names("0.3.0")["rpm"], versions.names("0.3.1rc1")["rpm"]) < 0


def test_check_tag_and_github_output(tmp_path):
    v = versions.read_version()
    assert versions.main(["--check-tag", "v" + v]) == 0
    assert versions.main(["--check-tag", "v9.9.9"]) == 1
    out = tmp_path / "out"
    assert versions.main(["--github-output", str(out)]) == 0
    lines = dict(x.split("=", 1) for x in out.read_text().splitlines())
    assert lines["pep440"] == v and lines["tag"] == "v" + v and lines["prerelease"] in ("true", "false")


ENV = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": "JoeHazurmoney/r",
       "GITHUB_REF": "refs/tags/v0.3.0", "GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "77",
       "GITHUB_RUN_ATTEMPT": "1", "GITHUB_EVENT_NAME": "push", "RUNNER_ENVIRONMENT": "github-hosted",
       "GITHUB_WORKFLOW_REF": "JoeHazurmoney/r/.github/workflows/release.yml@refs/tags/v0.3.0"}
FROMS = [{"ref": "r/hi/python:3.12-fips-builder@sha256:" + "1" * 64, "stage": "build",
          "name": "r/hi/python", "tag": "3.12-fips-builder", "digest": "sha256:" + "1" * 64},
         {"ref": "r/hi/python:3.12-fips@sha256:" + "2" * 64, "stage": None, "name": "r/hi/python",
          "tag": "3.12-fips", "digest": "sha256:" + "2" * 64}]


def test_provenance_names_the_commit_the_wheel_and_both_bases():
    p = prov.predicate(ENV, "wd2l-0.3.0-py3-none-any.whl", "c" * 64, FROMS,
                       "ghcr.io/o/wd2l-base/python", "t0", "t1")
    deps = p["buildDefinition"]["resolvedDependencies"]
    assert deps[0] == {"uri": "git+https://github.com/JoeHazurmoney/r@refs/tags/v0.3.0",
                       "digest": {"gitCommit": "a" * 40}}
    assert deps[1] == {"uri": "wd2l-0.3.0-py3-none-any.whl", "digest": {"sha256": "c" * 64}}
    assert [d["digest"]["sha256"] for d in deps[2:]] == ["1" * 64, "2" * 64]
    assert deps[3]["annotations"] == {"stage": "runtime",
                                      "mirror": "ghcr.io/o/wd2l-base/python@sha256:" + "2" * 64}
    assert p["runDetails"]["builder"]["id"] == "https://github.com/" + ENV["GITHUB_WORKFLOW_REF"]
    assert p["runDetails"]["metadata"]["invocationId"].endswith("/actions/runs/77/attempts/1")
    json.dumps(p)


def test_signing_config_names_no_log_and_no_timestamp_service():
    with open(os.path.join(REPO, "packaging", "release", "signing-config.json")) as f:
        sc = json.load(f)
    assert sc["mediaType"] == "application/vnd.dev.sigstore.signingconfig.v0.2+json"
    assert sc.get("rekorTlogConfig") == {} and sc.get("tsaConfig") == {}
    assert not any(k in sc for k in ("rekorTlogUrls", "tsaUrls", "caUrls", "oidcUrls"))


notes = load_script("packaging/release/notes.py")
SUMS = ("%s  wd2l-0.3.0-py3-none-any.whl\n%s  wd2l-0.3.0-1.el10.noarch.rpm\n"
        "%s  wd2l-0.3.0-image-oci.tar\n" % ("a" * 64, "b" * 64, "c" * 64))
RECORD = {"images": [
    {"ref": "r/hi/python:3.12-fips-builder@sha256:" + "1" * 64, "stage": "build",
     "index_digest": "sha256:" + "1" * 64, "source_image": "r/hi/python:111-source"},
    {"ref": "r/hi/python:3.12-fips@sha256:" + "2" * 64, "stage": "runtime",
     "index_digest": "sha256:" + "2" * 64, "source_image": "r/hi/python:222-source"}]}
ARGS = dict(image="ghcr.io/joehazurmoney/wd2l", digest="sha256:" + "d" * 64, sums_text=SUMS,
            base_record=RECORD, repo_url="https://github.com/o/r",
            run_url="https://github.com/o/r/actions/runs/7", commit="e" * 40)


def test_notes_name_every_asset_the_image_and_its_bases():
    text = notes.notes(versions.names("0.3.0"), **ARGS)
    for part in ("wd2l-0.3.0-py3-none-any.whl", "b" * 64, "ghcr.io/joehazurmoney/wd2l@sha256:" + "d" * 64,
                 "r/hi/python:3.12-fips@sha256:" + "2" * 64, "r/hi/python:222-source",
                 "cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
                 "sha256sum -c SHA256SUMS", "--local-image wd2l-oci", "e" * 40,
                 "https://github.com/o/r/blob/v0.3.0/docs/releasing.md"):
        assert part in text, part
    assert "Pre-release" not in text


def test_prerelease_notes_say_so_and_dry_runs_have_no_digest():
    text = notes.notes(versions.names("0.3.0rc1"), **dict(ARGS, digest=""))
    assert text.startswith("> **Pre-release**") and "not published (dry run)" in text


def test_only_a_tag_on_main_is_released_and_its_name_never_runs_as_shell():
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".github",
                           "workflows", "release.yml")) as f:
        wf = f.read()
    version = wf.split("\n  version:\n", 1)[1].split("\n  tests:\n", 1)[0]
    assert "fetch-depth: 0" in version
    assert 'git merge-base --is-ancestor "$GITHUB_SHA" origin/main' in version
    assert "TAG: ${{ github.ref_name }}" in version
    assert "${{ github.ref_name }}\"" not in wf      # never inside a run: script


def test_cosign_pub_is_a_public_key_and_never_a_private_one():
    with open(os.path.join(REPO, "cosign.pub")) as f:
        text = f.read()
    assert text.startswith("-----BEGIN PUBLIC KEY-----") and "PRIVATE" not in text
    assert not os.path.exists(os.path.join(REPO, "cosign.key"))
