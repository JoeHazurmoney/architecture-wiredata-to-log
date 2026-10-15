import hashlib
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
        "%s  wd2l-0.3.0-image-amd64-oci.tar\n%s  wd2l-0.3.0-image-arm64-oci.tar\n"
        % ("a" * 64, "b" * 64, "c" * 64, "f" * 64))
PLATFORMS = {"amd64": "sha256:" + "8" * 64, "arm64": "sha256:" + "9" * 64}
RECORD = {"images": [
    {"ref": "r/hi/python:3.12-fips-builder@sha256:" + "1" * 64, "stage": "build",
     "index_digest": "sha256:" + "1" * 64, "source_image": "r/hi/python:111-source"},
    {"ref": "r/hi/python:3.12-fips@sha256:" + "2" * 64, "stage": "runtime",
     "index_digest": "sha256:" + "2" * 64, "source_image": "r/hi/python:222-source"}]}
ARGS = dict(image="ghcr.io/joehazurmoney/wd2l", digest="sha256:" + "d" * 64, sums_text=SUMS,
            base_record=RECORD, repo_url="https://github.com/o/r",
            run_url="https://github.com/o/r/actions/runs/7", commit="e" * 40, platforms=PLATFORMS)


def test_notes_name_every_asset_the_image_and_its_bases():
    text = notes.notes(versions.names("0.3.0"), **ARGS)
    for part in ("wd2l-0.3.0-py3-none-any.whl", "b" * 64, "ghcr.io/joehazurmoney/wd2l@sha256:" + "d" * 64,
                 "r/hi/python:3.12-fips@sha256:" + "2" * 64, "r/hi/python:222-source",
                 "cosign verify-blob --key cosign.pub --insecure-ignore-tlog --bundle SHA256SUMS.sigstore.json SHA256SUMS",
                 "sha256sum -c SHA256SUMS", "tar -xf wd2l-0.3.0-image-amd64-oci.tar",
                 "--local-image wd2l-oci", "| linux/arm64 | `sha256:" + "9" * 64 + "` |",
                 "wd2l-0.3.0-image-arm64-oci.tar", "e" * 40,
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


def workflow(name):
    with open(os.path.join(REPO, ".github", "workflows", name)) as f:
        return f.read()


def test_asset_names_are_what_github_serves_before_sha256sums_lists_them():
    # GitHub turns "~" in an asset name into ".": a pre-release RPM (X.Y.Z~rcN) would be
    # downloaded under a name SHA256SUMS doesn't list (found on v0.3.0rc1).
    job = workflow("release.yml").split("- name: Assemble the assets", 1)[1].split("\n  attest:\n", 1)[0]
    rename = job.index(r'mv -- "$f" "${f//\~/.}"')
    # ...and the manifest lists the served names too: it's made between the two.
    assert rename < job.index("manifest.py generate") < job.index("sha256sum -- *")


def test_changelog_range_follows_double_dash():
    # git-cliff's --repository takes several paths, so a range after it is read as a second
    # repository ("No such file or directory"). 1.0.1 was the first release with a range (#105).
    cmd = workflow("release.yml").split("packaging/ci/tool git-cliff", 1)[1].split("\n          #", 1)[0]
    assert cmd.rstrip().endswith('-- ${prev:+"$prev..HEAD"}')
    assert cmd.index("--repository /work") < cmd.index("--output") < cmd.index(" -- ")


def test_signing_jobs_use_the_release_environment():
    rel, pub = workflow("release.yml"), workflow("publish.yml")
    assert "environment: ${{ startsWith(github.ref, 'refs/tags/v') && 'release' || '' }}" in rel
    # A reusable workflow's job gets an environment secret only if the caller passes it, by name
    # or with inherit; otherwise it's silently empty (#103). By name: nothing else is passed.
    call = rel.split("\n  publish:\n", 1)[1].split("\n  assets:\n", 1)[0]
    assert "secrets: inherit" not in rel
    assert ("    secrets:\n      COSIGN_PRIVATE_KEY: ${{ secrets.COSIGN_PRIVATE_KEY }}\n"
            "      COSIGN_PASSWORD: ${{ secrets.COSIGN_PASSWORD }}\n") in call
    # ...and publish.yml requires both, so a call without them fails to start.
    declared = pub.split("  workflow_call:\n", 1)[1].split("    outputs:\n", 1)[0]
    for name in ("COSIGN_PRIVATE_KEY", "COSIGN_PASSWORD"):
        assert "      %s:\n        required: true\n" % name in declared
    publish_job = pub.split("\n  publish:\n", 1)[1].split("\n  verify-published:\n", 1)[0]
    assert "    environment: release\n" in publish_job
    # tests.yml's code-scanning job asks for security-events: write; a caller must grant it,
    # or the whole release run fails to start.
    tests_job = rel.split("\n  tests:\n", 1)[1].split("\n  image:\n", 1)[0]
    assert "security-events: write" in tests_job


def test_publish_checks_the_signing_key_before_it_pushes_anything():
    # An empty, malformed or wrong key, or a wrong password, used to surface only at signing,
    # after the images were pushed (#103). The key's public half must be cosign.pub first.
    job = workflow("publish.yml").split("\n  publish:\n", 1)[1].split("\n  verify-published:\n", 1)[0]
    check = job.index("cosign public-key --key env://COSIGN_PRIVATE_KEY")
    assert "cosign.pub" in job[check:job.index("\n      - ", check)]
    assert check < job.index("podman login ghcr.io")


def test_notes_show_how_to_verify_the_github_attestations():
    text = notes.notes(versions.names("0.4.0"), **ARGS)
    pin = ("--repo o/r --signer-workflow o/r/.github/workflows/attest.yml "
           "--source-ref refs/tags/v0.4.0 --deny-self-hosted-runners")
    assert "gh attestation verify wd2l-0.4.0-py3-none-any.whl " + pin in text
    assert "gh attestation verify oci://ghcr.io/joehazurmoney/wd2l@sha256:%s %s --bundle-from-oci" % (
        "d" * 64, pin) in text
    assert "--bundle wd2l-0.4.0-attestations.jsonl --custom-trusted-root trusted_root.jsonl" in text


def test_dry_run_notes_have_no_platform_table():
    text = notes.notes(versions.names("0.4.0"), **dict(ARGS, digest="", platforms={}))
    assert "| linux/amd64 |" not in text


def test_dry_run_notes_have_no_image_attestation_line():
    text = notes.notes(versions.names("0.4.0"), **dict(ARGS, digest=""))
    assert "gh attestation verify wd2l-0.4.0-py3-none-any.whl" in text
    assert "gh attestation verify oci://" not in text


def test_releasing_md_pins_the_signer_workflow_and_the_tag():
    with open(os.path.join(REPO, "docs", "releasing.md"), encoding="utf-8") as f:
        doc = f.read()
    assert "## GitHub build provenance, offline" in doc
    assert "--signer-workflow JoeHazurmoney/architecture-wiredata-to-log/.github/workflows/attest.yml" in doc
    assert "--source-ref refs/tags/v<version>" in doc
    assert "gh attestation trusted-root > trusted_root.jsonl" in doc
    assert "done < SHA256SUMS" in doc          # every listed file, not a few globs
    assert ("--certificate-identity https://github.com/JoeHazurmoney/architecture-wiredata-to-log"
            "/.github/workflows/attest.yml@refs/tags/v<version>") in doc
    assert "--certificate-github-workflow-repository JoeHazurmoney/architecture-wiredata-to-log" in doc


image_index = load_script("packaging/release/image_index.py")


def _index_case(drop=None, wrong_config=None):
    manifests, ids, entries = {}, {}, []
    for arch in ("amd64", "arm64"):
        ids[arch] = hashlib.sha256(arch.encode()).hexdigest()
        cfg = "sha256:" + ("0" * 64 if arch == wrong_config else ids[arch])
        m = json.dumps({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "config": {"digest": cfg}}).encode()
        manifests[arch] = m
        if arch != drop:
            entries.append({"mediaType": "application/vnd.oci.image.manifest.v1+json",
                            "digest": "sha256:" + hashlib.sha256(m).hexdigest(),
                            "platform": {"os": "linux", "architecture": arch}})
    index = json.dumps({"mediaType": "application/vnd.oci.image.index.v1+json",
                        "manifests": entries}).encode()
    return index, "sha256:" + hashlib.sha256(index).hexdigest(), manifests, ids


def test_image_index_names_each_platform_digest():
    index, digest, manifests, ids = _index_case()
    got, probs = image_index.check(index, digest, manifests, ids)
    assert probs == [] and set(got) == {"amd64", "arm64"}
    assert got["arm64"] == "sha256:" + hashlib.sha256(manifests["arm64"]).hexdigest()


def test_image_index_refuses_a_missing_platform_or_an_untested_image():
    index, digest, manifests, ids = _index_case(drop="arm64")
    assert any("linux/arm64" in p for p in image_index.check(index, digest, manifests, ids)[1])
    index, digest, manifests, ids = _index_case(wrong_config="amd64")
    assert any("amd64" in p and "tested" in p for p in image_index.check(index, digest, manifests, ids)[1])
    index, digest, manifests, ids = _index_case()
    assert any("index" in p for p in image_index.check(index, "sha256:" + "0" * 64, manifests, ids)[1])


def test_release_assets_name_each_platform():
    step = workflow("release.yml").split("- name: Assemble the assets", 1)[1].split("- name:", 1)[0]
    for part in ('"assets/wd2l-$V-image-$a.spdx.json"', '"assets/wd2l-$V-image-$a.cdx.json"',
                 '"assets/wd2l-$V-vuln-summary-$a.md"', '"image-release/wd2l-$V-image-"*-oci.tar'):
        assert part in step, part
    notes_step = workflow("release.yml").split("- name: Notes", 1)[1].split("- name:", 1)[0]
    assert "--platform-digest amd64=${{ needs.publish.outputs.digest_amd64 }}" in notes_step


def test_notes_skip_a_platform_without_a_digest(tmp_path, capsys):
    # On a dry run publish is skipped, so release.yml passes "amd64=" and "arm64=".
    sums = tmp_path / "SHA256SUMS"
    sums.write_text(SUMS)
    rec = tmp_path / "record.json"
    rec.write_text(json.dumps(RECORD))
    assert notes.main(["--sums", str(sums), "--base-record", str(rec), "--repo-url", "https://github.com/o/r",
                       "--run-url", "u", "--commit", "e" * 40, "--image-digest", "",
                       "--platform-digest", "amd64=", "--platform-digest", "arm64="]) == 0
    assert "| linux/amd64 |" not in capsys.readouterr().out


def test_releasing_md_brings_in_one_platform():
    with open(os.path.join(REPO, "docs", "releasing.md"), encoding="utf-8") as f:
        doc = f.read()
    assert "tar -xf wd2l-<version>-image-<arch>-oci.tar" in doc
    assert "sudo skopeo copy oci:wd2l-oci containers-storage:ghcr.io/joehazurmoney/wd2l:<version>" in doc


def test_releasing_md_names_the_attestation_types_publish_uses():
    with open(os.path.join(REPO, "docs", "releasing.md"), encoding="utf-8") as f:
        doc = f.read()
    pub = workflow("publish.yml")
    for t in ("base-image-record/v2", "vuln-scan/v1"):
        assert t in pub and "/attestations/" + t in doc, t
    assert "base-image-record/v1" not in doc
    assert "wd2l-<version>-vuln-summary-<arch>.md" in doc and "`vuln-<arch>`" in doc


def example_manifest():
    with open(os.path.join(REPO, "packaging", "release", "release-manifest.example.json")) as f:
        return json.load(f)


def test_notes_carry_the_summary_and_the_issues_from_the_manifest():
    man = example_manifest()
    man["changes"]["issues_resolved"][0]["title"] = "Spool <dropped> | full disk"
    text = notes.notes(versions.names("1.1.0"), **dict(ARGS, man=man))
    assert text.index("## What changed since 1.0.0") < text.index("## Issues resolved (1)") < text.index("## Install")
    assert "Since v1.0.0. The full record" in text and "`wd2l-1.1.0-release-manifest.md`" in text
    assert "| [#79](https://github.com/JoeHazurmoney/architecture-wiredata-to-log/issues/79) | bug | " \
           "Spool &lt;dropped&gt; \\| full disk |" in text


def test_notes_mark_retroactive_issues_and_link_the_attestation_pages():
    man = example_manifest()
    man["changes"]["issues_resolved"][0]["retroactive"] = True
    text = notes.notes(versions.names("1.1.0"), **dict(ARGS, man=man, attestation_urls={
        "image index": "https://github.com/o/r/attestations/2", "release files": "", }))
    assert "/issues/79) † | bug |" in text and "† Recorded after its work had merged." in text
    assert "Attestation pages: [image index](https://github.com/o/r/attestations/2)." in text


def test_notes_without_a_manifest_are_unchanged():
    assert "## Issues resolved" not in notes.notes(versions.names("1.1.0"), **ARGS)
    assert "Attestation pages" not in notes.notes(versions.names("1.1.0"), **ARGS)
